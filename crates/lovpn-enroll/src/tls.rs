//! Pinned TLS 1.3 transport (rustls, ring provider).
//!
//! * TLS 1.3 only; TLS 1.2 is not compiled in.
//! * The server identity is a self-generated certificate. The client trusts exactly
//!   one certificate: the one whose SHA-256 (over its DER) equals the **pin** the
//!   administrator distributed out of band. No system roots, no trust-on-first-use,
//!   no hostname-based trust, and no way to disable verification: a mismatch aborts
//!   the handshake before any application data (the token) is sent.
//! * The handshake signature is still verified by rustls/webpki against the pinned
//!   certificate's key, so possession of the private key is proved.
//! * Every exchange has one overall deadline, enforced per read/write.
use crate::{EnrollError, proto};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError, ServerConfig,
    ServerConnection, SignatureScheme, StreamOwned,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms, ring},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    version::TLS13,
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// SHA-256 over the server certificate's DER encoding.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Pin([u8; 32]);

impl Pin {
    pub fn of_certificate(der: &[u8]) -> Self {
        Self(Sha256::digest(der).into())
    }

    fn matches(&self, der: &[u8]) -> bool {
        Self::of_certificate(der).0.ct_eq(&self.0).into()
    }
}

impl fmt::Display for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pin({self})")
    }
}

impl FromStr for Pin {
    type Err = EnrollError;
    fn from_str(text: &str) -> Result<Self, EnrollError> {
        let hex = text.strip_prefix("sha256:").ok_or(EnrollError::PinFormat)?;
        if hex.len() != 64 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(EnrollError::PinFormat);
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| EnrollError::PinFormat)?;
        }
        Ok(Self(out))
    }
}

/// A freshly generated server TLS identity.
pub struct Identity {
    pub certificate_der: Vec<u8>,
    /// PKCS#8 private key. Zeroized on drop; never log or print it.
    pub private_key_der: Zeroizing<Vec<u8>>,
}

pub fn generate_identity() -> Result<Identity, EnrollError> {
    let certified = rcgen::generate_simple_self_signed(vec!["lovpn-enroll".to_string()])
        .map_err(|_| EnrollError::Tls)?;
    Ok(Identity {
        certificate_der: certified.cert.der().to_vec(),
        private_key_der: Zeroizing::new(certified.signing_key.serialize_der()),
    })
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

pub fn server_config(
    certificate_der: &[u8],
    private_key_der: &[u8],
) -> Result<Arc<ServerConfig>, EnrollError> {
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(private_key_der.to_vec()));
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS13])
        .map_err(|_| EnrollError::Tls)?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(certificate_der.to_vec())], key)
        .map_err(|_| EnrollError::Tls)?;
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct PinVerifier {
    pin: Pin,
    algorithms: WebPkiSupportedAlgorithms,
    mismatch: Arc<AtomicBool>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // The pin is the whole trust decision: exactly one certificate, no chain.
        if !intermediates.is_empty() || !self.pin.matches(end_entity.as_ref()) {
            self.mismatch.store(true, Ordering::SeqCst);
            return Err(TlsError::General("pin mismatch".into()));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Socket wrapper that enforces one overall deadline across all reads and writes.
struct Deadline {
    socket: TcpStream,
    end: Instant,
}

impl Deadline {
    fn remaining(&self) -> io::Result<Duration> {
        self.end
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .map(|d| d.max(Duration::from_millis(1)))
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "deadline"))
    }
}

impl Read for Deadline {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(buf)
    }
}

impl Write for Deadline {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

fn map_io(error: &io::Error) -> EnrollError {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => EnrollError::Timeout,
        _ if error.get_ref().is_some_and(|e| e.is::<TlsError>()) => EnrollError::Tls,
        _ => EnrollError::Io,
    }
}

/// Serve one already-accepted connection: TLS handshake, read one bounded request
/// line, call `handler`, write its answer, close. Everything is bounded by `deadline`.
/// The handler receives raw bytes it must parse strictly itself.
pub fn serve_connection(
    config: Arc<ServerConfig>,
    socket: TcpStream,
    deadline: Duration,
    handler: impl FnOnce(Result<Vec<u8>, EnrollError>) -> Vec<u8>,
) -> Result<(), EnrollError> {
    let _ = socket.set_nodelay(true);
    let connection = ServerConnection::new(config).map_err(|_| EnrollError::Tls)?;
    let mut stream = StreamOwned::new(
        connection,
        Deadline {
            socket,
            end: Instant::now() + deadline,
        },
    );
    let request = proto::read_line(&mut stream, proto::MAX_REQUEST);
    // No completed handshake means no peer worth answering (scanner, idle socket,
    // wrong client): fail without invoking the handler.
    if request.is_err() && stream.conn.is_handshaking() {
        return Err(EnrollError::Tls);
    }
    let answer = handler(request);
    stream.write_all(&answer).map_err(|e| map_io(&e))?;
    stream.conn.send_close_notify();
    let _ = stream.flush();
    Ok(())
}

/// Connect to `address`, authenticate the server by `pin`, send one request line and
/// read one bounded response line. A pin mismatch aborts before the request is sent.
pub fn exchange(
    address: SocketAddr,
    pin: Pin,
    request_line: &[u8],
    deadline: Duration,
) -> Result<Vec<u8>, EnrollError> {
    let end = Instant::now() + deadline;
    let socket = TcpStream::connect_timeout(&address, deadline).map_err(|e| map_io(&e))?;
    let _ = socket.set_nodelay(true);
    let mismatch = Arc::new(AtomicBool::new(false));
    let provider = provider();
    let verifier = PinVerifier {
        pin,
        algorithms: provider.signature_verification_algorithms,
        mismatch: Arc::clone(&mismatch),
    };
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|_| EnrollError::Tls)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let name = ServerName::from(address.ip());
    let connection = ClientConnection::new(Arc::new(config), name).map_err(|_| EnrollError::Tls)?;
    let mut stream = StreamOwned::new(connection, Deadline { socket, end });
    // Complete the handshake before writing, so a mismatch cannot leak the token.
    while stream.conn.is_handshaking() {
        if let Err(error) = stream.conn.complete_io(&mut stream.sock) {
            return Err(if mismatch.load(Ordering::SeqCst) {
                EnrollError::PinMismatch
            } else {
                map_io(&error)
            });
        }
    }
    if mismatch.load(Ordering::SeqCst) {
        return Err(EnrollError::PinMismatch);
    }
    stream.write_all(request_line).map_err(|e| map_io(&e))?;
    stream.flush().map_err(|e| map_io(&e))?;
    proto::read_line(&mut stream, proto::MAX_RESPONSE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_text_round_trips_and_is_strict() {
        let pin = Pin::of_certificate(b"cert");
        assert_eq!(pin.to_string().parse::<Pin>().ok(), Some(pin));
        assert!("sha256:zz".parse::<Pin>().is_err());
        assert!("md5:00".parse::<Pin>().is_err());
        assert!(format!("sha256:{}", "0".repeat(63)).parse::<Pin>().is_err());
    }
}
