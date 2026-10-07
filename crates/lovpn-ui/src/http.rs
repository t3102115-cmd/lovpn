//! A deliberately tiny HTTP/1.1 layer for one local user: strict limits, no keep-alive,
//! no chunked bodies, no upgrades. It exists so the window needs no third-party server.
//!
//! Every request is read under a deadline and size caps; anything unexpected is rejected
//! with a status code rather than interpreted.
use std::{
    io::{Read, Write},
    time::{Duration, Instant},
};

pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_BODY_BYTES: usize = 96 * 1024;
pub const READ_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct Request {
    pub method: String,
    /// Path without query string.
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ParseError {
    TooLarge,
    Malformed,
    Timeout,
}

/// Read and parse one request from `stream`.
pub fn read_request<S: Read>(stream: &mut S) -> Result<Request, ParseError> {
    let started = Instant::now();
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(ParseError::TooLarge);
        }
        if started.elapsed() > READ_DEADLINE {
            return Err(ParseError::Timeout);
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(ParseError::Malformed),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ParseError::Timeout);
            }
            Err(_) => return Err(ParseError::Malformed),
        }
    };
    if header_end > MAX_HEADER_BYTES {
        return Err(ParseError::TooLarge);
    }
    let head = std::str::from_utf8(&buf[..header_end]).map_err(|_| ParseError::Malformed)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(ParseError::Malformed)?;
    let mut parts = request_line.split(' ');
    let (method, target, version) = (
        parts.next().ok_or(ParseError::Malformed)?,
        parts.next().ok_or(ParseError::Malformed)?,
        parts.next().ok_or(ParseError::Malformed)?,
    );
    if parts.next().is_some() || !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(ParseError::Malformed);
    }
    if !matches!(method, "GET" | "POST") || !target.starts_with('/') || target.starts_with("//") {
        return Err(ParseError::Malformed);
    }
    if target.bytes().any(|b| b < 0x21 || b == 0x7f) {
        return Err(ParseError::Malformed);
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = Vec::new();
    for line in lines {
        let (k, v) = line.split_once(':').ok_or(ParseError::Malformed)?;
        if k.is_empty() || k.bytes().any(|b| b <= b' ' || b == b':') {
            return Err(ParseError::Malformed);
        }
        headers.push((k.to_string(), v.trim().to_string()));
    }
    let mut request = Request {
        method: method.to_string(),
        path: path.to_string(),
        query: query.to_string(),
        headers,
        body: Vec::new(),
    };
    if request.header("transfer-encoding").is_some() || request.header("expect").is_some() {
        return Err(ParseError::Malformed);
    }
    // A repeated Content-Length is a request-smuggling vector: refuse rather than choose.
    if request
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .count()
        > 1
    {
        return Err(ParseError::Malformed);
    }
    let length = match request.header("content-length") {
        None => 0,
        Some(v) => v.parse::<usize>().map_err(|_| ParseError::Malformed)?,
    };
    if length > MAX_BODY_BYTES {
        return Err(ParseError::TooLarge);
    }
    if method == "GET" && length != 0 {
        return Err(ParseError::Malformed);
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < length {
        if started.elapsed() > READ_DEADLINE {
            return Err(ParseError::Timeout);
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(ParseError::Malformed),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(ParseError::Timeout),
        }
    }
    body.truncate(length);
    request.body = body;
    Ok(request)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub extra_headers: Vec<(&'static str, String)>,
}

impl Response {
    pub fn new(status: u16, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type,
            body: body.into(),
            extra_headers: Vec::new(),
        }
    }

    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        Self::new(status, "application/json", value.to_string())
    }

    pub fn text(status: u16, message: &str) -> Self {
        Self::new(status, "text/plain; charset=utf-8", message.to_string())
    }

    pub fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.extra_headers.push((name, value.into()));
        self
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        _ => "Error",
    }
}

/// Security headers that every response carries. The page may load only its own script and
/// stylesheet and talk only to this origin: no inline code, no third parties, no framing.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub fn write_response<W: Write>(stream: &mut W, response: &Response) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Resource-Policy: same-origin\r\nContent-Security-Policy: {CSP}\r\n",
        response.status,
        reason(response.status),
        response.content_type,
        response.body.len()
    );
    for (k, v) in &response.extra_headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Request, ParseError> {
        read_request(&mut text.as_bytes())
    }

    #[test]
    fn parses_a_simple_get_and_a_post_with_a_body() {
        let r = parse("GET /a?x=1 HTTP/1.1\r\nHost: h\r\n\r\n").unwrap();
        assert_eq!(
            (r.method.as_str(), r.path.as_str(), r.query.as_str()),
            ("GET", "/a", "x=1")
        );
        assert_eq!(r.header("HOST"), Some("h"));
        let r = parse("POST /api/x HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcdEXTRA").unwrap();
        assert_eq!(r.body, b"abcd");
    }

    #[test]
    fn rejects_smuggling_vectors_and_odd_requests() {
        for bad in [
            "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
            "GET //evil HTTP/1.1\r\n\r\n",
            "GET http://x/ HTTP/1.1\r\n\r\n",
            "PUT / HTTP/1.1\r\n\r\n",
            "GET / HTTP/2\r\n\r\n",
            "GET /a b HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\nBad Header: x\r\n\r\n",
            "GET / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
            "POST / HTTP/1.1\r\nContent-Length: nope\r\n\r\n",
            "POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn enforces_size_limits() {
        let big_header = format!(
            "GET / HTTP/1.1\r\nX: {}\r\n\r\n",
            "a".repeat(MAX_HEADER_BYTES + 10)
        );
        assert!(matches!(parse(&big_header), Err(ParseError::TooLarge)));
        let big_body = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        assert!(matches!(parse(&big_body), Err(ParseError::TooLarge)));
        assert!(parse("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort").is_err());
    }

    #[test]
    fn every_response_carries_the_security_headers() {
        let mut out = Vec::new();
        write_response(&mut out, &Response::text(200, "hi")).unwrap();
        let text = String::from_utf8(out).unwrap();
        for needle in [
            "Content-Security-Policy:",
            "X-Content-Type-Options: nosniff",
            "Cache-Control: no-store",
            "frame-ancestors 'none'",
            "Connection: close",
        ] {
            assert!(text.contains(needle), "{needle}");
        }
    }
}
