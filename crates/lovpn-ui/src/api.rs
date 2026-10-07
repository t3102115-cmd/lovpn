//! Routing, request authentication and the JSON API of the window.
//!
//! The window is a local web page, so the server defends itself like any local service
//! that a browser can reach:
//! - it listens on 127.0.0.1 only;
//! - a per-launch secret in the first URL becomes an HttpOnly, SameSite=Strict cookie, and
//!   every other request must carry it (no other local process or web page has it);
//! - the Host header must be the loopback address and port (DNS-rebinding defence);
//! - state-changing requests must be same-origin JSON POSTs (CSRF defence).
use crate::http::{Request, Response};
use lovpn_cli::AppError;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};

/// Cookies are shared across ports on one host, so the name carries the port: two windows
/// (two `lovpn-ui` processes) must not overwrite each other's session.
fn cookie_name(ctx: &Context) -> String {
    format!("lovpn_session_{}", ctx.port)
}

/// Everything the window can ask of the LoVPN service. The live implementation calls the
/// same functions as the `lovpn` command; tests substitute a stub.
pub trait Backend: Send + Sync {
    fn status(&self) -> Result<Value, AppError>;
    fn profiles(&self) -> Result<Value, AppError>;
    fn connect(&self, profile: Option<&str>) -> Result<Value, AppError>;
    fn disconnect(&self, release: bool) -> Result<Value, AppError>;
    fn reconnect(&self) -> Result<Value, AppError>;
    fn repair(&self) -> Result<Value, AppError>;
    fn reset(&self) -> Result<Value, AppError>;
    fn use_profile(&self, name: &str) -> Result<Value, AppError>;
    fn remove(&self, name: &str) -> Result<Value, AppError>;
    fn test(&self, name: &str) -> Result<Value, AppError>;
    fn create_identity(&self, name: &str) -> Result<Value, AppError>;
    fn device_key(&self, name: &str) -> Result<Value, AppError>;
    fn import(
        &self,
        name: &str,
        profile_text: &str,
        expected_server_key: &str,
    ) -> Result<Value, AppError>;
    fn logs(&self, lines: u32) -> Result<Value, AppError>;
}

pub struct Context {
    pub port: u16,
    pub token: String,
    /// Unix seconds of the last `ping` from the page (0 = never).
    pub last_ping: AtomicU64,
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn cookie_value<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request.header("cookie")?.split(';').find_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        (k == name).then_some(v)
    })
}

fn host_ok(ctx: &Context, host: Option<&str>) -> bool {
    matches!(host, Some(h) if h == format!("127.0.0.1:{}", ctx.port) || h == format!("localhost:{}", ctx.port))
}

fn origin_ok(ctx: &Context, origin: Option<&str>) -> bool {
    matches!(origin, Some(o) if o == format!("http://127.0.0.1:{}", ctx.port) || o == format!("http://localhost:{}", ctx.port))
}

fn json_error(status: u16, code: &str, message: &str) -> Response {
    Response::json(
        status,
        &json!({"ok": false, "error": {"code": code, "message": message}}),
    )
}

fn app_result(result: Result<Value, AppError>) -> Response {
    match result {
        Ok(data) => Response::json(200, &json!({"ok": true, "data": data})),
        Err(e) => json_error(200, &e.code, &e.message),
    }
}

const INDEX: &str = include_str!("../ui/index.html");
const SCRIPT: &str = include_str!("../ui/app.js");
const STYLE: &str = include_str!("../ui/app.css");
const ICON: &str = include_str!("../ui/icon.svg");

pub fn route(ctx: &Context, backend: &dyn Backend, request: &Request, now: u64) -> Response {
    if !host_ok(ctx, request.header("host")) {
        return Response::text(403, "Unexpected Host header.");
    }
    // First visit: exchange the secret in the URL for a cookie, then drop it from the URL.
    if request.method == "GET"
        && request.path == "/"
        && let Some(t) = request.query.strip_prefix("t=")
        && constant_time_eq(t, &ctx.token)
    {
        return Response::text(303, "").header("Location", "/").header(
            "Set-Cookie",
            format!(
                "{}={}; HttpOnly; SameSite=Strict; Path=/",
                cookie_name(ctx),
                ctx.token
            ),
        );
    }
    let authed =
        cookie_value(request, &cookie_name(ctx)).is_some_and(|c| constant_time_eq(c, &ctx.token));
    if !authed {
        return Response::text(
            403,
            "Open LoVPN from the link printed by `lovpn-ui`, or start it again.",
        );
    }
    if request.method == "GET" {
        return match request.path.as_str() {
            "/" => Response::new(200, "text/html; charset=utf-8", INDEX),
            "/app.js" => Response::new(200, "text/javascript; charset=utf-8", SCRIPT),
            "/app.css" => Response::new(200, "text/css; charset=utf-8", STYLE),
            "/icon.svg" => Response::new(200, "image/svg+xml", ICON),
            _ => Response::text(404, "Not found."),
        };
    }
    let Some(op) = request.path.strip_prefix("/api/") else {
        return Response::text(404, "Not found.");
    };
    if !origin_ok(ctx, request.header("origin")) {
        return json_error(
            403,
            "request.origin",
            "Cross-site requests are not accepted.",
        );
    }
    if request
        .header("content-type")
        .map(|c| c.split(';').next().unwrap_or("").trim())
        != Some("application/json")
    {
        return json_error(415, "request.content-type", "Requests must be JSON.");
    }
    let body: Value = match serde_json::from_slice(&request.body) {
        Ok(v @ Value::Object(_)) => v,
        _ if request.body.is_empty() => json!({}),
        _ => return json_error(400, "request.malformed", "The request was not valid JSON."),
    };
    let text = |k: &str| body.get(k).and_then(Value::as_str);
    let need = |k: &str| {
        text(k).ok_or_else(|| AppError::new("request.field", format!("Missing field: {k}.")))
    };
    let result: Result<Value, AppError> = match op {
        "ping" => {
            ctx.last_ping.store(now, Ordering::SeqCst);
            Ok(json!({}))
        }
        "status" => backend.status(),
        "profiles" => backend.profiles(),
        "connect" => backend.connect(text("profile")),
        "disconnect" => backend.disconnect(
            body.get("release")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        ),
        "reconnect" => backend.reconnect(),
        "repair" => backend.repair(),
        "reset" => backend.reset(),
        "use" => need("name").and_then(|n| backend.use_profile(n)),
        "remove" => need("name").and_then(|n| backend.remove(n)),
        "test" => need("name").and_then(|n| backend.test(n)),
        "identity" => need("name").and_then(|n| backend.create_identity(n)),
        "device" => need("name").and_then(|n| backend.device_key(n)),
        "import" => need("name").and_then(|n| {
            let profile = need("profile")?;
            let key = need("expected_server_key")?;
            backend.import(n, profile, key)
        }),
        "logs" => {
            let lines = body
                .get("lines")
                .and_then(Value::as_u64)
                .unwrap_or(100)
                .min(1000);
            backend.logs(u32::try_from(lines).unwrap_or(100))
        }
        "diagnostics" => backend.status().map(|s| sanitize(&s)),
        _ => return json_error(404, "request.unknown", "Unknown operation."),
    };
    app_result(result)
}

/// The text a person can paste into a bug report. Built from an allowlist of fields, so a
/// new secret-bearing field upstream cannot leak into it: nothing here is copied unless
/// it is named. Profile names, endpoints, keys, addresses and paths are never included.
pub fn sanitize(status: &Value) -> Value {
    let mut checks = Vec::new();
    for c in status
        .get("checks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = c.get("name").and_then(Value::as_str).unwrap_or("?");
        let state = c.get("status").and_then(Value::as_str).unwrap_or("unknown");
        // Details are short engine-generated phrases; keep them only if they carry no
        // address-like or key-like content.
        let detail = c
            .get("detail")
            .and_then(Value::as_str)
            .filter(|d| detail_is_safe(d))
            .unwrap_or("(omitted)");
        checks.push(json!({"name": name, "status": state, "detail": detail}));
    }
    let reasons: Vec<Value> = status
        .get("reasons")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|r| r.len() < 40 && r.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
        .map(|r| json!(r))
        .collect();
    json!({
        "report": "LoVPN sanitized diagnostics",
        "app_version": env!("CARGO_PKG_VERSION"),
        "platform": std::env::consts::OS,
        "service": status.get("service").and_then(Value::as_str).unwrap_or("unknown"),
        "state": status.get("state").and_then(Value::as_str).unwrap_or("unknown"),
        "desired": status.get("desired").and_then(Value::as_str).unwrap_or("unknown"),
        "kill_switch_mode": status.get("kill_switch").and_then(Value::as_str).unwrap_or("none"),
        "kill_switch_armed": status.get("kill_switch_armed").and_then(Value::as_bool),
        "handshake_age_secs": status.get("handshake_age_secs").and_then(Value::as_u64),
        "checks": checks,
        "reasons": reasons,
        "removed": "profile names, server addresses, keys, tunnel addresses, file paths",
    })
}

fn detail_is_safe(detail: &str) -> bool {
    detail.len() <= 80
        && !detail.contains('=')
        && !detail.contains("::")
        && !detail
            .split(|c: char| !c.is_ascii_digit() && c != '.')
            .any(|w| w.matches('.').count() >= 3)
        && !detail.split_whitespace().any(|w| w.len() >= 40)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::http::Request;

    struct Stub;
    fn ok() -> Result<Value, AppError> {
        Ok(json!({"stub": true}))
    }
    impl Backend for Stub {
        fn status(&self) -> Result<Value, AppError> {
            Ok(json!({
                "state": "protected", "desired": "connected", "profile": "Home Server (alice)",
                "kill_switch": "strict", "kill_switch_armed": true, "handshake_age_secs": 7,
                "service": "running",
                "checks": [
                    {"name": "interface", "status": "ok", "detail": "present, owned, up"},
                    {"name": "endpoint-route", "status": "ok", "detail": "reached 203.0.113.9 via 10.0.0.1"},
                    {"name": "dns", "status": "ok", "detail": "tunnel resolvers set; DNS to other servers blocked"},
                    {"name": "x", "status": "ok", "detail": "key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
                ],
                "reasons": ["endpoint-route", "Weird Reason With Spaces"],
                "private": "SECRET-VALUE", "public_key": "PUBKEY", "endpoint": "203.0.113.9:51820"
            }))
        }
        fn profiles(&self) -> Result<Value, AppError> {
            ok()
        }
        fn connect(&self, _: Option<&str>) -> Result<Value, AppError> {
            ok()
        }
        fn disconnect(&self, _: bool) -> Result<Value, AppError> {
            ok()
        }
        fn reconnect(&self) -> Result<Value, AppError> {
            ok()
        }
        fn repair(&self) -> Result<Value, AppError> {
            ok()
        }
        fn reset(&self) -> Result<Value, AppError> {
            ok()
        }
        fn use_profile(&self, _: &str) -> Result<Value, AppError> {
            ok()
        }
        fn remove(&self, _: &str) -> Result<Value, AppError> {
            ok()
        }
        fn test(&self, _: &str) -> Result<Value, AppError> {
            ok()
        }
        fn create_identity(&self, _: &str) -> Result<Value, AppError> {
            ok()
        }
        fn device_key(&self, _: &str) -> Result<Value, AppError> {
            ok()
        }
        fn import(&self, _: &str, _: &str, _: &str) -> Result<Value, AppError> {
            ok()
        }
        fn logs(&self, _: u32) -> Result<Value, AppError> {
            ok()
        }
    }

    fn ctx() -> Context {
        Context {
            port: 4242,
            token: "s3cret-token".into(),
            last_ping: AtomicU64::new(0),
        }
    }

    fn req(method: &str, path: &str, query: &str, headers: &[(&str, &str)], body: &str) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            query: query.into(),
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    const HOST: (&str, &str) = ("Host", "127.0.0.1:4242");
    const COOKIE_OK: (&str, &str) = ("Cookie", "lovpn_session_4242=s3cret-token");
    const ORIGIN: (&str, &str) = ("Origin", "http://127.0.0.1:4242");
    const JSON: (&str, &str) = ("Content-Type", "application/json");

    #[test]
    fn rebinding_hosts_are_refused_even_with_the_cookie() {
        let r = route(
            &ctx(),
            &Stub,
            &req(
                "GET",
                "/",
                "",
                &[("Host", "evil.example:4242"), COOKIE_OK],
                "",
            ),
            0,
        );
        assert_eq!(r.status, 403);
        let r = route(
            &ctx(),
            &Stub,
            &req("GET", "/", "", &[("Host", "127.0.0.1:9999"), COOKIE_OK], ""),
            0,
        );
        assert_eq!(r.status, 403);
    }

    #[test]
    fn the_page_requires_the_session_secret() {
        let r = route(&ctx(), &Stub, &req("GET", "/", "", &[HOST], ""), 0);
        assert_eq!(r.status, 403);
        let r = route(&ctx(), &Stub, &req("GET", "/", "t=wrong", &[HOST], ""), 0);
        assert_eq!(r.status, 403);
        let r = route(
            &ctx(),
            &Stub,
            &req("GET", "/", "t=s3cret-token", &[HOST], ""),
            0,
        );
        assert_eq!(r.status, 303);
        let cookie = r
            .extra_headers
            .iter()
            .find(|(k, _)| *k == "Set-Cookie")
            .unwrap()
            .1
            .clone();
        assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
        let r = route(
            &ctx(),
            &Stub,
            &req("GET", "/app.js", "", &[HOST, COOKIE_OK], ""),
            0,
        );
        assert_eq!(r.status, 200);
        let r = route(&ctx(), &Stub, &req("GET", "/app.js", "", &[HOST], ""), 0);
        assert_eq!(r.status, 403);
    }

    #[test]
    fn api_calls_must_be_same_origin_json_posts() {
        let base = [HOST, COOKIE_OK, JSON];
        let post = |headers: &[(&str, &str)], path: &str| {
            route(&ctx(), &Stub, &req("POST", path, "", headers, "{}"), 5)
        };
        assert_eq!(
            post(&[base[0], base[1], base[2], ORIGIN], "/api/status").status,
            200
        );
        // No origin / foreign origin (CSRF) and wrong content type are refused.
        assert_eq!(post(&base, "/api/disconnect").status, 403);
        assert_eq!(
            post(
                &[
                    base[0],
                    base[1],
                    base[2],
                    ("Origin", "https://evil.example")
                ],
                "/api/reset"
            )
            .status,
            403
        );
        assert_eq!(
            post(
                &[HOST, COOKIE_OK, ORIGIN, ("Content-Type", "text/plain")],
                "/api/reset"
            )
            .status,
            415
        );
        // GET never reaches the API.
        assert_eq!(
            route(
                &ctx(),
                &Stub,
                &req("GET", "/api/reset", "", &[HOST, COOKIE_OK], ""),
                0
            )
            .status,
            404
        );
        assert_eq!(
            post(&[base[0], base[1], base[2], ORIGIN], "/api/nope").status,
            404
        );
    }

    #[test]
    fn ping_is_recorded_and_fields_are_required() {
        let c = ctx();
        let h = [HOST, COOKIE_OK, JSON, ORIGIN];
        route(&c, &Stub, &req("POST", "/api/ping", "", &h, "{}"), 77);
        assert_eq!(c.last_ping.load(Ordering::SeqCst), 77);
        let r = route(&c, &Stub, &req("POST", "/api/use", "", &h, "{}"), 0);
        assert!(String::from_utf8_lossy(&r.body).contains("request.field"));
        let r = route(&c, &Stub, &req("POST", "/api/use", "", &h, "not json"), 0);
        assert_eq!(r.status, 400);
    }

    #[test]
    fn sanitized_diagnostics_contain_no_names_addresses_or_keys() {
        let out = sanitize(&Stub.status().unwrap()).to_string();
        for secret in [
            "Home Server",
            "alice",
            "203.0.113.9",
            "10.0.0.1",
            "SECRET-VALUE",
            "PUBKEY",
            "51820",
            "AAAAAAAA",
            "Weird Reason",
        ] {
            assert!(!out.contains(secret), "leaked {secret}: {out}");
        }
        assert!(out.contains("\"state\":\"protected\""));
        assert!(out.contains("present, owned, up"));
        assert!(out.contains("endpoint-route"));
    }
}
