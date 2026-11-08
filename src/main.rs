//! CORS proxy for IETF Internet-Draft XML.
//!
//! GET /archive/id/<name>-<rev>.xml is fetched from https://www.ietf.org/archive/id/
//! and returned with CORS headers, so a browser (WASM) app on any origin can load it.
//! GET /archive/id/<name> (no revision, no .xml) redirects to the latest revision's
//! XML URL; the latest revision comes from datatracker.ietf.org.
//! Both upstream requests carry X-Forwarded-For with the requesting client's address.
//!
//! Meant to sit behind nginx on loopback: nginx sends
//! `X-Forwarded-For: $proxy_add_x_forwarded_for`, which already ends with the client
//! address, so a request from a loopback peer passes that header on unchanged.
//! A request from any other peer gets the peer address appended.

use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};

const UPSTREAM: &str = "https://www.ietf.org/archive/id/";
const DATATRACKER: &str = "https://datatracker.ietf.org/doc/";
const XFF: HeaderName = HeaderName::from_static("x-forwarded-for");

#[derive(Clone)]
struct App {
    client: reqwest::Client,
}

/// `draft-<name>`: lowercase letters, digits and single hyphens.
fn valid_draft_name(name: &str) -> bool {
    name.starts_with("draft-")
        && name.len() > "draft-".len()
        && name.len() <= 200
        && !name.ends_with('-')
        && !name.contains("--")
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Accepts only `draft-<name>-<rev>.xml` with a two-digit revision.
/// Keeps this from being an open proxy for www.ietf.org.
fn valid_draft_file(file: &str) -> bool {
    let Some(stem) = file.strip_suffix(".xml") else {
        return false;
    };
    let Some((name, rev)) = stem.rsplit_once('-') else {
        return false;
    };
    valid_draft_name(name) && rev.len() == 2 && rev.bytes().all(|b| b.is_ascii_digit())
}

/// The X-Forwarded-For value to send upstream (see the module comment).
fn forwarded_for(headers: &HeaderMap, peer: SocketAddr) -> String {
    let incoming: Vec<&str> = headers
        .get_all(&XFF)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .collect();
    let peer_ip = peer.ip().to_canonical();
    if peer_ip.is_loopback() && !incoming.is_empty() {
        incoming.join(", ")
    } else {
        let mut chain = incoming.join(", ");
        if !chain.is_empty() {
            chain.push_str(", ");
        }
        chain.push_str(&peer_ip.to_string());
        chain
    }
}

fn cors(headers: &mut HeaderMap) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, HEAD, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("Content-Length, ETag, Last-Modified"),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
}

fn plain(status: StatusCode, msg: &'static str) -> Response {
    let mut resp = (status, msg).into_response();
    cors(resp.headers_mut());
    resp
}

async fn draft(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    Path(file): Path<String>,
    headers: HeaderMap,
) -> Response {
    if method == Method::OPTIONS {
        return plain(StatusCode::NO_CONTENT, "");
    }
    let xff = forwarded_for(&headers, peer);
    if !file.ends_with(".xml") && valid_draft_name(&file) {
        return latest(&app, &file, &xff).await;
    }
    if !valid_draft_file(&file) {
        return plain(
            StatusCode::BAD_REQUEST,
            "expected /archive/id/draft-<name>-<rev>.xml or /archive/id/draft-<name>\n",
        );
    }
    let mut req = app
        .client
        .request(
            if method == Method::HEAD {
                reqwest::Method::HEAD
            } else {
                reqwest::Method::GET
            },
            format!("{UPSTREAM}{file}"),
        )
        .header("X-Forwarded-For", &xff);
    for h in [header::IF_NONE_MATCH, header::IF_MODIFIED_SINCE] {
        if let Some(v) = headers.get(&h) {
            req = req.header(h.as_str(), v.as_bytes());
        }
    }
    let upstream = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{file} xff={xff}: upstream error: {e}");
            return plain(StatusCode::BAD_GATEWAY, "upstream fetch failed\n");
        }
    };
    let status = upstream.status().as_u16();
    eprintln!("{file} xff={xff}: {status}");
    match status {
        200 | 304 => {}
        404 | 410 => return plain(StatusCode::NOT_FOUND, "no such draft revision\n"),
        _ => return plain(StatusCode::BAD_GATEWAY, "unexpected upstream status\n"),
    }

    let mut out = HeaderMap::new();
    for h in [
        header::ETAG,
        header::LAST_MODIFIED,
        header::CACHE_CONTROL,
        header::CONTENT_LENGTH,
    ] {
        if let Some(v) = upstream
            .headers()
            .get(h.as_str())
            .and_then(|v| HeaderValue::from_bytes(v.as_bytes()).ok())
        {
            out.insert(h, v);
        }
    }
    out.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    cors(&mut out);
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    (code, out, Body::from_stream(upstream.bytes_stream())).into_response()
}

/// Redirects `draft-<name>` to the XML of its latest revision, per datatracker.
async fn latest(app: &App, name: &str, xff: &str) -> Response {
    let resp = match app
        .client
        .get(format!("{DATATRACKER}{name}/doc.json"))
        .header("X-Forwarded-For", xff)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{name} xff={xff}: datatracker error: {e}");
            return plain(StatusCode::BAD_GATEWAY, "datatracker lookup failed\n");
        }
    };
    let status = resp.status().as_u16();
    if status == 404 {
        eprintln!("{name} xff={xff}: datatracker 404");
        return plain(StatusCode::NOT_FOUND, "no such draft\n");
    }
    let rev = match resp.json::<serde_json::Value>().await {
        Ok(v) if status == 200 => v.get("rev").and_then(|r| r.as_str()).map(str::to_owned),
        _ => None,
    };
    let Some(rev) = rev.filter(|r| r.len() == 2 && r.bytes().all(|b| b.is_ascii_digit())) else {
        eprintln!("{name} xff={xff}: datatracker {status}, no usable rev");
        return plain(StatusCode::BAD_GATEWAY, "datatracker gave no revision\n");
    };
    eprintln!("{name} xff={xff}: latest -> {rev}");
    let mut out = HeaderMap::new();
    // Relative, so the redirect stays on whatever host and scheme the client used.
    out.insert(
        header::LOCATION,
        HeaderValue::from_str(&format!("{name}-{rev}.xml")).unwrap(),
    );
    out.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    cors(&mut out);
    (StatusCode::FOUND, out).into_response()
}

#[tokio::main]
async fn main() {
    let listen: SocketAddr = std::env::var("LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8096".into())
        .parse()
        .expect("LISTEN must be ip:port");
    let client = reqwest::Client::builder()
        .user_agent(concat!(
            "ietf-draft-proxy/",
            env!("CARGO_PKG_VERSION"),
            " (lab-ietf.ayourt.ch)"
        ))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client");
    let app = Router::new()
        .route("/archive/id/{file}", get(draft).options(draft))
        .fallback(|| async { plain(StatusCode::NOT_FOUND, "not found\n") })
        .with_state(App { client });
    let listener = tokio::net::TcpListener::bind(listen).await.expect("bind");
    eprintln!("listening on {listen}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    .expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_names() {
        assert!(valid_draft_file("draft-ietf-intarea-foo-03.xml"));
        assert!(valid_draft_file("draft-x-00.xml"));
        assert!(!valid_draft_file("draft-ietf-foo-3.xml"));
        assert!(!valid_draft_file("draft-ietf-foo-03.txt"));
        assert!(!valid_draft_file("draft--03.xml"));
        assert!(!valid_draft_file("draft-03.xml"));
        assert!(!valid_draft_file("rfc9000.xml"));
        assert!(!valid_draft_file("draft-Foo-03.xml"));
        assert!(!valid_draft_file("draft-a/../b-03.xml"));
        assert!(!valid_draft_file("draft-a%2f-03.xml"));
        assert!(valid_draft_name("draft-ietf-intarea-proxy-config"));
        assert!(!valid_draft_name("draft-ietf-foo.xml"));
        assert!(!valid_draft_name("draft-"));
    }

    #[test]
    fn xff_chain() {
        let lo: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let far: SocketAddr = "192.0.2.7:5000".parse().unwrap();
        let mut h = HeaderMap::new();
        assert_eq!(forwarded_for(&h, lo), "127.0.0.1");
        assert_eq!(forwarded_for(&h, far), "192.0.2.7");
        h.insert(XFF, HeaderValue::from_static("198.51.100.1, 203.0.113.9"));
        assert_eq!(forwarded_for(&h, lo), "198.51.100.1, 203.0.113.9");
        assert_eq!(
            forwarded_for(&h, far),
            "198.51.100.1, 203.0.113.9, 192.0.2.7"
        );
    }
}
