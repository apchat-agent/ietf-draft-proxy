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
//!
//! Draft XML is third-party content (anyone can post an Internet-Draft), so every
//! response carries `Content-Security-Policy: sandbox` and `nosniff`: a draft opened
//! directly in a browser cannot run script in this site's origin. Client addresses
//! are sent upstream (by design) but are not logged here.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use futures_util::StreamExt;

const UPSTREAM: &str = "https://www.ietf.org/archive/id/";
const DATATRACKER: &str = "https://datatracker.ietf.org/doc/";
const XFF: HeaderName = HeaderName::from_static("x-forwarded-for");
/// Upstream fetches in flight at once; beyond this the client gets 503.
/// Keeps one client from making this host hammer www.ietf.org / datatracker.
const DEFAULT_MAX_IN_FLIGHT: usize = 16;
/// Largest draft XML accepted for checking (the largest drafts are a few MB).
const MAX_XML_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone)]
struct App {
    client: reqwest::Client,
    slots: Arc<tokio::sync::Semaphore>,
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

/// Second line of defence behind the CSP sandbox: refuse XML that carries anything
/// able to run script when a browser renders it. RFC XML v3 may embed SVG artwork,
/// and RFC 7996's SVG profile already forbids script, event handlers and foreign
/// content there, so a real draft never trips this. Malformed XML is refused too
/// (fail closed).
fn active_content(xml: &[u8]) -> Option<String> {
    use quick_xml::events::Event;
    const ELEMENTS: [&str; 5] = ["script", "foreignobject", "iframe", "object", "embed"];
    let mut reader = quick_xml::Reader::from_reader(xml);
    let mut buf = Vec::new();
    loop {
        let event = match reader.read_event_into(&mut buf) {
            Ok(e) => e,
            Err(e) => return Some(format!("not well-formed XML: {e}")),
        };
        match &event {
            Event::Start(e) | Event::Empty(e) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_ascii_lowercase();
                if ELEMENTS.contains(&local.as_str()) {
                    return Some(format!("<{local}> element"));
                }
                for attr in e.attributes().with_checks(false) {
                    let Ok(attr) = attr else {
                        return Some("malformed attribute".into());
                    };
                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_ascii_lowercase();
                    let name = key.rsplit(':').next().unwrap_or(&key);
                    if name.len() > 2
                        && name.starts_with("on")
                        && name[2..].bytes().all(|b| b.is_ascii_alphabetic())
                    {
                        return Some(format!("event handler attribute {key}"));
                    }
                    // Decode character references first: "java&#x09;script:" is a script URI.
                    let decoded = match attr.unescape_value() {
                        Ok(v) => v.into_owned(),
                        Err(_) => String::from_utf8_lossy(&attr.value).into_owned(),
                    };
                    let value: String = decoded
                        .chars()
                        .filter(|c| !c.is_whitespace() && !c.is_control())
                        .collect::<String>()
                        .to_ascii_lowercase();
                    if value.contains("javascript:") || value.contains("vbscript:") {
                        return Some(format!("script URI in attribute {key}"));
                    }
                    if key.starts_with("xmlns") && value.contains("w3.org/1999/xhtml") {
                        return Some("XHTML namespace".into());
                    }
                }
            }
            Event::PI(pi) => {
                let target = String::from_utf8_lossy(pi.target()).to_ascii_lowercase();
                // Many drafts carry the authoring template's
                // <?xml-stylesheet href="rfc2629.xslt"?>: a bare file name resolves to
                // this proxy (which serves no XSLT) and CSP blocks it anyway. Anything
                // that could reach another origin or path is refused.
                if target == "xml-stylesheet" && !plain_stylesheet_href(pi.content()) {
                    return Some("xml-stylesheet processing instruction".into());
                }
            }
            Event::Eof => return None,
            _ => {}
        }
        buf.clear();
    }
}

/// True if an xml-stylesheet PI's `href` is a bare file name such as `rfc2629.xslt`.
fn plain_stylesheet_href(content: &[u8]) -> bool {
    let text = String::from_utf8_lossy(content);
    let Some(start) = text.find("href=") else {
        return false;
    };
    let rest = &text[start + 5..];
    let Some(quote) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') else {
        return false;
    };
    let Some(end) = rest[1..].find(quote) else {
        return false;
    };
    let href = &rest[1..1 + end];
    !href.is_empty()
        && !href.starts_with('.')
        && href
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
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

/// CORS plus the headers that keep third-party XML inert in this origin.
fn common_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
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
    common_headers(resp.headers_mut());
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
    // Held until the response body has been fully streamed (moved into it below).
    let Ok(permit) = app.slots.clone().try_acquire_owned() else {
        let mut resp = plain(StatusCode::SERVICE_UNAVAILABLE, "busy, retry shortly\n");
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        return resp;
    };
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
            eprintln!("{file}: upstream error: {e}");
            return plain(StatusCode::BAD_GATEWAY, "upstream fetch failed\n");
        }
    };
    let status = upstream.status().as_u16();
    eprintln!("{file}: {status}");
    match status {
        200 | 304 => {}
        404 | 410 => return plain(StatusCode::NOT_FOUND, "no such draft revision\n"),
        _ => return plain(StatusCode::BAD_GATEWAY, "unexpected upstream status\n"),
    }

    // A GET with a body is checked whole before any of it is sent on;
    // HEAD and 304 carry no body.
    let check = method != Method::HEAD && status == 200;
    let mut out = HeaderMap::new();
    for h in [
        header::ETAG,
        header::LAST_MODIFIED,
        header::CACHE_CONTROL,
        header::CONTENT_LENGTH,
    ] {
        if check && h == header::CONTENT_LENGTH {
            continue;
        }
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
    common_headers(&mut out);
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    if check {
        if upstream
            .content_length()
            .is_some_and(|n| n > MAX_XML_BYTES as u64)
        {
            return plain(StatusCode::BAD_GATEWAY, "draft XML too large\n");
        }
        let mut body = Vec::new();
        let mut stream = upstream.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let Ok(chunk) = chunk else {
                return plain(StatusCode::BAD_GATEWAY, "upstream read failed\n");
            };
            if body.len() + chunk.len() > MAX_XML_BYTES {
                return plain(StatusCode::BAD_GATEWAY, "draft XML too large\n");
            }
            body.extend_from_slice(&chunk);
        }
        drop(permit);
        if let Some(why) = active_content(&body) {
            eprintln!("{file}: refused: {why}");
            return plain(
                StatusCode::UNPROCESSABLE_ENTITY,
                "draft XML refused: it contains active content (script, event handler or similar)\n",
            );
        }
        return (code, out, Body::from(body)).into_response();
    }
    (
        code,
        out,
        Body::from_stream(upstream.bytes_stream().map(move |chunk| {
            let _held = &permit;
            chunk
        })),
    )
        .into_response()
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
            eprintln!("{name}: datatracker error: {e}");
            return plain(StatusCode::BAD_GATEWAY, "datatracker lookup failed\n");
        }
    };
    let status = resp.status().as_u16();
    if status == 404 {
        eprintln!("{name}: datatracker 404");
        return plain(StatusCode::NOT_FOUND, "no such draft\n");
    }
    let rev = match resp.json::<serde_json::Value>().await {
        Ok(v) if status == 200 => v.get("rev").and_then(|r| r.as_str()).map(str::to_owned),
        _ => None,
    };
    let Some(rev) = rev.filter(|r| r.len() == 2 && r.bytes().all(|b| b.is_ascii_digit())) else {
        eprintln!("{name}: datatracker {status}, no usable rev");
        return plain(StatusCode::BAD_GATEWAY, "datatracker gave no revision\n");
    };
    eprintln!("{name}: latest -> {rev}");
    let mut out = HeaderMap::new();
    // Relative, so the redirect stays on whatever host and scheme the client used.
    out.insert(
        header::LOCATION,
        HeaderValue::from_str(&format!("{name}-{rev}.xml")).unwrap(),
    );
    out.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    common_headers(&mut out);
    (StatusCode::FOUND, out).into_response()
}

#[tokio::main]
async fn main() {
    let listen: SocketAddr = std::env::var("LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8096".into())
        .parse()
        .expect("LISTEN must be ip:port");
    let max_in_flight = std::env::var("MAX_IN_FLIGHT")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or(DEFAULT_MAX_IN_FLIGHT);
    let client = reqwest::Client::builder()
        .user_agent(concat!(
            "ietf-draft-proxy/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/apchat-agent/ietf-draft-proxy)"
        ))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client");
    let app = Router::new()
        .route("/archive/id/{file}", get(draft).options(draft))
        .fallback(|| async { plain(StatusCode::NOT_FOUND, "not found\n") })
        .with_state(App {
            client,
            slots: Arc::new(tokio::sync::Semaphore::new(max_in_flight)),
        });
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
    fn active_content_is_refused() {
        let bad = [
            r#"<rfc><x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script></rfc>"#,
            r#"<rfc><artwork type="svg"><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg></artwork></rfc>"#,
            r#"<rfc><artwork><svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/></artwork></rfc>"#,
            r#"<rfc><svg xmlns="http://www.w3.org/2000/svg"><a xmlns:xl="http://www.w3.org/1999/xlink" xl:href=" Java&#x09;Script:alert(1)">x</a></svg></rfc>"#,
            r#"<rfc><eref target="javascript:alert(1)"/></rfc>"#,
            r#"<?xml-stylesheet type="text/xsl" href="https://evil.example/x.xsl"?><rfc/>"#,
            r#"<?xml-stylesheet type="text/xsl" href="//evil.example/x.xsl"?><rfc/>"#,
            r#"<?xml-stylesheet type="text/xsl" href="../x.xsl"?><rfc/>"#,
            r#"<?xml-stylesheet type="text/xsl" href="data:text/xsl,x"?><rfc/>"#,
            r#"<rfc><svg xmlns="http://www.w3.org/2000/svg"><foreignObject><p>x</p></foreignObject></svg></rfc>"#,
            r#"<rfc xmlns:h="http://www.w3.org/1999/xhtml"><h:p>x</h:p></rfc>"#,
            r#"<rfc><unclosed></rfc>"#,
        ];
        for b in bad {
            assert!(active_content(b.as_bytes()).is_some(), "not refused: {b}");
        }
        let good = r#"<?xml version="1.0" encoding="utf-8"?>
<?xml-stylesheet type="text/xsl" href="rfc2629.xslt" ?>
<!DOCTYPE rfc [ <!ENTITY nbsp "&#160;"> ]>
<rfc xmlns:xi="http://www.w3.org/2001/XInclude" docName="draft-x-00" category="std">
<front><title>On the onset of options</title></front>
<middle><section anchor="one"><t>See <eref target="https://example.org/"/>.</t>
<artwork type="svg"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10"/></svg></artwork>
</section></middle></rfc>"#;
        assert_eq!(active_content(good.as_bytes()), None);
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
