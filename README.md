# ietf-draft-proxy

A small CORS proxy for IETF Internet-Draft XML, so that a browser (for example a
WASM RFC editor) on any origin can load draft sources from www.ietf.org.

## What it serves

| Request | Response |
|---|---|
| `GET /archive/id/draft-<name>-<rev>.xml` | The XML from `https://www.ietf.org/archive/id/draft-<name>-<rev>.xml`, with `Access-Control-Allow-Origin: *` |
| `GET /archive/id/draft-<name>` | `302` to `draft-<name>-<rev>.xml` for the latest revision, as reported by `https://datatracker.ietf.org/doc/draft-<name>/doc.json` |
| `OPTIONS` on either | CORS preflight answer (`204`) |

- Only `draft-*` names made of lowercase letters, digits and single hyphens, with a
  two-digit revision, are accepted (`400` otherwise), so it is not an open proxy.
- An unknown draft or revision gives `404`; an upstream failure gives `502`.
- `ETag`, `Last-Modified` and `Cache-Control` are passed through, and
  `If-None-Match` / `If-Modified-Since` are forwarded, so conditional requests work.
- `HEAD` is supported.

## Client address

Every upstream request (www.ietf.org and datatracker) carries `X-Forwarded-For`
with the requesting client's address:

- Behind a reverse proxy on loopback, the incoming `X-Forwarded-For` is passed on
  unchanged. With nginx's `$proxy_add_x_forwarded_for` it already ends with the
  client address.
- A request from any other peer gets the peer address appended to whatever
  `X-Forwarded-For` it carried.

## Build and run

```sh
cargo build --release
LISTEN=127.0.0.1:8096 ./target/release/ietf-draft-proxy
```

`LISTEN` defaults to `127.0.0.1:8096`. Each request is logged to stderr with the
`X-Forwarded-For` value sent upstream and the upstream status.

## Deploying behind nginx

- `deploy/ietf-draft-proxy.service`: a systemd unit (DynamicUser, read-only system).
- `deploy/nginx-location.conf`: the `location /archive/id/` block.

## License

Apache License 2.0, see [LICENSE](LICENSE).
