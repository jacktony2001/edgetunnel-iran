# edt-ir - a Cloudflare Worker proxy tuned for Iran

One `_worker.js`, no build step. It terminates VLESS / Trojan / Shadowsocks at the Cloudflare edge
and forwards the traffic out through a proxyIP relay. Everything it defaults to is based on what
was measured on a real Iranian line, not on what upstream documentation claims.

* No backend server, no domain, no cost: runs on the Cloudflare free plan at `*.workers.dev`.
* Requires: a Cloudflare account, a GitHub account.
* Everything in this repository is English; CI rejects any CJK character in tracked files.

Licensed under GNU GPL-2.0, see `LICENSE`.

---

## Measured on an Iranian line (2026-09-20, no proxy, Windows `curl` 8.19)

| Probe | Result | What it means |
| --- | --- | --- |
| `https://<worker>.halmsal.workers.dev/` | HTTP 200 in 0.37 s from `188.114.99.0` | the worker, its hostname and its IP are all reachable from Iran without any proxy |
| Names under `*.workers.dev` that have no worker | no DNS answer | that is a normal NXDOMAIN, not filtering |
| SNI `www.cloudflare.com` with `Host: <worker>.workers.dev` | **HTTP 403**, 151 bytes, straight from the edge | Cloudflare refuses to route a `workers.dev` site whose SNI names something else, so **SNI fronting is not available on the free hostname** |
| `https://speed.cloudflare.com`, `github.com`, `www.google.com` | HTTP 200 | the line is up |
| `dns.alidns.com/dns-query` | handshake aborted mid-TLS | tampered with, not merely blocked |
| `cloudflare-dns.com`, `dns.google` | connection reset | DoH blocked |
| `mozilla.cloudflare-dns.com`, `quad9`, `dns.sb`, `opendns` | no answer | DoH blocked |
| `a.pages.dev`, `c.eu.org` | answered with a private `10.10.34.x` address | the resolver invents answers for those zones, so free-domain detours there are unreliable |
| `proxyip.cmliussss.net`, `fra./sin.tp1.090227.xyz` | TLS aborted | the donated egress relays are dead |
| `https://speed.cloudflare.com/__down?bytes=10` | HTTP 200 | the standard canary: if this fails, the ISP is the problem |

**What is actually broken, then.** Not DNS and not the SNI - on this line the worker is reachable
plainly. The dead part is the **egress hop**: the worker terminates the tunnel and then has to hand
the bytes to someone, and the donated public proxyIP endpoints no longer complete a handshake.
That is why a node connects, the client is happy, and nothing ever loads.

## What this build does

| Area | Behaviour |
| --- | --- |
| Node address | a literal Cloudflare IPv4 on **443**; non-standard Cloudflare ports are unreliable on Iranian links, so nothing is randomised |
| Node `sni` / `host` | both your `*.workers.dev` hostname - required, see the 403 measurement above |
| Egress with `PROXYIP` unset | the colo default plus `publicProxyPool`, shuffled and raced in batches, direct fallback on |
| Egress with `PROXYIP` set | your whole list deduplicated, shuffled and raced; fallback off, as asked |
| Subscription output | generated locally for every client type - the public converter APIs are dead, so no external converter is called by default |
| Diagnostics | `/admin/pool` probes every egress target and the ECH resolver **from the edge** and returns status plus milliseconds |
| Admin UI | served by the worker itself (`/login`, `/admin`), nothing fetched from a third-party page |
| Language | English identifiers, comments, strings and config keys throughout |

## Deploy

1. This repository is already on your GitHub account.
2. Cloudflare dashboard -> **Workers & Pages** -> **Create** -> **Deploy from Git**. If the GitHub
   connection is missing, add it under account **Settings -> Git integration** and grant this
   repository only.
3. Pick this repo. Cloudflare names the worker after the repository, so the hostname here is
   `edgetunnel-iran.halmsal.workers.dev` - default build settings, `wrangler.toml` points `main` at
   `_worker.js`.
4. Worker -> **Settings -> Variables and Secrets**:

   | Variable | Value | Notes |
   | --- | --- | --- |
   | `ADMIN` | your password | secret; nothing is served without it |
   | `KEY` | any random string | secret; changes the UUID derivation and enables the `/<KEY>` quick link |
   | `UUID` | a real v4 UUID | optional, otherwise derived from `ADMIN` + `KEY` |
   | `PROXY_CONCURRENT_DIAL` | `3` | how many egress candidates are dialed at once |
   | `PRELOAD_RACE_DIAL` | `1` | resolve the target ahead of time and race the addresses |
   | `URL` | usually **delete it** | `URL=1101` makes the root path print a fake Cloudflare "Error 1101: Worker threw exception" page as a decoy; that page is not a real failure |
   | `SNI` | leave empty | only meaningful with a custom domain, see the measurement above |
   | `CFPORT` | optional | node port, default `443` |

5. **Settings -> Bindings**: add a KV namespace under the binding name `KV`. Without it the admin
   panel, the event log and the preferred-IP pool stay disabled.
6. Push again to redeploy; every commit on `main` deploys automatically.

If a `config.json` from an older build is stored in KV, open `/admin` once and press
**Reset defaults** - the old keys were Chinese and are ignored now.

## Settings to use

Open `https://<your-worker>.workers.dev/admin`, sign in with the `ADMIN` value, and check:

| Field | Value | Why |
| --- | --- | --- |
| Outer SNI | **empty** | Cloudflare rejects a mismatched SNI on `workers.dev` (measured above) |
| Protocol / Transport | `vless` / `ws` | the best-tested path on `workers.dev` |
| uTLS fingerprint | `chrome` | matches a real browser handshake |
| ClientHello fragmentation | `Shadowrocket` or `Happ` | splits the handshake; useful on lossy MCI/Irancell links, though DPI can reassemble it |
| Node port | `443` | every other Cloudflare port is unreliable on Iranian links |
| Refresh interval (hours) | `3` | egress relays and IP ranges get re-classified often |
| Use ECH | **off** | see the caveat below |
| Skip certificate verify | off | the edge presents a valid certificate already |

**The ECH caveat, honestly.** The `ECH` switch only appends an `&ech=<inner SNI>+<DoH URL>` hint to
the link. Without a reachable DoH resolver that fetches a real `ECHConfigList`, no ECH handshake
happens and the outer SNI stays in the clear - and every resolver this project used to recommend is
blocked or tampered with on an Iranian line (table above). Leave it off. Real ECH is still possible
if the client is handed a pre-supplied `ECHConfigList` (sing-box `tls.ech`, no DoH needed), and it
is the only free way to hide a `workers.dev` name once SNI filtering tightens; but that is client
configuration, not something this worker can fake.

## Getting traffic out

The node tunnels to Cloudflare fine; the missing piece is where Cloudflare forwards it.

1. Look first: open `https://<your-worker>.workers.dev/admin/pool` while signed in. Every egress
   candidate is dialed **from the edge**, and you get `reachable`, an HTTP status and milliseconds.
   This endpoint only needs the login cookie, so it answers even before `KV` is bound.
2. If nothing is reachable, no client setting will help - you need egress. The options, cheapest
   first: a donated proxyIP that is currently alive (drop its hostname in `PROXYIP`), a friend's
   VPS with SOCKS/HTTP, or your own free-tier box running a relay.
3. Keep `publicProxyPool` short (top of `_worker.js`): every extra hostname costs one more
   DNS-over-HTTPS lookup per dial, and dead entries just slow the race down.

## Troubleshooting

1. "Error 1101: Worker threw exception" on the root path: with `URL=1101` that is this worker's own
   decoy page, printed deliberately. Delete the `URL` variable to get the real page back.
2. Node connects, no data: `/admin/pool`, as above.
3. `/admin` bouncing back to `/login` after a correct password: the user agent changed between
   requests, the session cookie is bound to it.
4. Panel loads but the fields are wrong or empty: KV is not bound under the name `KV`, or an old
   Chinese-keyed `config.json` is still stored - press **Reset defaults**.
5. Free plan gives 100,000 requests per day for the whole worker, and every proxied connection is
   one request, so a busy household can exhaust it by midday.

## Development

```
node --check _worker.js     # single ES module, no build step
```

The GitHub **Verify** workflow runs that check on every push, rejects CJK characters in tracked
files, and fails if the worker starts depending on a remote admin page again.
