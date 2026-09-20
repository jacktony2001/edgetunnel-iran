# edt-ir - a Cloudflare Worker proxy tuned for Iran

One `_worker.js`, no build step. It terminates VLESS / Trojan / Shadowsocks at the Cloudflare edge
and forwards the traffic out through a proxyIP relay. It is tuned for what an Iranian line
actually does in September 2026: DNS lies, non-standard ports get reset, and the clear-text SNI is
what the filter matches on.

* No backend server, no domain, no cost: runs on the Cloudflare free plan at `*.workers.dev`.
* Requires: a Cloudflare account, a GitHub account.
* Everything in this repository is English; CI rejects any CJK character in tracked files.

Licensed under GNU GPL-2.0, see `LICENSE`.

---

## Measured on an Iranian line (2026-09-20, no proxy, Windows `curl` 8.19)

| Probe | Result | What it means |
| --- | --- | --- |
| `*.workers.dev` through the ISP resolver | no answer at all | DNS is poisoned, so a client that resolves the node name never gets there |
| TLS to a Cloudflare IP, SNI `*.workers.dev` | handshake succeeded, HTTP 403 (a name that has no worker) | the SNI itself is **not** reset - reaching the edge by IP works |
| SNI `www.cloudflare.com` + `Host: <name>.workers.dev` | answered by the workers.dev handler | Cloudflare routes by the Host header, so the clear-text SNI can be a harmless name |
| `https://speed.cloudflare.com`, `github.com`, `www.google.com` | HTTP 200 | the line is up, this is targeting not an outage |
| `dns.alidns.com/dns-query` | handshake aborted mid-TLS | the ECH bootstrap this project used to recommend is dead here |
| `cloudflare-dns.com`, `dns.google` | connection reset | DoH is blocked |
| `mozilla.cloudflare-dns.com`, `quad9`, `dns.sb`, `opendns` | no answer | DoH is blocked |
| `*.pages.dev`, `*.eu.org` | sinkholed into `10.10.34.x` | the free-domain detours are poisoned too |
| `proxyip.cmliussss.net`, `fra./sin.tp1.090227.xyz` | TLS aborted | donated relays die; `tp1` is gone from the pool |

Four consequences drive every default below: never make the client resolve anything, never make it
depend on a DoH lookup, stay on port 443, and ship diagnostics because relays rot.

## What this build does

| Area | Behaviour |
| --- | --- |
| Node address | a literal Cloudflare IPv4 on **443**, so DNS poisoning is irrelevant |
| Node `host` | your `*.workers.dev` hostname - this is what Cloudflare routes on |
| Node `sni` | `www.cloudflare.com` by default (the **Outer SNI** field), so the filter sees an ordinary Cloudflare name; the certificate it presents matches that name, so verification still passes |
| Egress with `PROXYIP` unset | the colo default plus `publicProxyPool`, shuffled and raced in batches, direct fallback on |
| Egress with `PROXYIP` set | your whole list deduplicated, shuffled, raced; fallback off, as asked |
| Subscription output | generated locally for every client type - the public converter APIs are dead, so no external converter is called by default |
| Diagnostics | `/admin/pool` probes every egress target and the ECH resolver **from the edge** and returns timings as JSON |
| Admin UI | served by the worker itself (`/login`, `/admin`), nothing fetched from a third-party page |
| Language | English identifiers, comments, strings and config keys throughout |

## Deploy

1. This repository is already on your GitHub account.
2. Cloudflare dashboard -> **Workers & Pages** -> **Create** -> **Deploy from Git**. If the GitHub
   connection is missing, add it under account **Settings -> Git integration** and grant this
   repository only.
3. Pick this repo, production name `edt-ir`, default build settings - `wrangler.toml` points `main`
   at `_worker.js`.
4. Worker -> **Settings -> Variables and Secrets**:

   | Variable | Value | Notes |
   | --- | --- | --- |
   | `ADMIN` | your password | secret; nothing is served without it |
   | `KEY` | any random string | secret; changes the UUID derivation and enables the `/<KEY>` quick link |
   | `UUID` | a real v4 UUID | optional, otherwise derived from `ADMIN` + `KEY` |
   | `PROXY_CONCURRENT_DIAL` | `3` | how many egress candidates are dialed at once |
   | `PRELOAD_RACE_DIAL` | `1` | resolve the target ahead of time and race the addresses |
   | `SNI` | optional | overrides the Outer SNI; set it empty to put the workers.dev name back in the clear |
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
| Outer SNI | `www.cloudflare.com` | the only field the filter can read, so it should not be your hostname |
| Protocol / Transport | `vless` / `ws` | the best-tested path on `workers.dev` |
| uTLS fingerprint | `chrome` | matches a real browser handshake |
| ClientHello fragmentation | `Shadowrocket` or `Happ` | splits the handshake; helps on lossy MCI/Irancell links even though DPI can reassemble |
| Node port | `443` | every other Cloudflare port gets reset on Iranian links |
| Refresh interval (hours) | `3` | egress relays and IP ranges get re-classified often |
| Use ECH | **off** | see the caveat below |
| Skip certificate verify | off | not needed, the edge presents a valid certificate for the Outer SNI |

**The ECH caveat, honestly.** The `ECH` switch only appends an `&ech=<inner SNI>+<DoH URL>` hint to
the link. Without a reachable DoH resolver that fetches a real `ECHConfigList`, no ECH handshake
happens and the outer SNI stays in the clear - and every resolver this build used to recommend is
blocked from an Iranian line (table above). Leave it off and use the Outer SNI field. Real ECH is
still possible if you hand the client a pre-supplied `ECHConfigList` (sing-box `tls.ech`, no DoH
needed), but that is client configuration, not something this worker can fake for you.

## Reading the subscription when DNS is poisoned

The subscription URL itself lives on `*.workers.dev`, which your resolver will not answer. Three
ways around it, in order of preference:

1. **Import the node links, not the subscription.** Each generated link carries a literal IP, so
   once it is in the client no DNS is needed ever again. The panel shows the links; paste them.
2. **Pin the name in the OS hosts file** on a machine that can reach the panel, then refresh at
   will. On Windows (as Administrator):
   `Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "104.16.132.229  <your-worker>.workers.dev"`
3. **A client that resolves through its own remote DNS** (sing-box / NekoBox with a DoH server you
   have verified is reachable) - given the table above, do not count on this.

## The public proxyIP pool

At the top of `_worker.js`:

```
const publicProxyPool = ['proxyip.cmliussss.net'];
```

These are donated relays, not infrastructure you own, and they are the single weakest link in this
design - when they die, the subscription imports and connects but nothing comes out. Check
`/admin/pool` before blaming the client: it dials every candidate from the Cloudflare edge and
reports status and milliseconds. The durable fix is your own egress: a private proxyIP, a friend's
VPS with SOCKS/HTTP, or the `PROXYIP` variable with your own comma-separated list.

## Troubleshooting

1. Node connects but nothing loads: open `/admin/pool` and look for a target with `reachable: true`.
2. `https://speed.cloudflare.com/__down?bytes=10` from the same device and network - if that fails,
   the ISP is the problem, not the worker.
3. Worker root URL without a password shows "No admin password configured" - that proves the code
   is deployed and running.
4. `/admin` bouncing back to `/login` after a correct password: the user agent changed between
   requests, the session cookie is bound to it.
5. A client error that mentions a handshake or an unexpected certificate: clear the Outer SNI field
   (or set `SNI=` empty) - that client did not accept SNI/Host separation.
6. Free plan gives 100,000 requests per day for the whole worker, and every proxied connection is
   one request, so a busy household can exhaust it by midday.

## Development

```
node --check _worker.js     # single ES module, no build step
```

The GitHub **Verify** workflow runs that check on every push, rejects CJK characters in tracked
files, and fails if the worker starts depending on a remote admin page again.
