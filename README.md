# edgetunnel - Iran build

A Cloudflare Worker that terminates VLESS / Trojan / Shadowsocks at the edge and forwards the
traffic to a proxyIP backend. This build is tuned for the Iranian filtering environment: the
default egress is a **raced pool of public proxyIP endpoints** instead of a single random one,
and the settings panel is served by the worker itself, so nothing is fetched from a third-party
page.

Everything in this repository is in English and the whole file set is checked in CI for CJK
characters.

* No backend server, no domain, no cost: runs on the Cloudflare free plan at `*.workers.dev`.
* Requires: a Cloudflare account, a GitHub account.

Based on [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) (GNU GPL-2.0, see `LICENSE`).

---

## What this build changes

| Area | Upstream | This build |
| --- | --- | --- |
| Egress when `PROXYIP` is unset | one donated endpoint per request | the colo default **plus** `publicProxyPool` are shuffled and raced; the direct fallback stays on |
| Egress when `PROXYIP` is set | picks one entry at random and **disables** the fallback | your whole list is deduplicated, shuffled and raced in batches; the fallback stays off, as intended |
| Admin UI | fetched from a remote Chinese pages site | generated inside the worker (`/login`, `/admin`), English only |
| Language | Chinese identifiers, comments and strings | English throughout; CI fails the build if any CJK character returns |
| Self-certification comment block | present in the header | removed |

Protocol behaviour, link formats, xHTTP/gRPC handling and the KV config schema are unchanged
apart from the key names being English now.

## Deploy

1. Push this repository to your GitHub account (done).
2. Cloudflare dashboard -> **Workers & Pages** -> **Create** -> **Deploy from Git**.
   If the GitHub connection is missing, add it first from the account-level
   **Settings -> Git integration** and grant access to this repository only.
3. Pick this repo, production name `edt-ir`, and leave the build settings at their defaults -
   `wrangler.toml` already points `main` at `_worker.js`.
4. Open the worker -> **Settings -> Variables and Secrets** (or Environment variables) and add:

   | Variable | Value | Notes |
   | --- | --- | --- |
   | `ADMIN` | your password | secret; nothing is served without it |
   | `KEY` | any random string | secret; changes the UUID derivation and enables the `/<KEY>` quick-subscription link |
   | `UUID` | a real v4 UUID | optional, otherwise the UUID is derived from `ADMIN` + `KEY` |
   | `PROXY_CONCURRENT_DIAL` | `3` | how many proxyIP candidates are dialed at once |
   | `PRELOAD_RACE_DIAL` | `1` | resolve the target ahead of time and race the addresses |

5. **Settings -> Bindings**: add a KV namespace under the binding name `KV`. Without it the admin
   panel, the event log and the local preferred-IP pool stay disabled.
6. Deploy again if you changed anything after the first build.

If you had a `config.json` stored in KV from an earlier upstream build, open `/admin` once and
press **Reset defaults**: the stored keys were Chinese, the worker now expects English ones.

## Recommended client settings for Iran

Open `https://<your-worker>.workers.dev/admin`, sign in with the `ADMIN` value, and set:

| Field | Value | Why |
| --- | --- | --- |
| Use ECH | on | hides the `SNI` from the filter; the only practical answer for `workers.dev` |
| ECH inner SNI | `cloudflare-ech.com` | the name the ECH lookup asks for |
| ECH DoH resolver | `https://dns.alidns.com/dns-query` | reachable from inside Iran, unlike Google DoH |
| ClientHello fragmentation | `Shadowrocket` or `Happ` | splits the handshake so the middlebox cannot read the SNI |
| Protocol / Transport | `vless` / `ws` | the best-tested path |
| uTLS fingerprint | `chrome` | matches a real browser handshake |
| Refresh interval (hours) | `3` | `workers.dev` addresses get re-classified often |
| Skip certificate verify | off | not needed, the edge presents a valid certificate |

Copy the **Subscription URL** from the panel into your client. Recent clients that support ECH:
v2rayNG, Streisand, Happ, Shadowrocket, sing-box.

## The public proxyIP pool

`_worker.js` near the top holds the list that gets raced:

```
const publicProxyPool = ['proxyip.cmliussss.net', 'fra.tp1.090227.xyz', 'sin.tp1.090227.xyz'];
```

These are donated relays, not infrastructure you own. Expect them to change. Keep the list short:
every extra hostname costs one more DNS-over-HTTPS lookup per dial. To replace the pool, set the
`PROXYIP` variable to your own comma-separated list - your own backend is always the reliable
option, and a private proxyIP or a VPS with SOCKS/HTTP is cheap or free to run.

## Troubleshooting

1. `https://speed.cloudflare.com/__down?bytes=10` from the same device and network. If *that*
   fails, the problem is `workers.dev` being filtered at your ISP, not the worker. Try a mobile
   internet connection or a different DNS.
2. Worker root URL without a password returns a page that says no admin password is configured -
   that confirms the code is deployed and running.
3. `/admin` bouncing back to `/login` after a correct password means the user agent changed
   between requests; the session cookie is bound to it.
4. A subscription that imports but never connects: open the panel, check the egress field is not
   empty, raise `PROXY_CONCURRENT_DIAL` to `4`, then test a node with a different remark.
5. Free plan gives 100,000 requests per day for the whole worker; every proxied connection is one
   request, so a busy household can exhaust it by midday.

## Development

```
node --check _worker.js     # the file is a single ES module, no build step
```

The GitHub **Verify** workflow runs the same check on every push, rejects any CJK character in
tracked files, and fails if the worker starts depending on a remote admin page again.
