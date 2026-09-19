# edgetunnel — Iran build

A fork of [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) tuned for heavily filtered, high‑loss networks.

The upstream `_worker.js` is **never edited**, so the built-in `Upstream Sync` action keeps merging without conflicts. All Iran-specific code lives in `iran/`, and the **Iran Build** action writes the deployable file to `dist/_worker.js`.

> Deploy `dist/_worker.js`. Never deploy the root `_worker.js` — that one has no patches in it.

## What changes

| Upstream | This build |
| --- | --- |
| When `PROXYIP` is set, one entry is picked at random and the rest are forgotten; if that entry is dead the connection dies | The whole list is handed to the racing dialer, so the fastest live endpoint wins and the others stay as backups |
| With no `PROXYIP` you get only the project's own default pool | Default pool **plus** the endpoints in `iran/pool.json`, and the built-in fallback stays enabled |
| Spaces inside a `PROXYIP` list silently break entries | Entries are trimmed and de-duplicated |

If you set your own `PROXYIP`, public pool endpoints are **never** mixed into your traffic — only your own list races.

## Deploy (Cloudflare dashboard, no terminal)

1. Open `https://raw.githubusercontent.com/<owner>/<repo>/main/dist/_worker.js`, select all, copy.
2. Cloudflare dashboard → **Workers & Pages** → **Create** → **Get started** → name it `edt-ir` → **Deploy**.
3. **Edit code** → delete the template → paste → **Save and Deploy**. You now have `https://edt-ir.<account>.workers.dev`.
4. **Settings → Variables and Secrets → Edit as code**:

   ```
   ADMIN  = a long random password
   KEY    = a short random string (this becomes your subscription path)
   PROXY_CONCURRENT_DIAL = 3
   PRELOAD_RACE_DIAL     = 1
   URL                   = 1101
   ```

   **Save and Deploy**. If a **Compatibility date** is shown and it is older than `2025-11-04`, set it to that and deploy again.
5. **Settings → Bindings → Add → KV namespace** → create `edt-ir-kv` → set **Variable name** to exactly `KV` → **Save and Deploy**. This must come *after* step 3, otherwise the binding fails.
6. Open `https://edt-ir.<account>.workers.dev/admin` and log in with `ADMIN`.

The panel is served by upstream and is Chinese-only (no language switch). Right-click the page and use the browser's **Translate to English** — every field then reads by its English name. The ones that matter here:

| Setting | Value | Why |
| --- | --- | --- |
| ECH | on | Puts the real hostname inside encrypted ClientHello, which is the only free answer to `workers.dev` SNI filtering |
| TLS fingerprint | `chrome` | Blends the handshake with normal browser traffic |
| TLS fragmentation (Shadowrocket) | on | Splits the handshake into small pieces so packet loss and DPI don't kill it |
| ALPN | `h3,h2,1.1` | Lets the client fall back when one protocol is throttled |
| Subscription refresh interval | `24` hours | The free plan caps at 100k requests/day; clients refreshing every 3 hours burn it |

If ECH is on and *nothing* connects, turn ECH off: older v2rayNG builds can't fetch the ECH config and fail outright instead of falling back. For ECH use Hiddify, Karing, or a current v2rayNG.

## Subscription

```
https://edt-ir.<account>.workers.dev/<your KEY value>
```

Import it as a subscription URL. Keep the Cloudflare worker's own `/admin` page as the only place that can change these settings.

## Refreshing the pool

When every node dies at once, the donated upstreams have changed or been filtered.

* **Fast fix (no commit):** add a `PROXYIP` variable in Cloudflare with two or three fresh endpoints separated by commas → Save and Deploy.
* **Permanent fix:** edit `iran/pool.json`; the **Iran Build** action rebuilds `dist/_worker.js`, then paste and deploy it again.

Keep the list short (3 to 5). Every hostname costs one extra DNS lookup when a connection starts.

## Troubleshooting order

1. **Does `/admin` open?** No → the worker or its URL is the problem, not the nodes.
2. **Does the URL open from inside Iran?** If `/admin` is unreachable, `workers.dev` is being filtered and no node setting will help. Fix ECH on the client, or move to a custom domain.
3. **Connects but no traffic?** The upstream pool is dead. Read the panel log line `[TCP] ... proxyIP:` to see which target was tried, then add a fresh `PROXYIP`.
4. **Connects but slow or dropping?** Set `PROXY_CONCURRENT_DIAL = 4` and switch fragmentation to the `Happ` variant.

## Honest limits

* **No server of your own means borrowed internet.** Any public pool, including this one, runs on donated machines that can vanish or be blocked at any time. This build stops you from *noticing* one death; it cannot create egress.
* **`workers.dev` is the weak point.** If filtering hits Cloudflare's IPs rather than the SNI, ECH won't save it. A custom domain on Cloudflare is the durable fix, and the same worker serves it with zero code change.
* **The build fails loudly.** If upstream moves the code a patch sits on, **Iran Build** errors out instead of publishing a broken worker; update `iran/build.mjs` then.

Upstream license: GPL-2.0. Public fork, so nothing extra is required.
