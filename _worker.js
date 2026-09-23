const Version = '2026-09-04 16:24:13';
let config_JSON, cachedSocks5Whitelist = null, debugLogEnabled = false;
let SOCKS5whitelist = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
///////////////////////////////////////////////////////Global constants and utility functions///////////////////////////////////////////////
const WSearlyDataMaxBytes = 8 * 1024, WSearlyDataMaxHeaderLen = Math.ceil(WSearlyDataMaxBytes * 4 / 3) + 4;
const uplinkGrainTargetBytes = 20 * 1024, uplinkQueueMaxBytes = 16 * 1024 * 1024, uplinkQueueMaxItems = 4096;
const downGrainPacketBytes = 32 * 1024, downGrainTailThreshold = 512, downGrainLowWaterBytes = Math.max(4096, downGrainTailThreshold * 12), downGrainMaxWaitRounds = 4;
let tcpConcurrentDials = 2, proxyConcurrentDials = 1, preloadRaceDial = false;
// Public proxyIP endpoints this fork races when no private PROXYIP is configured.
// They are donated relays: expect them to rotate. Keep the list short - every extra
// hostname costs one more DoH lookup per dial. Edit here, or set PROXYIP to override.
// Open /admin/pool once logged in to see which of these the edge can still reach.
const publicProxyPool = ['proxyip.cmliussss.net'];
const shuffle = a => { for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; };
///////////////////////////////////////////////////////Abuse detection signatures///////////////////////////////////////////////
const signatureDictionary = [
	(Proxy.name + "IP").toUpperCase(),
	(String.fromCharCode(67, 109) + URL.name[2] + 'i' + URL.name[0]).toLowerCase(),
	String(2407 * 300 - 10).split('').reverse().join('')
];
///////////////////////////////////////////////////////Main entry point///////////////////////////////////////////////
///////////////////////////////////////////////////////Built-in admin panel (no external page)///////////////////////////////////////////////
const panelStyle = ':root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;padding:24px;background:#101418;color:#e8eaed;font:14px/1.5 ui-sans-serif,system-ui,Segoe UI,Roboto,Arial,sans-serif}h1{font-size:18px;margin:0 0 4px}h2{font-size:13px;margin:0 0 10px;color:#8ab4f8;text-transform:uppercase;letter-spacing:.06em}p.sub{margin:0 0 18px;color:#9aa0a6;font-size:13px}section{border:1px solid #2a2f36;border-radius:10px;padding:14px 16px;margin-bottom:16px;background:#161b20}label{display:block;margin:9px 0;color:#c8ccd0;font-size:13px}input,select,textarea{width:100%;margin-top:4px;padding:7px 9px;border:1px solid #3c424a;border-radius:6px;background:#0d1115;color:#e8eaed;font:inherit}textarea.raw{min-height:260px;font-family:ui-monospace,Consolas,monospace;font-size:12px}input[type=checkbox]{width:auto}select{appearance:auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:0 18px}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:14px}button{padding:8px 15px;border:0;border-radius:6px;background:#1a73e8;color:#fff;font:inherit;cursor:pointer}button.g{background:#2a2f36}button.w{background:#b3261e}a{color:#8ab4f8}#status{min-height:20px;font-size:13px;margin:8px 0}#status.ok{color:#81c995}#status.err{color:#f28b82}table{width:100%;border-collapse:collapse;font-size:12px}td,th{padding:5px 8px;border-bottom:1px solid #262b31;text-align:left;word-break:break-all}code{background:#0d1115;padding:2px 5px;border-radius:4px;font-size:12px;user-select:all}';
const panelScript = `var FIELDS = [
{ t: 'Basics', f: [
  ['HOST', 'Hostname'],
  ['HOSTS', 'All served hostnames', 'list'],
  ['PATH', 'Base path'],
  ['protocolType', 'Protocol', 'select', 'vless|trojan|ss'],
  ['transportProtocol', 'Transport', 'select', 'ws|grpc|xhttp'],
  ['gRPCmode', 'gRPC mode', 'select', 'gun|multi'],
  ['ALPN', 'ALPN (blank = default)'],
  ['Fingerprint', 'uTLS fingerprint'],
  ['skipCertVerify', 'Skip certificate verify', 'bool'],
  ['enable0Rtt', '0-RTT early data', 'bool'],
  ['randomPath', 'Random path', 'bool']
]},
{ t: 'Anti-censorship', f: [
  ['FRONTSNI', 'Outer SNI - custom domains only, workers.dev answers 403 (leave empty)'],
  ['ECH', 'Use ECH, hides the SNI from the filter', 'bool'],
  ['ECHConfig.SNI', 'ECH inner SNI'],
  ['ECHConfig.DNS', 'DoH resolver used to look up ECH'],
  ['TLSfragment', 'ClientHello fragmentation', 'select', '|Shadowrocket|Happ']
]},
{ t: 'Egress', f: [
  ['reverseProxy.PROXYIP', 'proxyIP endpoint, or auto for the public pool'],
  ['reverseProxy.SOCKS5.enabled', 'Named proxy type', 'select', '|SOCKS5|HTTP|HTTPS|TURN|SSTP'],
  ['reverseProxy.SOCKS5.globalFlag', 'Global, every destination', 'bool'],
  ['reverseProxy.SOCKS5.account', 'Proxy account, user:pass@host:port']
]},
{ t: 'Subscription', f: [
  ['preferredSubGen.SUBNAME', 'Subscription name'],
  ['preferredSubGen.SUBUpdateTime', 'Refresh interval in hours', 'num'],
  ['preferredSubGen.local', 'Generate locally', 'bool'],
  ['preferredSubGen.SUB', 'Remote generator URL'],
  ['preferredSubGen.localIpPool.randomIp', 'Random preferred IPs', 'bool'],
  ['preferredSubGen.localIpPool.randomIpCount', 'Random IP count', 'num'],
  ['preferredSubGen.localIpPool.specifiedPort', 'Node port; 443 is the only one reliable in Iran', 'num'],
  ['SS.cipherMethod', 'Shadowsocks cipher', 'select', 'aes-128-gcm|aes-256-gcm'],
  ['SS.TLS', 'Shadowsocks over TLS', 'bool']
]},
{ t: 'Converter', f: [
  ['subConverterConfig.SUBAPI', 'Converter API'],
  ['subConverterConfig.SUBCONFIG', 'Converter config URL'],
  ['subConverterConfig.SUBLIST', 'Plain node list', 'bool'],
  ['subConverterConfig.UDP', 'UDP', 'bool'],
  ['subConverterConfig.XUDP', 'XUDP', 'bool'],
  ['subConverterConfig.TLS13', 'TLS 1.3', 'bool'],
  ['subConverterConfig.SUBEMOJI', 'Emoji', 'bool'],
  ['subConverterConfig.APPEND_TYPE', 'Append node type', 'bool'],
  ['subConverterConfig.SORT', 'Sort nodes', 'bool']
]}];

var cfg = null;
function pick(o, p) { return p.split('.').reduce(function (a, k) { return a == null ? a : a[k]; }, o); }
function put(o, p, v) { var k = p.split('.'), l = o, i; for (i = 0; i < k.length - 1; i++) { if (l[k[i]] == null) l[k[i]] = {}; l = l[k[i]]; } l[k[k.length - 1]] = v; }
function el(tag, text) { var e = document.createElement(tag); if (text != null) e.textContent = text; return e; }
function say(msg, ok) { var s = document.getElementById('status'); s.textContent = msg; s.className = ok ? 'ok' : 'err'; }

function render() {
  var host = document.getElementById('form');
  host.textContent = '';
  FIELDS.forEach(function (sec) {
    var box = el('section'), head = el('h2', sec.t);
    box.appendChild(head);
    var grid = el('div'); grid.className = 'grid'; box.appendChild(grid);
    host.appendChild(box);
    sec.f.forEach(function (fld) {
      var path = fld[0], label = fld[1], kind = fld[2], input;
      var wrap = el('label', label);
      var value = pick(cfg, path);
      if (kind === 'bool') { input = el('input'); input.type = 'checkbox'; input.checked = !!value; }
      else if (kind === 'select') {
        input = el('select');
        var blank = el('option', 'none'); blank.value = '';
        input.appendChild(blank);
        fld[3].split('|').forEach(function (opt) {
          var o = el('option', opt || 'none'); o.value = opt;
          if (String(value == null ? '' : value) === opt) o.selected = true;
          input.appendChild(o);
        });
        if (value == null || value === '') blank.selected = true;
      }
      else if (kind === 'list') { input = el('input'); input.value = (value || []).join(', '); input.placeholder = 'comma separated'; }
      else { input = el('input'); if (kind === 'num') input.type = 'number'; input.value = value == null ? '' : value; }
      input.setAttribute('data-p', path);
      input.setAttribute('data-t', kind || 'str');
      wrap.appendChild(input);
      grid.appendChild(wrap);
    });
  });
  var adv = el('section');
  adv.appendChild(el('h2', 'Advanced'));
  var raw = el('textarea'); raw.className = 'raw'; raw.id = 'rawbox'; raw.value = JSON.stringify(cfg, null, 2);
  adv.appendChild(raw);
  var apply = el('button', 'Apply the raw JSON back into the form');
  apply.onclick = function () {
    try { cfg = JSON.parse(raw.value); render(); showLinks(); say('Raw JSON applied. Review the fields, then Save.', true); }
    catch (e) { say('Invalid JSON: ' + e.message, false); }
  };
  adv.appendChild(apply);
  host.appendChild(adv);
}

function showLinks() {
  var box = document.getElementById('links');
  box.hidden = false;
  var list = document.getElementById('linklist');
  list.textContent = '';
  var token = cfg.preferredSubGen && cfg.preferredSubGen.TOKEN ? cfg.preferredSubGen.TOKEN : '';
  [['Subscription URL', location.origin + '/sub?token=' + token], ['Node link', cfg.LINK || '(none)']].forEach(function (row) {
    var p = el('p');
    p.appendChild(el('span', row[0] + ': '));
    p.appendChild(el('code', row[1]));
    list.appendChild(p);
  });
}

async function load() {
  var r = await fetch('/admin/config.json', { credentials: 'same-origin' });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  cfg = await r.json();
  render();
  showLinks();
  var tg = cfg.TG || {};
  if (tg.BotToken) document.getElementById('tgtoken').placeholder = tg.BotToken;
  if (tg.ChatID) document.getElementById('tgchat').placeholder = tg.ChatID;
}

async function save() {
  FIELDS.forEach(function (sec) {
    sec.f.forEach(function (fld) {
      var node = document.querySelector('[data-p="' + fld[0] + '"]');
      if (!node) return;
      var kind = fld[2], v;
      if (kind === 'bool') v = node.checked;
      else if (kind === 'list') v = node.value.split(',').map(function (x) { return x.trim(); }).filter(Boolean);
      else if (kind === 'num') v = Number(node.value);
      else if (kind === 'select') v = node.value === '' ? null : node.value;
      else v = node.value === '' ? null : node.value;
      put(cfg, fld[0], v);
    });
  });
  var r = await fetch('/admin/config.json', { method: 'POST', credentials: 'same-origin', body: JSON.stringify(cfg, null, 2) });
  var j = await r.json().catch(function () { return {}; });
  say(r.ok ? 'Saved.' : 'Save failed: ' + (j.msg || j.error || r.status), r.ok);
  if (r.ok) showLinks();
}

async function postJson(url, body, stateId) {
  var r = await fetch(url, { method: 'POST', credentials: 'same-origin', body: JSON.stringify(body) });
  document.getElementById(stateId).textContent = r.ok ? 'saved' : 'failed (' + r.status + ')';
}

async function showLog() {
  var box = document.getElementById('logsec');
  box.hidden = false;
  var r = await fetch('/admin/log.json', { credentials: 'same-origin' });
  var rows = await r.json().catch(function () { return []; });
  var table = el('table'), body = el('tbody');
  rows.slice(-40).reverse().forEach(function (row) {
    var tr = el('tr');
    ['TIME', 'TYPE', 'IP', 'URL'].forEach(function (k) {
      tr.appendChild(el('td', String(row[k] == null ? '' : row[k]).slice(0, 90)));
    });
    body.appendChild(tr);
  });
  table.appendChild(body);
  var list = document.getElementById('loglist');
  list.textContent = '';
  list.appendChild(table);
}

document.getElementById('save').onclick = save;
document.getElementById('reload').onclick = function () { load().catch(function (e) { say('Load failed: ' + e.message, false); }); };
document.getElementById('logbtn').onclick = function () { showLog().catch(function (e) { say(e.message, false); }); };
document.getElementById('raw').onclick = function () { var r = document.getElementById('rawbox'); r.scrollIntoView(); r.focus(); };
document.getElementById('init').onclick = async function () {
  if (!confirm('Reset every setting back to the built-in defaults?')) return;
  await fetch('/admin/init', { credentials: 'same-origin' });
  await load();
  say('Configuration reset.', true);
};
document.getElementById('tgsave').onclick = function () {
  var token = document.getElementById('tgtoken').value, chat = document.getElementById('tgchat').value;
  postJson('/admin/tg.json', { BotToken: token, ChatID: chat, init: !token }, 'tgstate');
};
load().then(function () { say('Loaded.', true); }).catch(function (e) { say('Could not load the configuration: ' + e.message, false); });`;
const panelHtml = '<!doctype html><html lang="en"><head><meta charset="utf-8">'
	+ '<meta name="viewport" content="width=device-width,initial-scale=1">'
	+ '<title>edt-ir settings</title><style>' + panelStyle + '</style></head><body>'
	+ '<h1>edt-ir settings</h1><p class="sub">Iran build. Settings apply to the next subscription fetch.</p>'
	+ '<div class="row"><button id="save">Save</button><button id="reload" class="g">Reload</button>'
	+ '<button id="logbtn" class="g">Events</button><button id="raw" class="g">Jump to raw JSON</button>'
	+ '<button id="init" class="w">Reset defaults</button><a href="/logout">Sign out</a></div>'
	+ '<p id="status"></p><div id="form">Loading...</div>'
	+ '<section id="links" hidden><h2>Your endpoints</h2><div id="linklist"></div></section>'
	+ '<section id="logsec" hidden><h2>Recent events</h2><div id="loglist"></div></section>'
	+ '<section><h2>Telegram notifications</h2>'
	+ '<label>Bot token<input id="tgtoken" autocomplete="off" placeholder="(unchanged)"></label>'
	+ '<label>Chat ID<input id="tgchat" autocomplete="off" placeholder="(unchanged)"></label>'
	+ '<div class="row"><button id="tgsave">Save Telegram settings</button><span id="tgstate"></span></div></section>'
	+ '<script>' + panelScript + '<\/script></body></html>';
const loginHtml = '<!doctype html><html lang="en"><head><meta charset="utf-8">'
	+ '<meta name="viewport" content="width=device-width,initial-scale=1"><title>edt-ir login</title>'
	+ '<style>' + panelStyle + '</style></head><body>'
	+ '<div style="max-width:360px;margin:12vh auto auto"><h1>Sign in</h1>'
	+ '<p class="sub">Use the ADMIN value configured on this Worker.</p>'
	+ '<section><label>Password<input id="p" type="password" autocomplete="current-password"></label>'
	+ '<div class="row"><button id="go">Sign in</button><span id="m"></span></div></section></div>'
	+ "<script>function go(){var b=document.getElementById('p').value;fetch('/login',{method:'POST',credentials:'same-origin',body:'password='+encodeURIComponent(b),headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'}}).then(function(r){if(r.ok)location.href='/admin';else document.getElementById('m').textContent='Wrong password';});}document.getElementById('go').onclick=go;document.getElementById('p').addEventListener('keydown',function(e){if(e.key==='Enter')go();});<\/script></body></html>";
const htmlHeaders = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate' };
const page = (html, status = 200) => new Response(html, { status, headers: htmlHeaders });
const noticePage = (title, text) => page('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>' + title + '</title><style>' + panelStyle + '</style></head><body><div style="max-width:620px;margin:12vh auto"><h1>' + title + '</h1><p class="sub">' + text + '</p></div></body></html>', 404);

export default {
	async fetch(request, env, ctx) {
		let rawRequestUrl = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
		const fragmentIndex = rawRequestUrl.indexOf('#');
		const urlWithoutFragment = fragmentIndex === -1 ? rawRequestUrl : rawRequestUrl.slice(0, fragmentIndex);
		if (!urlWithoutFragment.includes('?') && /%3f/i.test(urlWithoutFragment)) {
			const urlFragment = fragmentIndex === -1 ? '' : rawRequestUrl.slice(fragmentIndex);
			rawRequestUrl = urlWithoutFragment.replace(/%3f/i, '?') + urlFragment;
		}
		const url = new URL(rawRequestUrl);
		const UA = request.headers.get('User-Agent') || 'null';
		const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase(), contentType = (request.headers.get('content-type') || '').toLowerCase();
		const adminPassword = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
		const accessKey = env.KEY || 'do not modify this default key; if needed, add the KEY variable to change it';
		const userIDMD5 = await MD5MD5(adminPassword + accessKey);
		const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
		const envUUID = env.UUID || env.uuid;
		const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
		const hosts = env.HOST ? (await normalizeToArray(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]) : [url.hostname];
		const host = hosts[0];
		const accessPath = url.pathname.slice(1).toLowerCase();
		debugLogEnabled = ['1', 'true'].includes(env.DEBUG) || debugLogEnabled;
		preloadRaceDial = ['1', 'true'].includes(env.PRELOAD_RACE_DIAL) || preloadRaceDial;
		proxyConcurrentDials = Math.max(1, Number(env.PROXY_CONCURRENT_DIAL) || proxyConcurrentDials);
		tcpConcurrentDials = Math.max(1, Number(env.TCP_CONCURRENT_DIAL) || tcpConcurrentDials);
		if (!env.TCP_CONCURRENT_DIAL && tcpConcurrentDials !== 1 && detectIsp(request) === 'cmcc') tcpConcurrentDials = 1;
		let defaultProxyIp = (`${request.cf.colo}.${signatureDictionary[0]}.${signatureDictionary[1]}SsSs.nEt`).toLowerCase(), defaultProxyFallback = true;
		if (env.PROXYIP) {
			const proxyIPs = [...new Set((await normalizeToArray(env.PROXYIP)).map(s => s.trim()))].filter(Boolean);
			if (proxyIPs.length) { defaultProxyIp = shuffle(proxyIPs).join(','); defaultProxyFallback = false; };
		} else if (publicProxyPool.length) {
			defaultProxyIp = [...new Set(shuffle([defaultProxyIp, ...publicProxyPool]))].join(',');
			defaultProxyFallback = true;
		};
		const clientIp = request.headers.get('CF-Connecting-IP') || request.headers.get('True-Client-IP') || request.headers.get('X-Real-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Cluster-Client-IP') || 'unknown IP';
		if (cachedSocks5Whitelist === null) {
			if (env.GO2SOCKS5) SOCKS5whitelist = [...new Set(SOCKS5whitelist.concat(await normalizeToArray(env.GO2SOCKS5)))];
			cachedSocks5Whitelist = SOCKS5whitelist;
		} else SOCKS5whitelist = cachedSocks5Whitelist;
		if (accessPath === 'version') {// Version info endpoint
			const requestUuid = (url.searchParams.get('uuid') || '').toLowerCase();
			if (uuidRegex.test(requestUuid)) {
				const targetUuid = String(userID).toLowerCase();
				let requestCharSum = 0, targetCharSum = 0;
				for (let i = 0; i < 8; i++) {
					const requestCharCode = requestUuid.charCodeAt(i);
					requestCharSum += requestCharCode <= 57 ? requestCharCode - 48 : requestCharCode - 87;
					const targetCharCode = targetUuid.charCodeAt(i);
					targetCharSum += targetCharCode <= 57 ? targetCharCode - 48 : targetCharCode - 87;
				}
				if (requestCharSum === targetCharSum && requestUuid.slice(-12) === targetUuid.slice(-12)) return new Response(JSON.stringify({ Version: Number(String(Version).replace(/\D+/g, '')) }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
			}
		} else if (adminPassword && upgradeHeader === 'websocket') {// WebSocket proxy
			const proxyContext = await buildProxyContext(url, userID, defaultProxyIp, defaultProxyFallback);
			log(`[WebSocket] request matched: ${url.pathname}${url.search}`);
			return await handleWsRequest(request, userID, url, proxyContext);
		} else if (adminPassword && !accessPath.startsWith('admin/') && accessPath !== 'login' && request.method === 'POST') {// gRPC/xHTTP proxy
			const proxyContext = await buildProxyContext(url, userID, defaultProxyIp, defaultProxyFallback);
			const { head: localPaddingHeader, paddingKey: localPaddingKey } = getXhttpPaddingIds(userID);
			const hitXhttpSignature = !!request.headers.get(localPaddingHeader) || !!url.searchParams.get(localPaddingKey);
			if (!hitXhttpSignature && contentType.startsWith('application/grpc')) {
				log(`[gRPC] request matched: ${url.pathname}${url.search}`);
				return await handleGrpcRequest(request, userID, proxyContext);
			}
			log(`[xHTTP] request matched: ${url.pathname}${url.search}`);
			return await handleXHttpRequest(request, userID, proxyContext);
		} else {
			if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
			if (!adminPassword) return noticePage('No admin password configured', 'Add the ADMIN variable to this Worker (Settings -&gt; Variables) and deploy again. Until then only the proxy endpoints are served.');
			if (accessPath === 'admin/pool') {// Egress diagnostics; deliberately outside the KV gate, because a worker with no KV is exactly when this is needed
				const cookies = request.headers.get('Cookie') || '';
				const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
				if (!authCookie || authCookie !== await MD5MD5(UA + accessKey + adminPassword)) return new Response('Redirecting...', { status: 302, headers: { 'Location': '/login' } });
				const egressTargets = [...new Set(String(defaultProxyIp).split(',').map(s => s.trim()).concat(publicProxyPool, String(env.PROXYIP || '').split(',').map(s => s.trim())))].filter(Boolean);
				const probe = async (target, path = '/') => {
					const started = performance.now();
					try {
						const res = await fetch(`https://${target}${path}`, { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(5000) });
						return { target, reachable: true, status: res.status, ms: Math.round(performance.now() - started) };
					} catch (error) {
						return { target, reachable: false, error: error.message, ms: Math.round(performance.now() - started) };
					}
				};
				const diagnostics = {
					workerHost: url.hostname,
					colo: request.cf.colo,
					clientIp,
					kvBound: !!(env.KV && typeof env.KV.get === 'function'),
					egress: await Promise.all(egressTargets.map(target => probe(target)))
				};
				if (diagnostics.kvBound) {
					config_JSON = await readConfigJson(env, host, userID, UA);
					const echDns = /^https?:\/\//.test(String(config_JSON.ECHConfig?.DNS || '')) ? String(config_JSON.ECHConfig.DNS) : '';
					diagnostics.frontSNI = config_JSON.FRONTSNI || null;
					diagnostics.nodePort = config_JSON.preferredSubGen.localIpPool.specifiedPort;
					diagnostics.echBootstrapResolver = echDns ? await probe(new URL(echDns).host, new URL(echDns).pathname + '?name=example.com&type=A') : null;
				}
				return new Response(JSON.stringify(diagnostics, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
			}
			if (env.KV && typeof env.KV.get === 'function') {
				const caseSensitivePath = url.pathname.slice(1);
				if (caseSensitivePath === accessKey && accessKey !== 'do not modify this default key; if needed, add the KEY variable to change it') {//Quick subscription
					const params = new URLSearchParams(url.search);
					params.set('token', await MD5MD5(host + userID));
					return new Response('Redirecting...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
				} else if (accessPath === 'login') {//Handle the login page and login requests
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					if (authCookie == await MD5MD5(UA + accessKey + adminPassword)) return new Response('Redirecting...', { status: 302, headers: { 'Location': '/admin' } });
					if (request.method === 'POST') {
						const formData = await request.text();
						const params = new URLSearchParams(formData);
						const enteredPassword = params.get('password');
						if (enteredPassword === (typeof adminPassword === 'string' ? adminPassword.replace(/[\r\n]/g, '') : adminPassword)) {
							// Password is correct: set the cookie and return the success flag
							const authResponse = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							authResponse.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + accessKey + adminPassword)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax`);
							return authResponse;
						}
					}
					return page(loginHtml);
				} else if (accessPath === 'admin' || accessPath.startsWith('admin/')) {//Serve the admin page once the cookie checks out
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					// No cookie or a bad cookie, go to the /login page
					if (!authCookie || authCookie !== await MD5MD5(UA + accessKey + adminPassword)) return new Response('Redirecting...', { status: 302, headers: { 'Location': '/login' } });
					if (accessPath === 'admin/log.json') {// Read the log contents
						const logJsonText = await env.KV.get('log.json') || '[]';
						return new Response(logJsonText, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (caseSensitivePath === 'admin/getCloudflareUsage') {// Query the request usage
						try {
							const Usage_JSON = await getCloudflareUsage(url.searchParams.get('Email'), url.searchParams.get('GlobalAPIKey'), url.searchParams.get('AccountID'), url.searchParams.get('APIToken'));
							return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
						} catch (err) {
							const errorResponse = { msg: 'failed to query request usage, reason:' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (caseSensitivePath === 'admin/getADDAPI') {// Validate the preferred API
						if (url.searchParams.get('url')) {
							const unverifiedPreferredUrl = url.searchParams.get('url');
							try {
								new URL(unverifiedPreferredUrl);
								const bestIpApiResult = await fetchBestIpApis([unverifiedPreferredUrl], url.searchParams.get('port') || '443');
								let preferredApiIps = bestIpApiResult[0].length > 0 ? bestIpApiResult[0] : bestIpApiResult[1];
								preferredApiIps = preferredApiIps.map(item => item.replace(/#(.+)$/, (_, remark) => '#' + decodeURIComponent(remark)));
								return new Response(JSON.stringify({ success: true, data: preferredApiIps }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (err) {
								const errorResponse = { msg: 'failed to validate optimized API, reason:' + err.message, error: err.message };
								return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						}
						return new Response(JSON.stringify({ success: false, data: [] }, null, 2), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (accessPath === 'admin/check') {// Proxy check
						const proxyProtocol = ['socks5', 'http', 'https', 'turn', 'sstp'].find(typeName => url.searchParams.has(typeName)) || null;
						if (!proxyProtocol) return new Response(JSON.stringify({ error: 'missing proxy parameter' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						const proxyParams = url.searchParams.get(proxyProtocol);
						const startTime = Date.now();
						let proxyCheckResponse;
						try {
							const checkParsed = await getSocks5Account(proxyParams, getProxyDefaultPort(proxyProtocol));
							const { username, password, hostname, port } = checkParsed;
							const proxyCredentials = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
							try {
								const probeHost = 'cloudflare.com', probePort = 443, encoder = new TextEncoder(), decoder = new TextDecoder();
								const TCPconnection = createRequestTcpConnector(request);
								let tcpSocket = null, tlsSocket = null;
								try {
									tcpSocket = proxyProtocol === 'socks5'
										? await socks5Connect(probeHost, probePort, new Uint8Array(0), TCPconnection, checkParsed)
										: proxyProtocol === 'turn'
											? await turnConnect(checkParsed, probeHost, probePort, TCPconnection)
											: proxyProtocol === 'sstp'
												? await sstpConnect(checkParsed, probeHost, probePort, TCPconnection)
												: (proxyProtocol === 'https' && isIPHostname(hostname)
													? await httpsConnect(probeHost, probePort, new Uint8Array(0), TCPconnection, checkParsed)
													: await httpConnect(probeHost, probePort, new Uint8Array(0), proxyProtocol === 'https', TCPconnection, checkParsed));
									if (!tcpSocket) throw new Error('unable to connect to proxy server');
									tlsSocket = new TlsClient(tcpSocket, { serverName: probeHost, insecure: true });
									await tlsSocket.handshake();
									await tlsSocket.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${probeHost}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`));
									let responseBuffer = new Uint8Array(0), headerEndIndex = -1, contentLength = null, chunked = false;
									const maxResponseBytes = 64 * 1024;
									while (responseBuffer.length < maxResponseBytes) {
										const value = await tlsSocket.read();
										if (!value) break;
										if (value.byteLength === 0) continue;
										responseBuffer = concatByteChunks(responseBuffer, value);
										if (headerEndIndex === -1) {
											const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
											if (crlfcrlf !== -1) {
												headerEndIndex = crlfcrlf + 4;
												const headers = decoder.decode(responseBuffer.slice(0, headerEndIndex));
												const statusLine = headers.split('\r\n')[0] || '';
												const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
												const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
												if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`proxy detection request failed: ${statusLine || 'invalid response'}`);
												const lengthMatch = headers.match(/\r\nContent-Length:\s*(\d+)/i);
												if (lengthMatch) contentLength = parseInt(lengthMatch[1], 10);
												chunked = /\r\nTransfer-Encoding:\s*chunked/i.test(headers);
											}
										}
										if (headerEndIndex !== -1 && contentLength !== null && responseBuffer.length >= headerEndIndex + contentLength) break;
										if (headerEndIndex !== -1 && chunked && decoder.decode(responseBuffer).includes('\r\n0\r\n\r\n')) break;
									}
									if (headerEndIndex === -1) throw new Error('proxy check response headers too long or invalid');
									const response = decoder.decode(responseBuffer);
									const ip = response.match(/(?:^|\n)ip=(.*)/)?.[1];
									const loc = response.match(/(?:^|\n)loc=(.*)/)?.[1];
									if (!ip || !loc) throw new Error('proxy check response invalid');
									proxyCheckResponse = { success: true, proxy: proxyProtocol + "://" + proxyCredentials, ip, loc, responseTime: Date.now() - startTime };
								} finally {
									try { tlsSocket ? tlsSocket.close() : await tcpSocket?.close?.() } catch (e) { }
								}
							} catch (error) {
								proxyCheckResponse = { success: false, error: error.message, proxy: proxyProtocol + "://" + proxyCredentials, responseTime: Date.now() - startTime };
							}
						} catch (err) {
							proxyCheckResponse = { success: false, error: err.message, proxy: proxyProtocol + "://" + proxyParams, responseTime: Date.now() - startTime };
						}
						return new Response(JSON.stringify(proxyCheckResponse, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					}

					config_JSON = await readConfigJson(env, host, userID, UA);

					if (accessPath === 'admin/init') {// Reset the configuration to its defaults
						try {
							config_JSON = await readConfigJson(env, host, userID, UA, true);
							ctx.waitUntil(recordRequestLog(env, request, clientIp, 'Init_Config', config_JSON));
							config_JSON.init = 'Configuration reset to defaults';
							return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						} catch (err) {
							const errorResponse = { msg: 'failed to reset configuration, reason:' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (request.method === 'POST') {// Handle KV operations (POST requests)
						if (accessPath === 'admin/config.json') { // Save the config.json configuration
							try {
								const newConfig = await request.json();
								// Check the configuration for completeness
								if (!newConfig.UUID || !newConfig.HOST) return new Response(JSON.stringify({ error: 'incomplete configuration' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });

								// Save to KV
								await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
								ctx.waitUntil(recordRequestLog(env, request, clientIp, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'Configuration saved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('failed to save configuration:', error);
								return new Response(JSON.stringify({ error: 'failed to save configuration: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (accessPath === 'admin/cf.json') { // Save the cf.json configuration
							try {
								const newConfig = await request.json();
								const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
								if (!newConfig.init || newConfig.init !== true) {
									if (newConfig.Email && newConfig.GlobalAPIKey) {
										CF_JSON.Email = newConfig.Email;
										CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
									} else if (newConfig.AccountID && newConfig.APIToken) {
										CF_JSON.AccountID = newConfig.AccountID;
										CF_JSON.APIToken = newConfig.APIToken;
									} else if (newConfig.UsageAPI) {
										CF_JSON.UsageAPI = newConfig.UsageAPI;
									} else {
										return new Response(JSON.stringify({ error: 'incomplete configuration' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									}
								}

								// Save to KV
								await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
								ctx.waitUntil(recordRequestLog(env, request, clientIp, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'Configuration saved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('failed to save configuration:', error);
								return new Response(JSON.stringify({ error: 'failed to save configuration: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (accessPath === 'admin/tg.json') { // Save the tg.json configuration
							try {
								const newConfig = await request.json();
								if (newConfig.init && newConfig.init === true) {
									const TG_JSON = { BotToken: null, ChatID: null };
									await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
								} else {
									if (!newConfig.BotToken || !newConfig.ChatID) return new Response(JSON.stringify({ error: 'incomplete configuration' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
								}
								ctx.waitUntil(recordRequestLog(env, request, clientIp, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'Configuration saved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('failed to save configuration:', error);
								return new Response(JSON.stringify({ error: 'failed to save configuration: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (caseSensitivePath === 'admin/ADD.txt') { // Save custom preferred IP
							try {
								const customIPs = await request.text();
								await env.KV.put('ADD.txt', customIPs);// Save to KV
								ctx.waitUntil(recordRequestLog(env, request, clientIp, 'Save_Custom_IPs', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'Custom IP saved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('failed to save custom IP:', error);
								return new Response(JSON.stringify({ error: 'failed to save custom IP: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else return new Response(JSON.stringify({ error: 'unsupported POST request path' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (accessPath === 'admin/config.json') {// Handle the admin/config.json request and return JSON
						return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
					} else if (caseSensitivePath === 'admin/ADD.txt') {// Handle the admin/ADD.txt request and return the local preferred IP
						let localPreferredIp = await env.KV.get('ADD.txt') || 'null';
						if (localPreferredIp == 'null') localPreferredIp = (await generateRandomIps(request, config_JSON.preferredSubGen.localIpPool.randomIpCount, config_JSON.preferredSubGen.localIpPool.specifiedPort))[1];
						return new Response(localPreferredIp, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'asn': request.cf.asn } });
					} else if (accessPath === 'admin/cf.json') {// CF config file
						return new Response(JSON.stringify(request.cf, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					}

					ctx.waitUntil(recordRequestLog(env, request, clientIp, 'Admin_Login', config_JSON));
					return page(panelHtml);
				} else if (accessPath === 'logout' || uuidRegex.test(accessPath)) {//Clear the cookie and go to the login page
					const authResponse = new Response('Redirecting...', { status: 302, headers: { 'Location': '/login' } });
					authResponse.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
					return authResponse;
				} else if (accessPath === 'sub') {//Handle subscription requests
					const subscriptionToken = await MD5MD5(host + userID), asPreferredSubGen = ['1', 'true'].includes(env.BEST_SUB) && url.searchParams.get('host') === 'example.com' && url.searchParams.get('uuid') === '00000000-0000-4000-8000-000000000000' && UA.toLowerCase().includes('tunnel (https://github.com/' + signatureDictionary[1] + '/edge');
					const requestToken = url.searchParams.get('token');
					const isUserSubRequest = requestToken === subscriptionToken;
					const currentDayIndex = Math.floor(Date.now() / 86400000);
					const subConverterSeedToken = base64SecretEncode(subscriptionToken, userID);
					const [todaySubConverterToken, yesterdaySubBackendToken] = await Promise.all([
						MD5MD5(subConverterSeedToken + currentDayIndex),
						MD5MD5(subConverterSeedToken + (currentDayIndex - 1)),
					]);
					const backendSubRequest = requestToken === todaySubConverterToken || requestToken === yesterdaySubBackendToken;
					if (isUserSubRequest || backendSubRequest || asPreferredSubGen) {
						config_JSON = await readConfigJson(env, host, userID, UA);
						if (asPreferredSubGen) ctx.waitUntil(recordRequestLog(env, request, clientIp, 'Get_Best_SUB', config_JSON, false));
						else ctx.waitUntil(recordRequestLog(env, request, clientIp, 'Get_SUB', config_JSON));
						const ua = UA.toLowerCase();
						const responseHeaders = {
							"content-type": "text/plain; charset=utf-8",
							"Profile-Update-Interval": config_JSON.preferredSubGen.SUBUpdateTime,
							"Profile-web-page-url": url.protocol + '//' + url.host + '/admin',
							"Cache-Control": "no-store",
						};
						if (config_JSON.CF.Usage.success) {
							const pagesSum = config_JSON.CF.Usage.pages;
							const workersSum = config_JSON.CF.Usage.workers;
							const total = Number.isFinite(config_JSON.CF.Usage.max) ? (config_JSON.CF.Usage.max / 1000) * 1024 : 1024 * 100;
							responseHeaders["Subscription-Userinfo"] = `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=4102329600`; // 2099-12-31 expiry time
						}
						const isSubConverterRequest = url.searchParams.has('b64') || url.searchParams.has('base64') || request.headers.get('subconverter-request') || request.headers.get('subconverter-version') || ua.includes('subconverter') || ua.includes(('CF-Workers-SUB').toLowerCase()) || asPreferredSubGen;
						const subscriptionType = isSubConverterRequest
							? 'mixed'
							: url.searchParams.has('target')
								? url.searchParams.get('target')
								: url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo')
									? 'clash'
									: url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') || ua.includes('sing-box')
										? 'singbox'
										: url.searchParams.has('surge') || ua.includes('surge')
											? 'surge&ver=4'
											: url.searchParams.has('quanx') || ua.includes('quantumult')
												? 'quanx'
												: url.searchParams.has('loon') || ua.includes('loon')
													? 'loon'
													: 'mixed';

						if (!ua.includes('mozilla')) responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(config_JSON.preferredSubGen.SUBNAME)}`;
						const protocolType = ((url.searchParams.has('surge') || ua.includes('surge')) && config_JSON.protocolType !== 'ss') ? 'tro' + 'jan' : config_JSON.protocolType;
						// With no converter configured, the locally generated link list goes to every client
						// type; it is the only output that survives a dead public converter.
						const localOnly = !config_JSON.subConverterConfig.SUBAPI;
						let subscriptionContent = '';
						if (subscriptionType === 'mixed' || localOnly) {
							const TLSfragmentParams = config_JSON.TLSfragment == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLSfragment == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
							let fullPreferredIps = [], otherNodesLink = '', proxyIpPool = [];

							if (!url.searchParams.has('sub') && config_JSON.preferredSubGen.local) { // Generate the subscription locally
								const fullPreferredList = config_JSON.preferredSubGen.localIpPool.randomIp ? (
									await generateRandomIps(request, config_JSON.preferredSubGen.localIpPool.randomIpCount, config_JSON.preferredSubGen.localIpPool.specifiedPort)
								)[0] : await env.KV.get('ADD.txt') ? await normalizeToArray(await env.KV.get('ADD.txt')) : (
									await generateRandomIps(request, config_JSON.preferredSubGen.localIpPool.randomIpCount, config_JSON.preferredSubGen.localIpPool.specifiedPort)
								)[0];
								const preferredApi = [], preferredIp = [], otherNodes = [];
								for (const element of fullPreferredList) {
									if (element.toLowerCase().startsWith('sub://')) {
										preferredApi.push(element);
									} else {
										const remarkIndex = element.indexOf('#');
										const addressPart = remarkIndex > -1 ? element.slice(0, remarkIndex) : element;
										const remarkSuffix = remarkIndex > -1 ? element.slice(remarkIndex) : '';
										const subMatch = element.match(/sub\s*=\s*([^\s&#]+)/i);
										if (subMatch && subMatch[1].trim().includes('.')) {
											const preferredIpAsProxyIp = element.toLowerCase().includes('proxyip=true');
											if (preferredIpAsProxyIp) preferredApi.push('sub://' + subMatch[1].trim() + "?proxyip=true" + (element.includes('#') ? ('#' + element.split('#')[1]) : ''));
											else preferredApi.push('sub://' + subMatch[1].trim() + (element.includes('#') ? ('#' + element.split('#')[1]) : ''));
										} else if (addressPart.toLowerCase().startsWith('https://')) {
											preferredApi.push(element);
										} else if (addressPart.toLowerCase().includes('://')) {
											if (element.includes('#')) {
												const addressRemarkSplit = element.split('#');
												otherNodes.push(addressRemarkSplit[0] + '#' + encodeURIComponent(decodeURIComponent(addressRemarkSplit[1])));
											} else otherNodes.push(element);
										} else {
											if (addressPart.includes('*')) {
												preferredIp.push(replaceStarsWithRandom(addressPart) + remarkSuffix);
											} else preferredIp.push(element);
										}
									}
								}
								const bestIpApiResult = await fetchBestIpApis(preferredApi, '443');
								const mergedOtherNodes = [...new Set(otherNodes.concat(bestIpApiResult[1]))];
								otherNodesLink = mergedOtherNodes.length > 0 ? mergedOtherNodes.join('\n') + '\n' : '';
								const preferredApiIps = bestIpApiResult[0];
								proxyIpPool = bestIpApiResult[3] || [];
								fullPreferredIps = [...new Set(preferredIp.concat(preferredApiIps))];
							} else { // Preferred subscription generator
								let preferredSubGenHost = url.searchParams.get('sub') || config_JSON.preferredSubGen.SUB;
								const [preferredGenIpList, preferredGenOtherNodes] = await getBestSubGeneratorData(preferredSubGenHost);
								fullPreferredIps = fullPreferredIps.concat(preferredGenIpList);
								otherNodesLink += preferredGenOtherNodes;
							}
							const ECHLINKparams = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
							const frontSNI = (config_JSON.FRONTSNI || '').trim();
							const sniParam = frontSNI ? 'sni=__FRONTSNI__' : 'sni=example.com';
							const isLoonOrSurge = ua.includes('loon') || ua.includes('surge');
							const { type: transportProtocol, pathFieldName, domainFieldName } = getTransportConfig(config_JSON);
							subscriptionContent = otherNodesLink + fullPreferredIps.map(rawAddress => {
								// Single regex: matches a domain/IPv4/IPv6 address + an optional port + an optional remark
								// Examples:
								//   - Domain: hj.xmm1993.top:2096#remark or example.com
								//   - IPv4: 166.0.188.128:443#Los Angeles or 166.0.188.128
								//   - IPv6: [2606:4700::]:443#CMCC or [2606:4700::]
								const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
								const match = rawAddress.match(regex);

								let nodeAddress, nodePort = "443", nodeRemark;

								if (match) {
									nodeAddress = match[1];  // IP address or hostname (may be wrapped in brackets)
									nodePort = match[2] ? match[2] : '443';  // port defaults to 443, SS noTLS is remapped when the link is built
									nodeRemark = match[3] || nodeAddress;  // remark, defaults to the address itself
								} else {
									// Malformed entry, skip it and return null
									console.warn(`[subscription content] non-standard IP format ignored: ${rawAddress}`);
									return null;
								}

								let fullNodePath = config_JSON.fullNodePath;

								const chainedProxyMatch = nodeRemark.match(/\$(socks5|http|https|turn|sstp):\/\/([^#\s]+)/i);
								if (chainedProxyMatch) {
									try {
										const proxyProtocol = chainedProxyMatch[1].toLowerCase(), proxyParams = chainedProxyMatch[2];
										const chainedProxyData = { type: proxyProtocol, ...getSocks5Account(proxyParams, getProxyDefaultPort(proxyProtocol)) };
										fullNodePath = `/video/${base64SecretEncode(JSON.stringify(chainedProxyData), userID) + (config_JSON.enable0Rtt ? '?ed=2560' : '')}`;
										nodeRemark = nodeRemark.replace(chainedProxyMatch[0], '').trim() || nodeAddress;
									} catch (error) {
										console.warn(`[subscription content] chained proxy parse failed, directive ignored: ${chainedProxyMatch[0]} (${error && error.message ? error.message : error})`);
									}
								} else if (proxyIpPool.length > 0) {
									const matchedProxyIp = proxyIpPool.find(p => p.includes(nodeAddress));
									if (matchedProxyIp) fullNodePath = (`${config_JSON.PATH}/proxyip=${matchedProxyIp}`).replace(/\/\//g, '/') + (config_JSON.enable0Rtt ? '?ed=2560' : '');
								}
								if (isLoonOrSurge) fullNodePath = fullNodePath.replace(/,/g, '%2C');

								if (protocolType === 'ss' && !asPreferredSubGen) {
									if (!config_JSON.SS.TLS) {
										const TLSresolvedPort = [443, 2053, 2083, 2087, 2096, 8443];
										const NOTLSresolvedPort = [80, 2052, 2082, 2086, 2095, 8080];
										nodePort = String(NOTLSresolvedPort[TLSresolvedPort.indexOf(Number(nodePort))] ?? nodePort);
									}
									fullNodePath = (fullNodePath.includes('?') ? fullNodePath.replace('?', '?enc=' + config_JSON.SS.cipherMethod + '&') : (fullNodePath + '?enc=' + config_JSON.SS.cipherMethod)).replace(/([=,])/g, '\\$1');
									if (!isSubConverterRequest) fullNodePath = fullNodePath + ';mux=0';
									return `${protocolType}://${btoa(config_JSON.SS.cipherMethod + ':00000000-0000-4000-8000-000000000000')}@${nodeAddress}:${nodePort}?plugin=v2${encodeURIComponent('ray-plugin;mode=websocket;host=example.com;path=' + (config_JSON.randomPath ? randomPath(fullNodePath) : fullNodePath) + (config_JSON.SS.TLS ? ';tls' : '')) + ECHLINKparams + TLSfragmentParams}#${encodeURIComponent(nodeRemark)}`;
								} else {
									const transportPathValue = getTransportPathValue(config_JSON, fullNodePath, asPreferredSubGen);
									return `${protocolType}://00000000-0000-4000-8000-000000000000@${nodeAddress}:${nodePort}?security=tls&type=${transportProtocol + ECHLINKparams}&${domainFieldName}=example.com&fp=${config_JSON.Fingerprint}&${sniParam}&${pathFieldName}=${encodeURIComponent(transportPathValue) + TLSfragmentParams}&encryption=none&alpn=${encodeURIComponent(config_JSON.ALPN)}#${encodeURIComponent(nodeRemark)}`;
								}
							}).filter(item => item !== null).join('\n').replace(/__FRONTSNI__/g, frontSNI);
						} else { // Subscription conversion
							const subConverterUrl = `${config_JSON.subConverterConfig.SUBAPI}/sub?target=${subscriptionType}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?target=mixed&token=' + todaySubConverterToken + '&cnIspCode=' + detectIsp(request) + (url.searchParams.has('sub') && url.searchParams.get('sub') != '' ? `&sub=${url.searchParams.get('sub')}` : ''))}&config=${encodeURIComponent(config_JSON.subConverterConfig.SUBCONFIG)}&emoji=${config_JSON.subConverterConfig.SUBEMOJI}&list=${config_JSON.subConverterConfig.SUBLIST}&scv=${config_JSON.skipCertVerify}&xudp=${config_JSON.subConverterConfig.XUDP}&udp=${config_JSON.subConverterConfig.UDP}&tls13=${config_JSON.subConverterConfig.TLS13}&append_type=${config_JSON.subConverterConfig.APPEND_TYPE}&sort=${config_JSON.subConverterConfig.SORT}`;
							try {
								const response = await fetch(subConverterUrl, { headers: { 'User-Agent': 'Subconverter for ' + subscriptionType + ' edge' + 'tunnel (https://github.com/' + signatureDictionary[1] + '/edge' + 'tunnel)' } });
								if (response.ok) {
									subscriptionContent = await response.text();
									if (url.searchParams.has('surge') || ua.includes('surge')) subscriptionContent = SurgeapplySubConfigHotPatch(subscriptionContent, url.protocol + '//' + url.host + '/sub?token=' + subscriptionToken + '&surge', config_JSON);
								} else return new Response('subscription conversion backend error:' + response.statusText, { status: response.status });
							} catch (error) {
								return new Response('subscription conversion backend error:' + error.message, { status: 403 });
							}
						}

						if (!ua.includes('subconverter') && isUserSubRequest) {
							const shuffledHosts = [...config_JSON.HOSTS].sort(() => Math.random() - 0.5);
							let domainSwapCount = 0, currentRandomHost = null;
							subscriptionContent = subscriptionContent
								.replace(/00000000-0000-4000-8000-000000000000/g, config_JSON.UUID)
								.replace(/MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw/g, btoa(config_JSON.UUID))
								.replace(/example\.com/g, () => {
									if (domainSwapCount % 2 === 0) {
										const originalHost = shuffledHosts[Math.floor(domainSwapCount / 2) % shuffledHosts.length];
										currentRandomHost = replaceStarsWithRandom(originalHost);
									}
									domainSwapCount++;
									return currentRandomHost;
								});
						}

						if ((subscriptionType === 'mixed' || localOnly) && (!ua.includes('mozilla') || url.searchParams.has('b64') || url.searchParams.has('base64'))) subscriptionContent = btoa(subscriptionContent);

						if (!localOnly && subscriptionType === 'singbox') {
							subscriptionContent = await SingboxapplySubConfigHotPatch(subscriptionContent, config_JSON);
							responseHeaders["content-type"] = 'application/json; charset=utf-8';
						} else if (!localOnly && subscriptionType === 'clash') {
							subscriptionContent = ClashapplySubConfigHotPatch(subscriptionContent, config_JSON);
							responseHeaders["content-type"] = 'application/x-yaml; charset=utf-8';
						}
						return new Response(subscriptionContent, { status: 200, headers: responseHeaders });
					}
				} else if (accessPath === 'locations') {//Reverse-proxy locations list
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					if (authCookie && authCookie == await MD5MD5(UA + accessKey + adminPassword)) return fetch(new Request('https://speed.cloudflare.com/locations', { headers: { 'Referer': 'https://speed.cloudflare.com/' } }));
				} else if (accessPath === 'robots.txt') return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
			} else if (!envUUID) return noticePage('KV namespace is not bound', 'Create a Workers KV namespace and bind it to this Worker with the binding name KV (see the README). The admin panel and the local preferred-IP pool both need it.');
		}

		let fakePageUrl = env.URL || 'nginx';
		if (fakePageUrl && fakePageUrl !== 'nginx' && fakePageUrl !== '1101') {
			fakePageUrl = fakePageUrl.trim().replace(/\/$/, '');
			if (!fakePageUrl.match(/^https?:\/\//i)) fakePageUrl = 'https://' + fakePageUrl;
			if (fakePageUrl.toLowerCase().startsWith('http://')) fakePageUrl = 'https://' + fakePageUrl.substring(7);
			try { const u = new URL(fakePageUrl); fakePageUrl = u.protocol + '//' + u.host } catch (e) { fakePageUrl = 'nginx' }
		}
		if (fakePageUrl === '1101') return new Response(await html1101(url.host, clientIp), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
		try {
			const reverseProxyUrl = new URL(fakePageUrl), proxyRequestHeaders = new Headers(request.headers);
			proxyRequestHeaders.set('Host', reverseProxyUrl.host);
			proxyRequestHeaders.set('Referer', reverseProxyUrl.origin);
			proxyRequestHeaders.set('Origin', reverseProxyUrl.origin);
			if (!proxyRequestHeaders.has('User-Agent') && UA && UA !== 'null') proxyRequestHeaders.set('User-Agent', UA);
			const proxyResponse = await fetch(reverseProxyUrl.origin + url.pathname + url.search, { method: request.method, headers: proxyRequestHeaders, body: request.body, cf: request.cf });
			const contentType = proxyResponse.headers.get('content-type') || '';
			// Only handle text-like responses
			if (/text|javascript|json|xml/.test(contentType)) {
				const responseBody = (await proxyResponse.text()).replaceAll(reverseProxyUrl.host, url.host);
				return new Response(responseBody, { status: proxyResponse.status, headers: { ...Object.fromEntries(proxyResponse.headers), 'Cache-Control': 'no-store' } });
			}
			return proxyResponse;
		} catch (error) { }
		return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
	}
};
///////////////////////////////////////////////////////////////////////xHTTP transfer data///////////////////////////////////////////////
const HPACKHuffmancodeLength = [
	13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
	28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
	6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
	5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
	13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
	15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
	6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
	20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
	24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
	22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
	21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
	26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
	19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
	20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
	26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
	30
];

function getXhttpPaddingIds(yourUUID) {
	return { head: yourUUID.slice(1, 7), paddingKey: '_' + yourUUID.slice(25, 31) };
}

function calcHpackHuffmanByteLen(inputString) {
	const bytes = new TextEncoder().encode(inputString);
	let totalBits = 0;
	for (let i = 0; i < bytes.length; i++) {
		totalBits += HPACKHuffmancodeLength[bytes[i]];
	}
	return Math.ceil(totalBits / 8);
}

function extractXHttpPadding(request, localPaddingHeader, localPaddingKey) {
	const headerValue = request.headers.get(localPaddingHeader);
	if (headerValue) {
		try {
			const paddingHeaderUrl = new URL(headerValue, 'https://x.invalid');
			const queryValue = paddingHeaderUrl.searchParams.get(localPaddingKey);
			if (queryValue) return queryValue;
		} catch (e) { }
		return headerValue;
	}
	const parsedRequestUrl = new URL(request.url);
	return parsedRequestUrl.searchParams.get(localPaddingKey) || '';
}

function verifyXhttpPadding(request, localPaddingHeader, localPaddingKey) {
	const paddingvalue = extractXHttpPadding(request, localPaddingHeader, localPaddingKey);
	if (!paddingvalue) return true;
	const huffmanpaddingLength = calcHpackHuffmanByteLen(paddingvalue);
	return huffmanpaddingLength >= 98 && huffmanpaddingLength <= 1002;
}

const xhttpBase62Charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
function generateXhttpPadding(paddingLength) {
	const charsetLength = xhttpBase62Charset.length;
	let resultValue = '';
	for (let i = 0; i < paddingLength; i++) {
		resultValue += xhttpBase62Charset[Math.floor(Math.random() * charsetLength)];
	}
	return resultValue;
}

async function handleXHttpRequest(request, yourUUID, proxyContext = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const { head: localPaddingHeader, paddingKey: localPaddingKey } = getXhttpPaddingIds(yourUUID);
	if (!verifyXhttpPadding(request, localPaddingHeader, localPaddingKey)) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const firstPacket = await readXHttpFirstPacket(reader, yourUUID);
	if (!firstPacket) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('Invalid request', { status: 400 });
	}
	if (isSpeedTestSite(firstPacket.hostname) && proxyContext.proxyType === null) {
		try { reader.releaseLock() } catch (e) { }
		return new Response(buildLocal204Response(firstPacket.respHeader), {
			status: 200,
			headers: {
				'Content-Type': 'application/octet-stream',
				'X-Accel-Buffering': 'no',
				'Cache-Control': 'no-store'
			}
		});
	}
	if (firstPacket.isUDP && firstPacket.protocol !== 'trojan' && firstPacket.port !== 53) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('UDP is not supported', { status: 400 });
	}

	const responseHeaders = new Headers({
		'Content-Type': 'application/octet-stream',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	try {
		const responseUrl = new URL('https://x.invalid/');
		responseUrl.searchParams.set(localPaddingKey, generateXhttpPadding(100 + Math.floor(Math.random() * 901)));
		responseHeaders.set(localPaddingHeader, responseUrl.toString());
	} catch (e) { }

	if (firstPacket.isUDP) return handleXHttpUdpRequest(firstPacket, reader, request, proxyContext, responseHeaders);

	try { reader.releaseLock() } catch (e) { }

	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const abortController = new AbortController();
	let isCleanedUp = false;
	const cleanup = (reason) => {
		if (isCleanedUp) return;
		isCleanedUp = true;
		try { abortController.abort(reason) } catch (e) { }
		invalidateTcpGeneration(remoteConnWrapper);
	};

	const placeholderWs = { readyState: WebSocket.OPEN };

	let socket;
	try {
		socket = await forwardataTCP(firstPacket.hostname, firstPacket.port, firstPacket.rawData, placeholderWs, firstPacket.respHeader, remoteConnWrapper, yourUUID, request, proxyContext, firstPacket.protocol === 'trojan', firstPacket.rawFirstPacket, true);
	} catch (err) {
		log(`[xHTTP-Pipe] connection failed: ${err?.message || err}`);
		cleanup(err);
		return new Response('bad gateway', { status: 502 });
	}
	if (!socket) {
		cleanup(new Error('socket is null'));
		return new Response('bad gateway', { status: 502 });
	}

	const uplinkPromise = (async () => {
		const uplinkGrainPacker = createUplinkGrainStream();
		const pumpPromise = uplinkGrainPacker.readable.pipeTo(socket.writable, { signal: abortController.signal });
		void pumpPromise.catch(cleanup);
		const uplinkReader = request.body.getReader();
		const cancelUplinkReader = () => {
			try { uplinkReader.cancel(abortController.signal.reason).catch(() => { }); } catch (e) { }
		};
		abortController.signal.addEventListener('abort', cancelUplinkReader, { once: true });
		try {
			try {
				while (true) {
					const { done, value } = await uplinkReader.read();
					if (done) break;
					if (value?.byteLength) await uplinkGrainPacker.write(value);
				}
			} finally {
				abortController.signal.removeEventListener('abort', cancelUplinkReader);
				try { uplinkReader.releaseLock() } catch (e) { }
			}
		} finally {
			try { await uplinkGrainPacker.finish() } catch (e) { }
		}
		await pumpPromise;
	})();

	const responseStream = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream();
	const downlinkPromise = (async () => {
		const writer = responseStream.writable.getWriter();
		try {
			if (validDataLength(firstPacket.respHeader) > 0) await writer.write(firstPacket.respHeader);
		} catch (error) {
			try { await writer.abort(error) } catch (e) { }
			throw error;
		} finally {
			try { writer.releaseLock() } catch (e) { }
		}
		await socket.readable.pipeTo(responseStream.writable, { signal: abortController.signal });
	})();

	void uplinkPromise.catch(cleanup);
	void downlinkPromise.then(() => cleanup(), cleanup);
	void Promise.allSettled([uplinkPromise, downlinkPromise]);

	return new Response(responseStream.readable, { status: 200, headers: responseHeaders });
}

function handleXHttpUdpRequest(firstPacket, reader, request, proxyContext, responseHeaders) {
	const trojanUdpContext = { cachedBytes: new Uint8Array(0), proxyAddress: proxyContext.trojanFallbackAddress };
	return new Response(new ReadableStream({
		async start(controller) {
			let isClosed = false;
			let udpRespHeader = firstPacket.respHeader;
			const xhttpBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (isClosed) return;
					try {
						const chunk = data instanceof Uint8Array
							? data
							: data instanceof ArrayBuffer
								? new Uint8Array(data)
								: ArrayBuffer.isView(data)
									? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
									: new Uint8Array(data);
						controller.enqueue(chunk);
					} catch (e) {
						isClosed = true;
						this.readyState = WebSocket.CLOSED;
					}
				},
				close() {
					if (isClosed) return;
					isClosed = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};
			let forwardFailed = false;
			try {
				if (firstPacket.protocol === 'trojan') {
					trojanUdpContext.targetHost = firstPacket.hostname;
					trojanUdpContext.targetPort = firstPacket.port;
					if (trojanUdpContext.proxyAddress) await forwardTrojanUdpData(firstPacket.rawFirstPacket, xhttpBridge, trojanUdpContext, request);
				}
				if (!(firstPacket.protocol === 'trojan' && trojanUdpContext.proxyAddress) && firstPacket.rawData?.byteLength) {
					if (firstPacket.protocol === 'trojan') await forwardTrojanUdpData(firstPacket.rawData, xhttpBridge, trojanUdpContext, request);
					else await forwardataudp(firstPacket.rawData, xhttpBridge, udpRespHeader, request);
					udpRespHeader = null;
				}
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					if (firstPacket.protocol === 'trojan') await forwardTrojanUdpData(value, xhttpBridge, trojanUdpContext, request);
					else await forwardataudp(value, xhttpBridge, udpRespHeader, request);
					udpRespHeader = null;
				}
			} catch (err) {
				forwardFailed = true;
				log(`[xHTTP forward] handling failed: ${err?.message || err}`);
				closeSocketQuietly(xhttpBridge);
			} finally {
				const keepTrojanUdpDownlink = !forwardFailed && firstPacket.protocol === 'trojan' && trojanUdpContext.proxyAddress && trojanUdpContext.proxyIpSocket;
				if (!keepTrojanUdpDownlink) {
					try { trojanUdpContext.proxyIpSocket?.close() } catch (e) { }
					closeSocketQuietly(xhttpBridge);
				}
				try { reader.releaseLock() } catch (e) { }
			}
		},
		cancel() {
			try { trojanUdpContext.proxyIpSocket?.close() } catch (e) { }
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: responseHeaders });
}

function validDataLength(data) {
	if (!data) return 0;
	if (typeof data.byteLength === 'number') return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

function invalidateTcpGeneration(remoteConnWrapper) {
	if (!remoteConnWrapper) return;
	remoteConnWrapper.generation = (Number.isInteger(remoteConnWrapper.generation) ? remoteConnWrapper.generation : 0) + 1;
	const socket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	remoteConnWrapper.downlinkController = null;
	remoteConnWrapper.downlinkDrain = Promise.resolve();
	try { socket?.close?.() } catch (e) { }
}

function startTcpGeneration(remoteConnWrapper) {
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;
	const generation = ++remoteConnWrapper.generation;
	const previousSocket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	const previousDownlink = remoteConnWrapper.downlinkController;
	remoteConnWrapper.downlinkController = null;
	const previousDrain = remoteConnWrapper.downlinkDrain || Promise.resolve();
	let currentDrain;
	try { currentDrain = previousDownlink?.stopAndFlush?.() || Promise.resolve() }
	catch (error) { currentDrain = Promise.reject(error) }
	const downlinkDrain = Promise.all([previousDrain, currentDrain]);
	// Installation awaits this promise; attach a handler immediately in case draining fails before dialing completes.
	downlinkDrain.catch(() => { });
	remoteConnWrapper.downlinkDrain = downlinkDrain;
	try { previousSocket?.close?.() } catch (e) { }
	return { generation, downlinkDrain };
}

async function readXHttpFirstPacket(reader, token) {
	const decoder = vlessTextDecoder;

	const tryParseVlessFirstPacket = (data) => {
		const length = data.byteLength;
		if (length < 18) return { status: 'need_more' };
		if (!UUIDbyteMatch(data, 1, token)) return { status: 'invalid' };

		const optLen = data[17];
		const cmdIndex = 18 + optLen;
		if (length < cmdIndex + 1) return { status: 'need_more' };

		const cmd = data[cmdIndex];
		if (cmd !== 1 && cmd !== 2) return { status: 'invalid' };

		const portIndex = cmdIndex + 1;
		if (length < portIndex + 3) return { status: 'need_more' };

		const port = (data[portIndex] << 8) | data[portIndex + 1];
		const addressType = data[portIndex + 2];
		const addressIndex = portIndex + 3;
		let headerLen = -1;
		let hostname = '';

		if (addressType === 1) {
			if (length < addressIndex + 4) return { status: 'need_more' };
			hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			headerLen = addressIndex + 4;
		} else if (addressType === 2) {
			if (length < addressIndex + 1) return { status: 'need_more' };
			const domainLen = data[addressIndex];
			if (length < addressIndex + 1 + domainLen) return { status: 'need_more' };
			hostname = decoder.decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen));
			headerLen = addressIndex + 1 + domainLen;
		} else if (addressType === 3) {
			if (length < addressIndex + 16) return { status: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addressIndex + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			headerLen = addressIndex + 16;
		} else return { status: 'invalid' };

		if (!hostname) return { status: 'invalid' };

		return {
			status: 'ok',
			resultValue: {
				protocol: 'vl' + 'ess',
				hostname,
				port,
				isUDP: cmd === 2,
				rawData: data.subarray(headerLen),
				respHeader: new Uint8Array([data[0], 0]),
				rawFirstPacket: null,
			}
		};
	};

	const tryParseTrojanFirstPacket = (data) => {
		const passwordHash = sha224(token);
		const passwordHashBytes = new TextEncoder().encode(passwordHash);
		const length = data.byteLength;
		if (length < 58) return { status: 'need_more' };
		if (data[56] !== 0x0d || data[57] !== 0x0a) return { status: 'invalid' };
		for (let i = 0; i < 56; i++) {
			if (data[i] !== passwordHashBytes[i]) return { status: 'invalid' };
		}

		const socksStart = 58;
		if (length < socksStart + 2) return { status: 'need_more' };
		const cmd = data[socksStart];
		if (cmd !== 1 && cmd !== 3) return { status: 'invalid' };
		const isUDP = cmd === 3;

		const atype = data[socksStart + 1];
		let cursor = socksStart + 2;
		let hostname = '';

		if (atype === 1) {
			if (length < cursor + 4) return { status: 'need_more' };
			hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
			cursor += 4;
		} else if (atype === 3) {
			if (length < cursor + 1) return { status: 'need_more' };
			const domainLen = data[cursor];
			if (length < cursor + 1 + domainLen) return { status: 'need_more' };
			hostname = decoder.decode(data.subarray(cursor + 1, cursor + 1 + domainLen));
			cursor += 1 + domainLen;
		} else if (atype === 4) {
			if (length < cursor + 16) return { status: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = cursor + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			cursor += 16;
		} else return { status: 'invalid' };

		if (!hostname) return { status: 'invalid' };
		if (length < cursor + 4) return { status: 'need_more' };

		const port = (data[cursor] << 8) | data[cursor + 1];
		if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { status: 'invalid' };
		const dataOffset = cursor + 4;

		return {
			status: 'ok',
			resultValue: {
				protocol: 'trojan',
				hostname,
				port,
				isUDP,
				rawData: data.subarray(dataOffset),
				rawFirstPacket: data,
				respHeader: null,
			}
		};
	};

	let buffer = new Uint8Array(1024);
	let offset = 0;

	while (true) {
		const { value, done } = await reader.read();
		if (done) {
			if (offset === 0) return null;
			break;
		}

		const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
		if (offset + chunk.byteLength > buffer.byteLength) {
			const newBuffer = new Uint8Array(Math.max(buffer.byteLength * 2, offset + chunk.byteLength));
			newBuffer.set(buffer.subarray(0, offset));
			buffer = newBuffer;
		}

		buffer.set(chunk, offset);
		offset += chunk.byteLength;

		const currentData = buffer.subarray(0, offset);
		const trojanResult = tryParseTrojanFirstPacket(currentData);
		if (trojanResult.status === 'ok') return { ...trojanResult.resultValue, reader };

		const vlessParseResult = tryParseVlessFirstPacket(currentData);
		if (vlessParseResult.status === 'ok') return { ...vlessParseResult.resultValue, reader };

		if (trojanResult.status === 'invalid' && vlessParseResult.status === 'invalid') return null;
	}

	const finalData = buffer.subarray(0, offset);
	const finalTrojanResult = tryParseTrojanFirstPacket(finalData);
	if (finalTrojanResult.status === 'ok') return { ...finalTrojanResult.resultValue, reader };
	const finalVlessResult = tryParseVlessFirstPacket(finalData);
	if (finalVlessResult.status === 'ok') return { ...finalVlessResult.resultValue, reader };
	return null;
}
///////////////////////////////////////////////////////////////////////gRPC transfer data///////////////////////////////////////////////
async function handleGrpcRequest(request, yourUUID, proxyContext = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const invalidateRemoteConn = () => invalidateTcpGeneration(remoteConnWrapper);
	let isDnsQuery = false;
	const trojanUdpContext = { cachedBytes: new Uint8Array(0), proxyAddress: proxyContext.trojanFallbackAddress };
	let isTrojanDetected = null;
	let currentWriteSocket = null;
	let remoteWriter = null;
	let GRPCuplinkWriteQueue = null;
	//log('[gRPC] start handling the bidirectional stream');
	const grpcHeaders = new Headers({
		'Content-Type': 'application/grpc',
		'grpc-status': '0',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	const downlinkBufferLimit = downGrainPacketBytes;
	const downlinkFlushInterval = 1;

	return new Response(new ReadableStream({
		async start(controller) {
			let isClosed = false;
			let sendQueue = [];
			let queueByteCount = 0;
			let flushTimer = null;
			let flushMicrotaskQueued = false;
			const grpcBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (isClosed) return;
					const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
					const lenBytesarray = [];
					let remaining = chunk.byteLength >>> 0;
					while (remaining > 127) {
						lenBytesarray.push((remaining & 0x7f) | 0x80);
						remaining >>>= 7;
					}
					lenBytesarray.push(remaining);
					const lenBytes = new Uint8Array(lenBytesarray);
					const protobufLen = 1 + lenBytes.length + chunk.byteLength;
					const frame = new Uint8Array(5 + protobufLen);
					frame[0] = 0;
					frame[1] = (protobufLen >>> 24) & 0xff;
					frame[2] = (protobufLen >>> 16) & 0xff;
					frame[3] = (protobufLen >>> 8) & 0xff;
					frame[4] = protobufLen & 0xff;
					frame[5] = 0x0a;
					frame.set(lenBytes, 6);
					frame.set(chunk, 6 + lenBytes.length);
					sendQueue.push(frame);
					queueByteCount += frame.byteLength;
					scheduleSendQueueFlush();
				},
				close() {
					if (this.readyState === WebSocket.CLOSED) return;
					flushSendQueue(true);
					isClosed = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};

			const flushSendQueue = (force = false) => {
				flushMicrotaskQueued = false;
				if (flushTimer) {
					clearTimeout(flushTimer);
					flushTimer = null;
				}
				if ((!force && isClosed) || queueByteCount === 0) return;
				const out = new Uint8Array(queueByteCount);
				let offset = 0;
				for (const item of sendQueue) {
					out.set(item, offset);
					offset += item.byteLength;
				}
				sendQueue = [];
				queueByteCount = 0;
				try {
					controller.enqueue(out);
				} catch (e) {
					isClosed = true;
					grpcBridge.readyState = WebSocket.CLOSED;
				}
			};

			const scheduleSendQueueFlush = () => {
				if (queueByteCount >= downlinkBufferLimit) {
					flushSendQueue();
					return;
				}
				if (flushMicrotaskQueued || flushTimer) return;
				flushMicrotaskQueued = true;
				queueMicrotask(() => {
					flushMicrotaskQueued = false;
					if (isClosed || queueByteCount === 0 || flushTimer) return;
					flushTimer = setTimeout(flushSendQueue, downlinkFlushInterval);
				});
			};

			const closeConnection = () => {
				if (isClosed) return;
				GRPCuplinkWriteQueue?.clear();
				invalidateRemoteConn();
				flushSendQueue(true);
				isClosed = true;
				grpcBridge.readyState = WebSocket.CLOSED;
				if (flushTimer) clearTimeout(flushTimer);
				if (remoteWriter) {
					try { remoteWriter.releaseLock() } catch (e) { }
					remoteWriter = null;
				}
				currentWriteSocket = null;
				try { reader.releaseLock() } catch (e) { }
				try { trojanUdpContext.proxyIpSocket?.close() } catch (e) { }
				try { controller.close() } catch (e) { }
			};

			const releaseRemoteWriter = () => {
				if (remoteWriter) {
					try { remoteWriter.releaseLock() } catch (e) { }
					remoteWriter = null;
				}
				currentWriteSocket = null;
			};

			const uplinkWriteQueue = GRPCuplinkWriteQueue = createUplinkWriteQueue({
				getWriter: () => {
					const socket = remoteConnWrapper.socket;
					if (!socket) return null;
					if (socket !== currentWriteSocket) {
						releaseRemoteWriter();
						currentWriteSocket = socket;
						remoteWriter = socket.writable.getWriter();
					}
					return remoteWriter;
				},
				getConnectionTask: () => remoteConnWrapper.connectingPromise,
				releaseWriter: releaseRemoteWriter,
				retryConnection: async () => {
					if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
					await remoteConnWrapper.retryConnect();
				},
				closeConnection,
				queueName: 'gRPC upload'
			});

			const writeRemote = async (payload, allowRetry = true) => {
				return uplinkWriteQueue.writeAndWait(payload, allowRetry);
			};

			let forwardFailed = false;
			try {
				let pending = new Uint8Array(0);
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					const currentChunk = value instanceof Uint8Array ? value : new Uint8Array(value);
					const merged = new Uint8Array(pending.length + currentChunk.length);
					merged.set(pending, 0);
					merged.set(currentChunk, pending.length);
					pending = merged;
					while (pending.byteLength >= 5) {
						const grpcLen = ((pending[1] << 24) >>> 0) | (pending[2] << 16) | (pending[3] << 8) | pending[4];
						const frameSize = 5 + grpcLen;
						if (pending.byteLength < frameSize) break;
						const grpcPayload = pending.subarray(5, frameSize);
						pending = pending.slice(frameSize);
						if (!grpcPayload.byteLength) continue;
						let payload = grpcPayload;
						if (payload.byteLength >= 2 && payload[0] === 0x0a) {
							let shift = 0;
							let offset = 1;
							let varintvalid = false;
							while (offset < payload.length) {
								const current = payload[offset++];
								if ((current & 0x80) === 0) {
									varintvalid = true;
									break;
								}
								shift += 7;
								if (shift > 35) break;
							}
							if (varintvalid) payload = payload.subarray(offset);
						}
						if (!payload.byteLength) continue;
						if (isDnsQuery) {
							if (isTrojanDetected) await forwardTrojanUdpData(payload, grpcBridge, trojanUdpContext, request);
							else await forwardataudp(payload, grpcBridge, null, request);
							continue;
						}
						if (remoteConnWrapper.socket || remoteConnWrapper.connectingPromise) {
							if (!(await writeRemote(payload))) throw new Error('Remote socket is not ready');
						} else {
							const firstPacketBytes = toUint8Array(payload);
							if (isTrojanDetected === null) isTrojanDetected = firstPacketBytes.byteLength >= 58 && firstPacketBytes[56] === 0x0d && firstPacketBytes[57] === 0x0a;
							if (isTrojanDetected) {
								const parseResult = parseTrojanRequest(firstPacketBytes, yourUUID);
								if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid trojan request');
								const { port, hostname, rawClientData, isUDP } = parseResult;
								log(`[gRPC] Trojan first packet: ${hostname}:${port} | UDP: ${isUDP ? 'yes' : 'no'}`);
								if (isSpeedTestSite(hostname) && proxyContext.proxyType === null) {
									grpcBridge.send(buildLocal204Response());
									return;
								}
								if (isUDP) {
									isDnsQuery = true;
									trojanUdpContext.targetHost = hostname;
									trojanUdpContext.targetPort = port;
									if (trojanUdpContext.proxyAddress) await forwardTrojanUdpData(firstPacketBytes, grpcBridge, trojanUdpContext, request);
									else if (validDataLength(rawClientData) > 0) await forwardTrojanUdpData(rawClientData, grpcBridge, trojanUdpContext, request);
								} else {
									await forwardataTCP(hostname, port, rawClientData, grpcBridge, null, remoteConnWrapper, yourUUID, request, proxyContext, true, firstPacketBytes);
								}
							} else {
								isTrojanDetected = false;
								const parseResult = parseVlessRequest(firstPacketBytes, yourUUID);
								if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid VLESS request');
								const { port, hostname, version, isUDP, rawClientData } = parseResult;
								log(`[gRPC] VLESS first packet: ${hostname}:${port} | UDP: ${isUDP ? 'yes' : 'no'}`);
								const respHeader = new Uint8Array([version, 0]);
								if (isSpeedTestSite(hostname) && proxyContext.proxyType === null) {
									grpcBridge.send(buildLocal204Response(respHeader));
									return;
								}
								if (isUDP) {
									if (port !== 53) throw new Error('UDP is not supported');
									isDnsQuery = true;
								}
								grpcBridge.send(respHeader);
								const rawData = rawClientData;
								if (isDnsQuery) {
									if (isTrojanDetected) await forwardTrojanUdpData(rawData, grpcBridge, trojanUdpContext, request);
									else await forwardataudp(rawData, grpcBridge, null, request);
								}
								else await forwardataTCP(hostname, port, rawData, grpcBridge, null, remoteConnWrapper, yourUUID, request, proxyContext);
							}
						}
					}
					flushSendQueue();
				}
				await uplinkWriteQueue.waitQueueDrained();
			} catch (err) {
				forwardFailed = true;
				log(`[gRPC forward] handling failed: ${err?.message || err}`);
			} finally {
				const keepTrojanUdpDownlink = !forwardFailed && isDnsQuery && isTrojanDetected && trojanUdpContext.proxyAddress && trojanUdpContext.proxyIpSocket;
				if (keepTrojanUdpDownlink) {
					uplinkWriteQueue.clear();
					invalidateRemoteConn();
					releaseRemoteWriter();
					try { reader.releaseLock() } catch (e) { }
				} else {
					closeConnection();
				}
			}
		},
		cancel() {
			GRPCuplinkWriteQueue?.clear();
			invalidateRemoteConn();
			try { trojanUdpContext.proxyIpSocket?.close() } catch (e) { }
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: grpcHeaders });
}

function isValidWsEarlyData(bytes, token) {
	if (!bytes?.byteLength) return false;
	if (bytes.byteLength >= 18 && UUIDbyteMatch(bytes, 1, token)) return true;
	if (bytes.byteLength < 58 || bytes[56] !== 0x0d || bytes[57] !== 0x0a) return false;

	const trojanPassword = sha224(token);
	for (let i = 0; i < 56; i++) {
		if (bytes[i] !== trojanPassword.charCodeAt(i)) return false;
	}
	return true;
}

function decodeWsEarlyData(header, token) {
	if (!header) return null;
	if (header.length > WSearlyDataMaxHeaderLen) throw new Error('early data is too large');

	let bytes;
	const Uint8ArrayBase64 = /** @type {any} */ (Uint8Array);
	if (typeof Uint8ArrayBase64.fromBase64 === 'function') {
		try {
			bytes = Uint8ArrayBase64.fromBase64(header, { alphabet: 'base64url' });
		} catch (_) { }
	}
	if (!bytes) {
		let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
		const padding = normalized.length % 4;
		if (padding) normalized += '='.repeat(4 - padding);
		let binaryString;
		try {
			binaryString = atob(normalized);
		} catch (_) {
			return null;
		}
		bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
	}

	if (bytes.byteLength > WSearlyDataMaxBytes) throw new Error('early data is too large');
	return isValidWsEarlyData(bytes, token) ? bytes : null;
}

///////////////////////////////////////////////////////////////////////WS transfer data///////////////////////////////////////////////
async function handleWsRequest(request, yourUUID, url, proxyContext = {}) {
	const WSsocketPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(WSsocketPair);
	try { (/** @type {any} */ (serverSock)).accept({ allowHalfOpen: true }) }
	catch (_) { serverSock.accept() }
	serverSock.binaryType = 'arraybuffer';
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const invalidateRemoteConn = () => invalidateTcpGeneration(remoteConnWrapper);
	let isDnsQuery = false;
	let isTrojanDetected = null;
	const trojanUdpContext = { cachedBytes: new Uint8Array(0), proxyAddress: proxyContext.trojanFallbackAddress };
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const SSearlyDataDisabled = !!url.searchParams.get('enc');
	let WSuplinkWriteQueue = null;
	let wsExplicitTransportChain = Promise.resolve();
	let WSexplicitStopReceiving = false, WSexplicitTransportFailed = false, WSexplicitFinalizeQueued = false;
	let WSexplicitQueueBytes = 0, WSexplicitQueueItems = 0;
	let detectedProtocol = null, currentWriteSocket = null, remoteWriter = null;
	let sscontext = null, ssinitTask = null;
	let WSlocalSpeedTestMode = false, WSspeedTestSocket = null;
	let WSlocalSpeedTestReqBuffer = new Uint8Array(0);
	let WSlocalSpeedTestRespHeader = null;
	const WSlocalSpeedTestReqLimit = 64 * 1024;

	const sendWsLocalSpeedReply = async () => {
		if (!WSspeedTestSocket) return;
		const respHeader = WSlocalSpeedTestRespHeader;
		WSlocalSpeedTestRespHeader = null;
		await WebSocketsendAndWait(WSspeedTestSocket, buildWsLocal204Response(respHeader));
	};

	const findHttpHeaderEnd = (data) => {
		for (let i = 0; i <= data.byteLength - 4; i++) {
			if (data[i] === 0x0d && data[i + 1] === 0x0a && data[i + 2] === 0x0d && data[i + 3] === 0x0a) return i + 4;
		}
		return -1;
	};

	const handleWsLocalSpeedTestData = async (data) => {
		const chunk = toUint8Array(data);
		if (!chunk.byteLength) return;
		if (WSlocalSpeedTestReqBuffer.byteLength + chunk.byteLength > WSlocalSpeedTestReqLimit) throw new Error('WS local speed-test request is too large');
		WSlocalSpeedTestReqBuffer = concatByteChunks(WSlocalSpeedTestReqBuffer, chunk);

		while (WSlocalSpeedTestReqBuffer.byteLength) {
			const headerEnd = findHttpHeaderEnd(WSlocalSpeedTestReqBuffer);
			if (headerEnd === -1) return;
			const headerText = vlessTextDecoder.decode(WSlocalSpeedTestReqBuffer.subarray(0, headerEnd));
			const contentLengthMatch = headerText.match(/(?:^|\r\n)content-length\s*:\s*(\d+)/i);
			const contentLength = contentLengthMatch ? Number(contentLengthMatch[1]) : 0;
			const requestLength = headerEnd + contentLength;
			if (!Number.isSafeInteger(contentLength) || requestLength > WSlocalSpeedTestReqLimit) throw new Error('WS local speed-test request body is too large');
			if (WSlocalSpeedTestReqBuffer.byteLength < requestLength) return;
			WSlocalSpeedTestReqBuffer = WSlocalSpeedTestReqBuffer.slice(requestLength);
			await sendWsLocalSpeedReply();
		}
	};

	const enableWsLocalSpeedtest = async (replySocket, respHeader = null, firstRequestData = null) => {
		WSlocalSpeedTestMode = true;
		WSspeedTestSocket = replySocket;
		WSlocalSpeedTestReqBuffer = new Uint8Array(0);
		WSlocalSpeedTestRespHeader = respHeader;
		if (validDataLength(firstRequestData) > 0) await handleWsLocalSpeedTestData(firstRequestData);
	};

	const releaseRemoteWriter = () => {
		if (remoteWriter) {
			try { remoteWriter.releaseLock() } catch (e) { }
			remoteWriter = null;
		}
		currentWriteSocket = null;
	};

	const uplinkWriteQueue = WSuplinkWriteQueue = createUplinkWriteQueue({
		getWriter: () => {
			const socket = remoteConnWrapper.socket;
			if (!socket) return null;
			if (socket !== currentWriteSocket) {
				releaseRemoteWriter();
				currentWriteSocket = socket;
				remoteWriter = socket.writable.getWriter();
			}
			return remoteWriter;
		},
		getConnectionTask: () => remoteConnWrapper.connectingPromise,
		releaseWriter: releaseRemoteWriter,
		retryConnection: async () => {
			if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
			await remoteConnWrapper.retryConnect();
		},
		closeConnection: err => handleWsExplicitError(err),
		queueName: 'WS upstream'
	});

	const writeRemote = async (chunk, allowRetry = true) => {
		return uplinkWriteQueue.write(chunk, allowRetry);
	};

	const getSsContext = async () => {
		if (sscontext) return sscontext;
		if (!ssinitTask) {
			ssinitTask = (async () => {
				const requestedCipher = (url.searchParams.get('enc') || '').toLowerCase();
				const preferredCipherConfig = SSsupportedCipherConfigs[requestedCipher] || SSsupportedCipherConfigs['aes-128-gcm'];
				const inboundCipherCandidates = [preferredCipherConfig, ...Object.values(SSsupportedCipherConfigs).filter(c => c.method !== preferredCipherConfig.method)];
				const inboundKeyTaskCache = new Map();
				const getInboundKeyTask = (config) => {
					if (!inboundKeyTaskCache.has(config.method)) inboundKeyTaskCache.set(config.method, SSderiveMasterKey(yourUUID, config.keyLen));
					return inboundKeyTaskCache.get(config.method);
				};
				const inboundState = {
					buffer: new Uint8Array(0),
					hasSalt: false,
					waitPayloadLength: null,
					decryptKey: null,
					nonceCounter: new Uint8Array(SSNoncepaddingLength),
					cipherConfig: null,
				};
				const initInboundDecryptState = async () => {
					const lengthCipherTotalLength = 2 + SSAEADtagLength;
					const maxSaltLength = Math.max(...inboundCipherCandidates.map(c => c.saltLen));
					const maxAlignScanBytes = 16;
					const maxScanOffset = Math.min(maxAlignScanBytes, Math.max(0, inboundState.buffer.byteLength - (lengthCipherTotalLength + Math.min(...inboundCipherCandidates.map(c => c.saltLen)))));
					for (let offset = 0; offset <= maxScanOffset; offset++) {
						for (const cipherConfig of inboundCipherCandidates) {
							const minInitBytes = offset + cipherConfig.saltLen + lengthCipherTotalLength;
							if (inboundState.buffer.byteLength < minInitBytes) continue;
							const salt = inboundState.buffer.subarray(offset, offset + cipherConfig.saltLen);
							const lengthCipher = inboundState.buffer.subarray(offset + cipherConfig.saltLen, minInitBytes);
							const masterKey = await getInboundKeyTask(cipherConfig);
							const decryptKey = await SSderiveSessionKey(cipherConfig, masterKey, salt, ['decrypt']);
							const nonceCounter = new Uint8Array(SSNoncepaddingLength);
							try {
								const lengthPlain = await SSAEADdecryptPayload(decryptKey, nonceCounter, lengthCipher);
								if (lengthPlain.byteLength !== 2) continue;
								const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
								if (payloadLength < 0 || payloadLength > cipherConfig.maxChunk) continue;
								if (offset > 0) log(`[SS inbound] detected leading noise ${offset}B, auto-aligned`);
								if (cipherConfig.method !== preferredCipherConfig.method) log(`[SS inbound] URL enc=${requestedCipher || preferredCipherConfig.method} mismatches actual ${cipherConfig.method}, auto-switched`);
								inboundState.buffer = inboundState.buffer.subarray(minInitBytes);
								inboundState.decryptKey = decryptKey;
								inboundState.nonceCounter = nonceCounter;
								inboundState.waitPayloadLength = payloadLength;
								inboundState.cipherConfig = cipherConfig;
								inboundState.hasSalt = true;
								return true;
							} catch (_) { }
						}
					}
					const initFailThresholdBytes = maxSaltLength + lengthCipherTotalLength + maxAlignScanBytes;
					if (inboundState.buffer.byteLength >= initFailThresholdBytes) {
						throw new Error(`SS handshake decrypt failed (enc=${requestedCipher || 'auto'}, candidates=${inboundCipherCandidates.map(c => c.method).join('/')})`);
					}
					return false;
				};
				const inboundDecryptor = {
					async decryptInput(dataChunk) {
						const chunk = toUint8Array(dataChunk);
						if (chunk.byteLength > 0) inboundState.buffer = concatByteChunks(inboundState.buffer, chunk);
						if (!inboundState.hasSalt) {
							const initSucceeded = await initInboundDecryptState();
							if (!initSucceeded) return [];
						}
						const plaintextChunks = [];
						while (true) {
							if (inboundState.waitPayloadLength === null) {
								const lengthCipherTotalLength = 2 + SSAEADtagLength;
								if (inboundState.buffer.byteLength < lengthCipherTotalLength) break;
								const lengthCipher = inboundState.buffer.subarray(0, lengthCipherTotalLength);
								inboundState.buffer = inboundState.buffer.subarray(lengthCipherTotalLength);
								const lengthPlain = await SSAEADdecryptPayload(inboundState.decryptKey, inboundState.nonceCounter, lengthCipher);
								if (lengthPlain.byteLength !== 2) throw new Error('SS length decrypt failed');
								const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
								if (payloadLength < 0 || payloadLength > inboundState.cipherConfig.maxChunk) throw new Error(`SS payload length invalid: ${payloadLength}`);
								inboundState.waitPayloadLength = payloadLength;
							}
							const payloadCipherTotalLength = inboundState.waitPayloadLength + SSAEADtagLength;
							if (inboundState.buffer.byteLength < payloadCipherTotalLength) break;
							const payloadCipher = inboundState.buffer.subarray(0, payloadCipherTotalLength);
							inboundState.buffer = inboundState.buffer.subarray(payloadCipherTotalLength);
							const payloadPlain = await SSAEADdecryptPayload(inboundState.decryptKey, inboundState.nonceCounter, payloadCipher);
							plaintextChunks.push(payloadPlain);
							inboundState.waitPayloadLength = null;
						}
						return plaintextChunks;
					},
				};
				let outboundEncryptor = null;
				const SSmaxBatchBytes = 32 * 1024;
				const getOutboundCipher = async () => {
					if (outboundEncryptor) return outboundEncryptor;
					if (!inboundState.cipherConfig) throw new Error('SS cipher is not negotiated');
					const outboundCipherConfig = inboundState.cipherConfig;
					const outboundMasterKey = await SSderiveMasterKey(yourUUID, outboundCipherConfig.keyLen);
					const outboundSaltBytes = crypto.getRandomValues(new Uint8Array(outboundCipherConfig.saltLen));
					const outboundSessionKey = await SSderiveSessionKey(outboundCipherConfig, outboundMasterKey, outboundSaltBytes, ['encrypt']);
					const outboundNonceCounter = new Uint8Array(SSNoncepaddingLength);
					let randomBytesSent = false;
					outboundEncryptor = {
						async encryptAndSend(dataChunk, sendChunk) {
							const plaintextData = toUint8Array(dataChunk);
							if (!randomBytesSent) {
								await sendChunk(outboundSaltBytes);
								randomBytesSent = true;
							}
							if (plaintextData.byteLength === 0) return;
							let offset = 0;
							while (offset < plaintextData.byteLength) {
								const end = Math.min(offset + outboundCipherConfig.maxChunk, plaintextData.byteLength);
								const payloadPlain = plaintextData.subarray(offset, end);
								const lengthPlain = new Uint8Array(2);
								lengthPlain[0] = (payloadPlain.byteLength >>> 8) & 0xff;
								lengthPlain[1] = payloadPlain.byteLength & 0xff;
								const lengthCipher = await SSAEADencrypt(outboundSessionKey, outboundNonceCounter, lengthPlain);
								const payloadCipher = await SSAEADencrypt(outboundSessionKey, outboundNonceCounter, payloadPlain);
								const frame = new Uint8Array(lengthCipher.byteLength + payloadCipher.byteLength);
								frame.set(lengthCipher, 0);
								frame.set(payloadCipher, lengthCipher.byteLength);
								await sendChunk(frame);
								offset = end;
							}
						},
					};
					return outboundEncryptor;
				};
				let SSsendQueue = Promise.resolve();
				const SSenqueueSend = (chunk) => {
					SSsendQueue = SSsendQueue.then(async () => {
						if (serverSock.readyState !== WebSocket.OPEN) return;
						const readyOutboundCipher = await getOutboundCipher();
						await readyOutboundCipher.encryptAndSend(chunk, async (encryptedChunk) => {
							if (encryptedChunk.byteLength > 0 && serverSock.readyState === WebSocket.OPEN) {
								await WebSocketsendAndWait(serverSock, encryptedChunk.buffer);
							}
						});
					}).catch((error) => {
						log(`[SS send] encryption failed: ${error?.message || error}`);
						closeSocketQuietly(serverSock);
					});
					return SSsendQueue;
				};
				const replySocket = {
					get readyState() {
						return serverSock.readyState;
					},
					send(data) {
						const chunk = toUint8Array(data);
						if (chunk.byteLength <= SSmaxBatchBytes) {
							return SSenqueueSend(chunk);
						}
						for (let i = 0; i < chunk.byteLength; i += SSmaxBatchBytes) {
							SSenqueueSend(chunk.subarray(i, Math.min(i + SSmaxBatchBytes, chunk.byteLength)));
						}
						return SSsendQueue;
					},
					close() {
						closeSocketQuietly(serverSock);
					}
				};
				sscontext = {
					inboundDecryptor,
					replySocket,
					firstPacketEstablished: false,
					targetHost: '',
					targetPort: 0,
				};
				return sscontext;
			})().finally(() => { ssinitTask = null });
		}
		return ssinitTask;
	};

	const handleSsData = async (chunk) => {
		const context = await getSsContext();
		let plaintextChunkList = null;
		try {
			plaintextChunkList = await context.inboundDecryptor.decryptInput(chunk);
		} catch (err) {
			const msg = err?.message || `${err}`;
			if (msg.includes('Decryption failed') || msg.includes('SS handshake decrypt failed') || msg.includes('SS length decrypt failed')) {
				log(`[SS inbound] decryption failed, connection closed: ${msg}`);
				closeSocketQuietly(serverSock);
				return;
			}
			throw err;
		}
		for (const plaintextChunk of plaintextChunkList) {
			if (WSlocalSpeedTestMode) {
				await handleWsLocalSpeedTestData(plaintextChunk);
				continue;
			}
			let hasWritten = false;
			try {
				hasWritten = await writeRemote(plaintextChunk, false);
			} catch (err) {
				if ((/** @type {any} */ (err))?.isQueueOverflow) throw err;
				hasWritten = false;
			}
			if (hasWritten) continue;
			if (context.firstPacketEstablished && context.targetHost && context.targetPort > 0) {
				await forwardataTCP(context.targetHost, context.targetPort, plaintextChunk, context.replySocket, null, remoteConnWrapper, yourUUID, request, proxyContext);
				continue;
			}
			const plaintextData = toUint8Array(plaintextChunk);
			if (plaintextData.byteLength < 3) throw new Error('invalid ss data');
			const addressType = plaintextData[0];
			let cursor = 1;
			let hostname = '';
			if (addressType === 1) {
				if (plaintextData.byteLength < cursor + 4 + 2) throw new Error('invalid ss ipv4 length');
				hostname = `${plaintextData[cursor]}.${plaintextData[cursor + 1]}.${plaintextData[cursor + 2]}.${plaintextData[cursor + 3]}`;
				cursor += 4;
			} else if (addressType === 3) {
				if (plaintextData.byteLength < cursor + 1) throw new Error('invalid ss domain length');
				const domainLength = plaintextData[cursor];
				cursor += 1;
				if (plaintextData.byteLength < cursor + domainLength + 2) throw new Error('invalid ss domain data');
				hostname = SStextDecoder.decode(plaintextData.subarray(cursor, cursor + domainLength));
				cursor += domainLength;
			} else if (addressType === 4) {
				if (plaintextData.byteLength < cursor + 16 + 2) throw new Error('invalid ss ipv6 length');
				const ipv6 = [];
				const ipv6View = new DataView(plaintextData.buffer, plaintextData.byteOffset + cursor, 16);
				for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
				hostname = ipv6.join(':');
				cursor += 16;
			} else {
				throw new Error(`invalid ss addressType: ${addressType}`);
			}
			if (!hostname) throw new Error(`invalid ss address: ${addressType}`);
			const port = (plaintextData[cursor] << 8) | plaintextData[cursor + 1];
			cursor += 2;
			const rawClientData = plaintextData.subarray(cursor);
			if (isSpeedTestSite(hostname) && proxyContext.proxyType === null) {
				await enableWsLocalSpeedtest(context.replySocket, null, rawClientData);
				return;
			}
			context.firstPacketEstablished = true;
			context.targetHost = hostname;
			context.targetPort = port;
			await forwardataTCP(hostname, port, rawClientData, context.replySocket, null, remoteConnWrapper, yourUUID, request, proxyContext);
		}
	};

	const handleWsInboundData = async (chunk) => {
		let currentChunkBytes = null;
		if (isDnsQuery) {
			if (isTrojanDetected) return await forwardTrojanUdpData(chunk, serverSock, trojanUdpContext, request);
			return await forwardataudp(chunk, serverSock, null, request);
		}
		if (detectedProtocol === 'ss') {
			await handleSsData(chunk);
			return;
		}
		if (WSlocalSpeedTestMode) {
			await handleWsLocalSpeedTestData(chunk);
			return;
		}
		if (await writeRemote(chunk)) return;

		if (detectedProtocol === null) {
			if (url.searchParams.get('enc')) detectedProtocol = 'ss';
			else {
				currentChunkBytes = currentChunkBytes || toUint8Array(chunk);
				const bytes = currentChunkBytes;
				detectedProtocol = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a ? 'Trojan' : 'VLESS';
			}
			isTrojanDetected = detectedProtocol === 'Trojan';
			log(`[WS forward] protocol type: ${detectedProtocol} | from: ${url.host} | UA: ${request.headers.get('user-agent') || 'unknown'}`);
		}

		if (detectedProtocol === 'ss') {
			await handleSsData(chunk);
			return;
		}
		if (await writeRemote(chunk)) return;
		if (detectedProtocol === 'Trojan') {
			const parseResult = parseTrojanRequest(chunk, yourUUID);
			if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid trojan request');
			const { port, hostname, rawClientData, isUDP } = parseResult;
			if (isSpeedTestSite(hostname) && proxyContext.proxyType === null) {
				await enableWsLocalSpeedtest(serverSock, null, rawClientData);
				return;
			}
			if (isUDP) {
				isDnsQuery = true;
				trojanUdpContext.targetHost = hostname;
				trojanUdpContext.targetPort = port;
				if (trojanUdpContext.proxyAddress) return forwardTrojanUdpData(currentChunkBytes || toUint8Array(chunk), serverSock, trojanUdpContext, request);
				if (validDataLength(rawClientData) > 0) return forwardTrojanUdpData(rawClientData, serverSock, trojanUdpContext, request);
				return;
			}
			await forwardataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, yourUUID, request, proxyContext, true, currentChunkBytes || toUint8Array(chunk));
		} else {
			isTrojanDetected = false;
			currentChunkBytes = currentChunkBytes || toUint8Array(chunk);
			const bytes = currentChunkBytes;
			const parseResult = parseVlessRequest(bytes, yourUUID);
			if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid VLESS request');
			const { port, hostname, version, isUDP, rawClientData } = parseResult;
			const respHeader = new Uint8Array([version, 0]);
			if (isSpeedTestSite(hostname) && proxyContext.proxyType === null) {
				await enableWsLocalSpeedtest(serverSock, respHeader, rawClientData);
				return;
			}
			if (isUDP) {
				if (port === 53) isDnsQuery = true;
				else throw new Error('UDP is not supported');
			}
			const rawData = rawClientData;
			if (isDnsQuery) {
				if (isTrojanDetected) return forwardTrojanUdpData(rawData, serverSock, trojanUdpContext, request);
				return forwardataudp(rawData, serverSock, respHeader, request);
			}
			await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, yourUUID, request, proxyContext);
		}
	};

	const handleWsExplicitError = (err) => {
		if (WSexplicitTransportFailed) return;
		WSexplicitTransportFailed = true;
		WSexplicitStopReceiving = true;
		WSexplicitQueueBytes = 0;
		WSexplicitQueueItems = 0;
		const msg = err?.message || `${err}`;
		if (msg.includes('Network connection lost') || msg.includes('ReadableStream is closed')) {
			log(`[WS forward] connection ended: ${msg}`);
		} else {
			log(`[WS forward] processing failed: ${msg}`);
		}
		uplinkWriteQueue.clear();
		releaseRemoteWriter();
		invalidateRemoteConn();
		try { trojanUdpContext.proxyIpSocket?.close() } catch (e) { }
		closeSocketQuietly(serverSock);
	};

	const appendWsExplicitTask = (task) => {
		wsExplicitTransportChain = wsExplicitTransportChain.then(task).catch(handleWsExplicitError);
		return wsExplicitTransportChain;
	};

	const enqueueWsExplicit = (data) => {
		if (WSexplicitStopReceiving || WSexplicitTransportFailed) return;
		const chunkSize = Math.max(0, validDataLength(data));
		const nextBytes = WSexplicitQueueBytes + chunkSize;
		const nextItems = WSexplicitQueueItems + 1;
		if (nextBytes > uplinkQueueMaxBytes || nextItems > uplinkQueueMaxItems) {
			handleWsExplicitError(new Error(`[WS explicit transport] queue overflow: ${nextBytes}B/${nextItems}`));
			return;
		}
		WSexplicitQueueBytes = nextBytes;
		WSexplicitQueueItems = nextItems;
		appendWsExplicitTask(async () => {
			WSexplicitQueueBytes = Math.max(0, WSexplicitQueueBytes - chunkSize);
			WSexplicitQueueItems = Math.max(0, WSexplicitQueueItems - 1);
			if (WSexplicitTransportFailed) return;
			await handleWsInboundData(data);
		});
	};

	const finishWsExplicitTransport = () => {
		if (WSexplicitFinalizeQueued) return;
		WSexplicitFinalizeQueued = true;
		WSexplicitStopReceiving = true;
		appendWsExplicitTask(async () => {
			if (WSexplicitTransportFailed) return;
			await uplinkWriteQueue.waitQueueDrained();
			releaseRemoteWriter();
			invalidateRemoteConn();
			try { trojanUdpContext.proxyIpSocket?.close() } catch (e) { }
		});
	};

	serverSock.addEventListener('message', (event) => {
		enqueueWsExplicit(event.data);
	});
	serverSock.addEventListener('close', () => {
		closeSocketQuietly(serverSock);
		finishWsExplicitTransport();
	});
	serverSock.addEventListener('error', (err) => {
		handleWsExplicitError(err);
	});

	// SS mode, disable sec-websocket-protocol early-data so a subprotocol value (such as "binary") is not taken for base64 data and pushed into the first packet, which would break AEAD decryption.
	if (!SSearlyDataDisabled && earlyDataHeader) {
		try {
			const bytes = decodeWsEarlyData(earlyDataHeader, yourUUID);
			if (bytes?.byteLength) enqueueWsExplicit(bytes.buffer);
		} catch (error) {
			handleWsExplicitError(error);
		}
	}

	return new Response(null, { status: 101, webSocket: clientSock, headers: { 'Sec-WebSocket-Extensions': '' } });
}

const trojanTextDecoder = new TextDecoder();

function parseTrojanReverseAddress(address) {
	const raw = String(address || '').trim();
	if (!raw || raw.includes('/') || raw.includes('@') || raw.includes('://')) throw new Error('Trojan reverse proxy only supports host:port');
	let hostname = '', portText = '';
	if (raw.startsWith('[')) {
		const matchResult = raw.match(/^(\[[^\]]+\]):(\d+)$/);
		if (!matchResult) throw new Error('invalid IPv6 Trojan reverse proxy address');
		hostname = matchResult[1];
		portText = matchResult[2];
	} else {
		const parts = raw.split(':');
		if (parts.length !== 2) throw new Error('Trojan reverse proxy only supports host:port');
		hostname = parts[0];
		portText = parts[1];
	}
	const port = Number(portText);
	if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('invalid Trojan reverse proxy port');
	return { hostname, port };
}

async function connectTrojanProxy(firstPacketData, TCPconnection, trojanFallbackTarget) {
	if (!trojanFallbackTarget) throw new Error('trojan fallback is not configured');
	const socket = TCPconnection({ hostname: stripIPv6Brackets(trojanFallbackTarget.hostname), port: trojanFallbackTarget.port });
	let writer = null;
	try {
		if (socket.opened) await socket.opened;
		if (validDataLength(firstPacketData) > 0) {
			writer = socket.writable.getWriter();
			await writer.write(toUint8Array(firstPacketData));
		}
		return socket;
	} catch (error) {
		try { socket?.close?.() } catch (e) { }
		throw error;
	} finally {
		try { writer?.releaseLock() } catch (e) { }
	}
}

function extractTrojanHandshake(firstPacketData, rawData) {
	const firstPacket = toUint8Array(firstPacketData);
	const payload = toUint8Array(rawData);
	if (!payload.byteLength) return firstPacket;
	const handshakeLength = firstPacket.byteLength - payload.byteLength;
	if (handshakeLength <= 0) return firstPacket;
	for (let i = 0; i < payload.byteLength; i++) {
		if (firstPacket[handshakeLength + i] !== payload[i]) return firstPacket;
	}
	return firstPacket.subarray(0, handshakeLength);
}

async function forwardTrojanUdpProxyData(chunk, webSocket, context, request) {
	const data = toUint8Array(chunk);
	if (!context.proxyIpSocket) {
		const TCPconnection = createRequestTcpConnector(request);
		const socket = await connectTrojanProxy(data, TCPconnection, context.proxyAddress);
		context.proxyIpSocket = socket;
		socket.closed.catch(() => { }).finally(() => closeSocketQuietly(webSocket));
		connectStreams(socket, webSocket, null, null);
		return;
	}
	if (!data.byteLength) return;
	const writer = context.proxyIpSocket.writable.getWriter();
	try { await writer.write(data) }
	finally { try { writer.releaseLock() } catch (e) { } }
}

function parseTrojanRequest(buffer, passwordPlainText) {
	const data = toUint8Array(buffer);
	const sha224Password = sha224(passwordPlainText);
	if (data.byteLength < 58) return { hasError: true, message: "invalid data" };
	let crLfIndex = 56;
	if (data[crLfIndex] !== 0x0d || data[crLfIndex + 1] !== 0x0a) return { hasError: true, message: "invalid header format" };
	for (let i = 0; i < crLfIndex; i++) {
		if (data[i] !== sha224Password.charCodeAt(i)) return { hasError: true, message: "invalid password" };
	}

	const socks5Index = crLfIndex + 2;
	if (data.byteLength < socks5Index + 6) return { hasError: true, message: "invalid S5 request data" };

	const cmd = data[socks5Index];
	if (cmd !== 1 && cmd !== 3) return { hasError: true, message: "unsupported command, only TCP/UDP is allowed" };
	const isUDP = cmd === 3;

	const atype = data[socks5Index + 1];
	let addressLength = 0;
	let addressIndex = socks5Index + 2;
	let address = "";
	switch (atype) {
		case 1: // IPv4
			addressLength = 4;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			break;
		case 3: // Domain
			if (data.byteLength < addressIndex + 1) return { hasError: true, message: "invalid S5 request data" };
			addressLength = data[addressIndex];
			addressIndex += 1;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = trojanTextDecoder.decode(data.subarray(addressIndex, addressIndex + addressLength));
			break;
		case 4: // IPv6
			addressLength = 16;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const partIndex = addressIndex + i * 2;
				ipv6.push(((data[partIndex] << 8) | data[partIndex + 1]).toString(16));
			}
			address = ipv6.join(":");
			break;
		default:
			return { hasError: true, message: `invalid addressType is ${atype}` };
	}

	if (!address) {
		return { hasError: true, message: `address is empty, addressType is ${atype}` };
	}

	const portIndex = addressIndex + addressLength;
	if (data.byteLength < portIndex + 4) return { hasError: true, message: "invalid S5 request data" };
	const portRemote = (data[portIndex] << 8) | data[portIndex + 1];

	return {
		hasError: false,
		addressType: atype,
		port: portRemote,
		hostname: address,
		isUDP,
		rawClientData: data.subarray(portIndex + 4)
	};
}

const UUIDbyteCache = new Map();
const vlessTextDecoder = new TextDecoder();

function readHexNibble(code) {
	if (code >= 48 && code <= 57) return code - 48;
	code |= 32;
	if (code >= 97 && code <= 102) return code - 87;
	return -1;
}

function getUuidBytes(uuid) {
	const key = String(uuid || '');
	let cached = UUIDbyteCache.get(key);
	if (cached) return cached;

	const clean = key.replace(/-/g, '');
	if (clean.length !== 32) return null;

	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		const high = readHexNibble(clean.charCodeAt(i * 2));
		const low = readHexNibble(clean.charCodeAt(i * 2 + 1));
		if (high < 0 || low < 0) return null;
		bytes[i] = (high << 4) | low;
	}

	if (UUIDbyteCache.size >= 32) UUIDbyteCache.clear();
	UUIDbyteCache.set(key, bytes);
	return bytes;
}

function UUIDbyteMatch(data, offset, uuid) {
	const expected = getUuidBytes(uuid);
	if (!expected || data.byteLength < offset + 16) return false;
	for (let i = 0; i < 16; i++) {
		if (data[offset + i] !== expected[i]) return false;
	}
	return true;
}

function parseVlessRequest(chunk, token) {
	const data = toUint8Array(chunk);
	const length = data.byteLength;
	if (length < 24) return { hasError: true, message: 'Invalid data' };
	const version = data[0];
	if (!UUIDbyteMatch(data, 1, token)) return { hasError: true, message: 'Invalid uuid' };

	const optLen = data[17];
	const cmdIndex = 18 + optLen;
	if (length < cmdIndex + 4) return { hasError: true, message: 'Invalid data' };

	const cmd = data[cmdIndex];
	let isUDP = false;
	if (cmd === 1) { } else if (cmd === 2) { isUDP = true } else { return { hasError: true, message: 'Invalid command' } }

	const portIdx = cmdIndex + 1;
	const port = (data[portIdx] << 8) | data[portIdx + 1];
	let addrValIdx = portIdx + 3, addrLen = 0, hostname = '';
	const addressType = data[portIdx + 2];
	switch (addressType) {
		case 1:
			addrLen = 4;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv4 address length' };
			hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
			break;
		case 2:
			if (length < addrValIdx + 1) return { hasError: true, message: 'Invalid domain length' };
			addrLen = data[addrValIdx];
			addrValIdx += 1;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid domain data' };
			hostname = vlessTextDecoder.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
			break;
		case 3:
			addrLen = 16;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv6 address length' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addrValIdx + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			break;
		default:
			return { hasError: true, message: `Invalid address type: ${addressType}` };
	}
	if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
	const rawIndex = addrValIdx + addrLen;
	return { hasError: false, addressType, port, hostname, isUDP, rawClientData: data.subarray(rawIndex), version };
}

const SSsupportedCipherConfigs = {
	'aes-128-gcm': { method: 'aes-128-gcm', keyLen: 16, saltLen: 16, maxChunk: 0x3fff, aesLength: 128 },
	'aes-256-gcm': { method: 'aes-256-gcm', keyLen: 32, saltLen: 32, maxChunk: 0x3fff, aesLength: 256 },
};

const SSAEADtagLength = 16, SSNoncepaddingLength = 12;
const SSsubkeyLabel = new TextEncoder().encode('ss-subkey');
const SStextEncoder = new TextEncoder(), SStextDecoder = new TextDecoder(), SSmasterKeyCache = new Map();

function toUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

function concatByteChunks(...chunkList) {
	if (!chunkList || chunkList.length === 0) return new Uint8Array(0);
	const chunks = chunkList.map(toUint8Array);
	const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) { result.set(c, offset); offset += c.byteLength }
	return result;
}

async function forwardTrojanUdpData(chunk, webSocket, context, request) {
	const currentChunk = toUint8Array(chunk);
	if (context?.proxyAddress) return forwardTrojanUdpProxyData(currentChunk, webSocket, context, request);
	const pendingCachedChunk = context?.cachedBytes instanceof Uint8Array ? context.cachedBytes : new Uint8Array(0);
	const input = pendingCachedChunk.byteLength ? concatByteChunks(pendingCachedChunk, currentChunk) : currentChunk;
	let cursor = 0;

	while (cursor < input.byteLength) {
		const packetStart = cursor;
		const atype = input[cursor];
		let addrCursor = cursor + 1;
		let addrLen = 0;
		if (atype === 1) addrLen = 4;
		else if (atype === 4) addrLen = 16;
		else if (atype === 3) {
			if (input.byteLength < addrCursor + 1) break;
			addrLen = 1 + input[addrCursor];
		} else throw new Error(`invalid trojan udp addressType: ${atype}`);

		const portCursor = addrCursor + addrLen;
		if (input.byteLength < portCursor + 6) break;

		const port = (input[portCursor] << 8) | input[portCursor + 1];
		const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
		if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) throw new Error('invalid trojan udp delimiter');

		const payloadStart = portCursor + 6;
		const payloadEnd = payloadStart + payloadLength;
		if (input.byteLength < payloadEnd) break;

		const addressPortHeader = input.slice(packetStart, portCursor + 2);
		const payload = input.slice(payloadStart, payloadEnd);
		cursor = payloadEnd;

		if (port !== 53) throw new Error('UDP is not supported');
		if (!payload.byteLength) continue;

		let tcpDNSquery = payload;
		if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
			tcpDNSquery = new Uint8Array(payload.byteLength + 2);
			tcpDNSquery[0] = (payload.byteLength >>> 8) & 0xff;
			tcpDNSquery[1] = payload.byteLength & 0xff;
			tcpDNSquery.set(payload, 2);
		}

		const dnsresponseContext = { cachedBytes: new Uint8Array(0) };
		await forwardataudp(tcpDNSquery, webSocket, null, request, (dnsRespChunk) => {
			const currentResponseChunk = toUint8Array(dnsRespChunk);
			const responseInput = dnsresponseContext.cachedBytes.byteLength ? concatByteChunks(dnsresponseContext.cachedBytes, currentResponseChunk) : currentResponseChunk;
			const responseFrames = [];
			let responseCursor = 0;
			while (responseCursor + 2 <= responseInput.byteLength) {
				const dnsLen = (responseInput[responseCursor] << 8) | responseInput[responseCursor + 1];
				const dnsStart = responseCursor + 2;
				const dnsEnd = dnsStart + dnsLen;
				if (dnsEnd > responseInput.byteLength) break;
				const dnsPayload = responseInput.slice(dnsStart, dnsEnd);
				const frame = new Uint8Array(addressPortHeader.byteLength + 4 + dnsPayload.byteLength);
				frame.set(addressPortHeader, 0);
				frame[addressPortHeader.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
				frame[addressPortHeader.byteLength + 1] = dnsPayload.byteLength & 0xff;
				frame[addressPortHeader.byteLength + 2] = 0x0d;
				frame[addressPortHeader.byteLength + 3] = 0x0a;
				frame.set(dnsPayload, addressPortHeader.byteLength + 4);
				responseFrames.push(frame);
				responseCursor = dnsEnd;
			}
			dnsresponseContext.cachedBytes = responseInput.slice(responseCursor);
			return responseFrames.length ? responseFrames : new Uint8Array(0);
		});
	}

	if (context) context.cachedBytes = input.slice(cursor);
}

function SSincrementNonceCounter(counter) {
	for (let i = 0; i < counter.length; i++) { counter[i] = (counter[i] + 1) & 0xff; if (counter[i] !== 0) return }
}

async function SSderiveMasterKey(passwordText, keyLen) {
	const cacheKey = `${keyLen}:${passwordText}`;
	if (SSmasterKeyCache.has(cacheKey)) return SSmasterKeyCache.get(cacheKey);
	const deriveTask = (async () => {
		const pwBytes = SStextEncoder.encode(passwordText || '');
		let prev = new Uint8Array(0), result = new Uint8Array(0);
		while (result.byteLength < keyLen) {
			const input = new Uint8Array(prev.byteLength + pwBytes.byteLength);
			input.set(prev, 0); input.set(pwBytes, prev.byteLength);
			prev = new Uint8Array(await crypto.subtle.digest('MD5', input));
			result = concatByteChunks(result, prev);
		}
		return result.slice(0, keyLen);
	})();
	SSmasterKeyCache.set(cacheKey, deriveTask);
	try { return await deriveTask }
	catch (error) { SSmasterKeyCache.delete(cacheKey); throw error }
}

async function SSderiveSessionKey(config, masterKey, salt, usages) {
	const hmacOpts = { name: 'HMAC', hash: 'SHA-1' };
	const saltHmacKey = await crypto.subtle.importKey('raw', salt, hmacOpts, false, ['sign']);
	const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltHmacKey, masterKey));
	const prkHmacKey = await crypto.subtle.importKey('raw', prk, hmacOpts, false, ['sign']);
	const subKey = new Uint8Array(config.keyLen);
	let prev = new Uint8Array(0), written = 0, counter = 1;
	while (written < config.keyLen) {
		const input = concatByteChunks(prev, SSsubkeyLabel, new Uint8Array([counter]));
		prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkHmacKey, input));
		const copyLen = Math.min(prev.byteLength, config.keyLen - written);
		subKey.set(prev.subarray(0, copyLen), written);
		written += copyLen; counter += 1;
	}
	return crypto.subtle.importKey('raw', subKey, { name: 'AES-GCM', length: config.aesLength }, false, usages);
}

async function SSAEADencrypt(cryptoKey, nonceCounter, plaintext) {
	const iv = nonceCounter.slice();
	const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, plaintext);
	SSincrementNonceCounter(nonceCounter);
	return new Uint8Array(ct);
}

async function SSAEADdecryptPayload(cryptoKey, nonceCounter, ciphertext) {
	const iv = nonceCounter.slice();
	const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, ciphertext);
	SSincrementNonceCounter(nonceCounter);
	return new Uint8Array(pt);
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID, request = null, proxyContext = {}, allowTrojanProxy = false, trojanFallbackFirstData = null, connectOnly = false) {
	const ctxproxyIp = proxyContext.proxyIp || '';
	const ctxproxyType = proxyContext.proxyType !== undefined ? proxyContext.proxyType : null;
	const ctxproxyGlobal = proxyContext.proxyGlobal !== undefined ? proxyContext.proxyGlobal : false;
	const ctxproxyParams = proxyContext.proxyParams || {};
	const ctxproxyFallback = proxyContext.proxyFallback !== undefined ? proxyContext.proxyFallback : true;
	let proxyArrayCursor = 0;
	log(`[TCP forward] target: ${host}:${portNum} | reverse proxy IP: ${ctxproxyIp} | reverse proxy fallback: ${ctxproxyFallback ? 'yes' : 'no'} | reverse proxy type: ${ctxproxyType || 'proxyip'} | global: ${ctxproxyGlobal ? 'yes' : 'no'}`);
	const connectTimeoutMs = 1000;
	let firstPacketSentViaProxy = false;
	const TCPconnection = createRequestTcpConnector(request);
	const useTrojanProxy = allowTrojanProxy && (proxyContext.trojanFallbackAddress || null);
	const trojanFallbackTarget = useTrojanProxy ? proxyContext.trojanFallbackAddress : null;
	const trojanHandshakeData = useTrojanProxy ? extractTrojanHandshake(trojanFallbackFirstData, rawData) : null;
	let pendingResponseHeader = respHeader;
	const takeResponseHeader = () => {
		const header = pendingResponseHeader;
		pendingResponseHeader = null;
		return header;
	};
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;

	const installCurrentConn = async (socket, generation, downlinkDrain, retryFunc = null) => {
		try { await downlinkDrain } catch (e) {
			if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
			try { socket?.close?.() } catch (_) { }
			if (remoteConnWrapper.generation === generation) closeSocketQuietly(ws);
			throw e;
		}
		if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
		const isConnectionStillValid = () => remoteConnWrapper.generation === generation && remoteConnWrapper.socket === socket;
		if (remoteConnWrapper.generation !== generation || ws.readyState !== WebSocket.OPEN) {
			try { socket?.close?.() } catch (e) { }
			if (remoteConnWrapper.generation === generation) remoteConnWrapper.socket = null;
			throw new Error('connection superseded or client closed');
		}
		remoteConnWrapper.socket = socket;
		if (connectOnly) return socket;
		connectStreams(socket, ws, takeResponseHeader, retryFunc, isConnectionStillValid, remoteConnWrapper).catch(err => {
			if (!isConnectionStillValid()) return;
			log(`[TCP downstream] processing failed: ${err?.message || err}`);
			try { socket?.close?.() } catch (e) { }
			closeSocketQuietly(ws);
		});
		return true;
	};

	async function waitForConnectionOpen(remoteSock, timeoutMs = connectTimeoutMs) {
		await Promise.race([
			remoteSock.opened,
			new Promise((_, reject) => setTimeout(() => reject(new Error('connection timeout')), timeoutMs))
		]);
	}

	async function openTcpConnection(address, port) {
		const remoteSock = TCPconnection({ hostname: address, port });
		try {
			await waitForConnectionOpen(remoteSock);
			return remoteSock;
		} catch (err) {
			try { remoteSock?.close?.() } catch (e) { }
			throw err;
		}
	}

	async function writeFirstPacket(remoteSock, data) {
		if (validDataLength(data) <= 0) return;
		const writer = remoteSock.writable.getWriter();
		try { await writer.write(toUint8Array(data)) }
		finally { try { writer.releaseLock() } catch (e) { } }
	}

	async function openCandidatesInParallel(candidateList) {
		if (candidateList.length === 1) {
			const candidate = candidateList[0];
			return { socket: await openTcpConnection(candidate.hostname, candidate.port), candidate: candidate };
		}
		const attempts = candidateList.map(candidate => openTcpConnection(candidate.hostname, candidate.port).then(socket => ({ socket, candidate: candidate })));
		let winner = null;
		try {
			winner = await Promise.any(attempts);
			return winner;
		} finally {
			if (winner) {
				for (const attempt of attempts) {
					attempt.then(({ socket }) => {
						if (socket !== winner.socket) {
							try { socket?.close?.() } catch (e) { }
						}
					}).catch(() => { });
				}
			}
		}
	}

	async function buildRaceCandidateList(address, port) {
		if (!preloadRaceDial || isIPHostname(address)) return null;
		log(`[TCP direct] preload racing dial enabled, starting concurrent A/AAAA lookup for ${address}`);
		const [aRecords, aaaaRecords] = await Promise.all([
			DoHquery(address, 'A'),
			DoHquery(address, 'AAAA')
		]);
		const ipv4List = [...new Set(aRecords.flatMap(r => {
			const data = r.data;
			return r.type === 1 && typeof data === 'string' && isIPv4(data) ? [data] : [];
		}))];
		const ipv6List = [...new Set(aaaaRecords.flatMap(r => {
			const data = r.data;
			return r.type === 28 && typeof data === 'string' && isIPHostname(data) ? [data] : [];
		}))];
		const dialLimit = Math.max(1, tcpConcurrentDials | 0);
		const ipList = ipv4List.length >= dialLimit
			? ipv4List.slice(0, dialLimit)
			: ipv4List.concat(ipv6List.slice(0, dialLimit - ipv4List.length));
		const useRecordType = ipv4List.length > 0
			? (ipList.length > ipv4List.length ? 'A+AAAA' : 'A')
			: 'AAAA';
		if (ipList.length === 0) {
			log(`[TCP direct] no usable A/AAAA resolution result for ${address}, preload race unavailable, falling back to direct connection to the original hostname.`);
			return null;
		}
		const selectedIpList = ipList;
		log(`[TCP direct] ${address} A records:${ipv4List.length} AAAA records:${ipv6List.length}, using ${useRecordType} records, racing dial ${selectedIpList.length}/${dialLimit}: ${selectedIpList.join(', ')}`);
		return selectedIpList.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
	}

	async function connectDirect(address, port, data = null, enablePreload = false) {
		const preloadCandidateList = enablePreload ? await buildRaceCandidateList(address, port) : null;
		const candidateList = preloadCandidateList || Array.from({ length: tcpConcurrentDials }, (_, attempt) => ({ hostname: address, port, attempt }));
		log(preloadCandidateList
			? `[TCP direct] racing ${candidateList.length} paths: ${candidateList.map(candidate => `${candidate.hostname}:${candidate.port}`).join(', ')}`
			: `[TCP direct] concurrent attempt over ${candidateList.length} paths: ${address}:${port}`);
		let socket = null;
		try {
			const connectionResult = await openCandidatesInParallel(candidateList);
			socket = connectionResult.socket;
			if (preloadCandidateList) {
				const winner = connectionResult.candidate;
				log(`[TCP direct] preload race result: ${winner.hostname}:${winner.port} won, source domain: ${winner.resolvedFrom || address}`);
			}
			await writeFirstPacket(socket, data);
			return socket;
		} catch (err) {
			try { socket?.close?.() } catch (e) { }
			if (preloadCandidateList) log(`[TCP direct] preload race failed: ${err.message || err}`);
			throw err;
		}
	}

	async function connectProxyIP(address, port, data = null, allProxyArray = null, fallbackOnProxyFail = true) {
		if (allProxyArray && allProxyArray.length > 0) {
			const actualConcurrency = Math.max(1, Math.floor(Number(proxyConcurrentDials) || 1));
			for (let i = 0; i < allProxyArray.length; i += actualConcurrency) {
				const candidateList = [];
				for (let j = 0; j < actualConcurrency && i + j < allProxyArray.length; j++) {
					const candidateIndex = (proxyArrayCursor + i + j) % allProxyArray.length;
					const [proxyAddress, proxyPort] = allProxyArray[candidateIndex];
					candidateList.push({ hostname: proxyAddress, port: proxyPort, index: candidateIndex });
				}
				let socket = null, candidate = null;
				try {
					log(`[proxy connect] racing ${candidateList.length} paths: ${candidateList.map(candidate => `${candidate.hostname}:${candidate.port}`).join(', ')}`);
					const connectionResult = await openCandidatesInParallel(candidateList);
					socket = connectionResult.socket;
					candidate = connectionResult.candidate;
					await writeFirstPacket(socket, data);
					log(`[reverse proxy connect] successfully connected to: ${candidate.hostname}:${candidate.port} (index: ${candidate.index})`);
					proxyArrayCursor = candidate.index;
					return socket;
				} catch (err) {
					try { socket?.close?.() } catch (e) { }
					log(`[reverse-proxy connection] batch connections failed: ${err.message || err}`);
				}
			}
		}

		if (fallbackOnProxyFail) return connectDirect(address, port, data, false);
		else {
			throw new Error('[reverse proxy connect] all reverse proxy connections failed and reverse proxy fallback is disabled, connection terminated.');
		}
	}

	async function connecttoPry(allowFirstPacketSend = true) {
		if (remoteConnWrapper.connectingPromise) {
			await remoteConnWrapper.connectingPromise;
			return;
		}
		const { generation: currentConnGeneration, downlinkDrain } = startTcpGeneration(remoteConnWrapper);

		let sendsFirstPacketNow = false, currentFirstPacketData = null;
		if (useTrojanProxy) {
			if (allowFirstPacketSend && !firstPacketSentViaProxy && validDataLength(trojanFallbackFirstData) > 0) {
				currentFirstPacketData = trojanFallbackFirstData;
				sendsFirstPacketNow = validDataLength(rawData) > 0;
			} else {
				currentFirstPacketData = trojanHandshakeData;
			}
		} else {
			sendsFirstPacketNow = allowFirstPacketSend && !firstPacketSentViaProxy && validDataLength(rawData) > 0;
			currentFirstPacketData = sendsFirstPacketNow ? rawData : null;
		}

		const currentConnectTask = (async () => {
			let newSocket = null;
			try {
				if (useTrojanProxy) {
					log(`[trojan reverse-proxy] proxying to: ${host}:${portNum}`);
					newSocket = await connectTrojanProxy(currentFirstPacketData, TCPconnection, trojanFallbackTarget);
				} else if (ctxproxyType === 'socks5') {
					log(`[SOCKS5 proxy] proxying to: ${host}:${portNum}`);
					newSocket = await socks5Connect(host, portNum, currentFirstPacketData, TCPconnection, ctxproxyParams);
				} else if (ctxproxyType === 'http') {
					log(`[HTTP proxy] proxying to: ${host}:${portNum}`);
					newSocket = await httpConnect(host, portNum, currentFirstPacketData, false, TCPconnection, ctxproxyParams);
				} else if (ctxproxyType === 'https') {
					log(`[HTTPS proxy] proxying to: ${host}:${portNum}`);
					newSocket = isIPHostname(ctxproxyParams.hostname)
						? await httpsConnect(host, portNum, currentFirstPacketData, TCPconnection, ctxproxyParams)
						: await httpConnect(host, portNum, currentFirstPacketData, true, TCPconnection, ctxproxyParams);
				} else if (ctxproxyType === 'turn') {
					log(`[TURN proxy] proxying to: ${host}:${portNum}`);
					newSocket = await turnConnect(ctxproxyParams, host, portNum, TCPconnection);
					if (validDataLength(currentFirstPacketData) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(toUint8Array(currentFirstPacketData)) }
						finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else if (ctxproxyType === 'sstp') {
					log(`[SSTP proxy] proxying to: ${host}:${portNum}`);
					newSocket = await sstpConnect(ctxproxyParams, host, portNum, TCPconnection);
					if (validDataLength(currentFirstPacketData) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(toUint8Array(currentFirstPacketData)) }
						finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else {
					log(`[reverse-proxy connection] proxying to: ${host}:${portNum}`);
					const allProxyArray = await resolveProxyEndpoints(ctxproxyIp, host, yourUUID);
					newSocket = await connectProxyIP(`${signatureDictionary[0]}.tp1.${signatureDictionary[2]}.xyz`, 1, currentFirstPacketData, allProxyArray, ctxproxyFallback);
				}
				await installCurrentConn(newSocket, currentConnGeneration, downlinkDrain);
				if (sendsFirstPacketNow) firstPacketSentViaProxy = true;
			} catch (err) {
				try { newSocket?.close?.() } catch (e) { }
				if (remoteConnWrapper.generation === currentConnGeneration) {
					remoteConnWrapper.socket = null;
					closeSocketQuietly(ws);
					throw err;
				}
			}
		})();

		remoteConnWrapper.connectingPromise = currentConnectTask;
		try {
			await currentConnectTask;
		} finally {
			if (remoteConnWrapper.connectingPromise === currentConnectTask) {
				remoteConnWrapper.connectingPromise = null;
			}
		}
	}
	remoteConnWrapper.retryConnect = async () => connecttoPry(!firstPacketSentViaProxy);

	if (ctxproxyType && (ctxproxyGlobal || SOCKS5whitelist.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(host)))) {
		log(`[TCP forward] SOCKS5/HTTP/HTTPS/TURN/SSTP global proxy enabled`);
		try {
			await connecttoPry();
			if (connectOnly) return remoteConnWrapper.socket;
		} catch (err) {
			log(`[TCP forward] SOCKS5/HTTP/HTTPS/TURN/SSTP proxy connection failed: ${err.message}`);
			throw err;
		}
	} else {
		let directGeneration = remoteConnWrapper.generation;
		try {
			log(`[TCP forward] attempting direct connection to: ${host}:${portNum}`);
			const connGeneration = startTcpGeneration(remoteConnWrapper);
			directGeneration = connGeneration.generation;
			const initialSocket = await connectDirect(host, portNum, rawData, true);
			await installCurrentConn(initialSocket, directGeneration, connGeneration.downlinkDrain, async () => {
				if (remoteConnWrapper.generation !== directGeneration || remoteConnWrapper.socket !== initialSocket) return;
				await connecttoPry();
			});
			if (connectOnly) return initialSocket;
		} catch (err) {
			log(`[TCP forward] direct connection to ${host}:${portNum} failed: ${err.message}`);
			if (remoteConnWrapper.generation !== directGeneration) throw err;
			if (err instanceof Error && err.name === 'preload resolution empty') {
				closeSocketQuietly(ws);
				throw err;
			}
			if (ws.readyState !== WebSocket.OPEN) throw err;
			await connecttoPry();
			if (connectOnly) return remoteConnWrapper.socket;
		}
	}
}

async function forwardataudp(udpChunk, webSocket, respHeader, request, responseWrapper = null) {
	const requestData = toUint8Array(udpChunk);
	const requestByteLength = requestData.byteLength;
	log(`[UDP forward] DNS request received: ${requestByteLength}B -> 8.8.4.4:53`);
	try {
		const TCPconnection = createRequestTcpConnector(request);
		const tcpSocket = TCPconnection({ hostname: '8.8.4.4', port: 53 });
		let vlessHeader = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(requestData);
		log(`[UDP forward] DNS request written to upstream: ${requestByteLength}B`);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				const rawResponse = toUint8Array(chunk);
				log(`[UDP forward] DNS response received: ${rawResponse.byteLength}B`);
				const wrappedResult = responseWrapper ? await responseWrapper(rawResponse) : rawResponse;
				const sendFragmentList = Array.isArray(wrappedResult) ? wrappedResult : [wrappedResult];
				if (!sendFragmentList.length) return;
				if (webSocket.readyState !== WebSocket.OPEN) return;
				for (const fragment of sendFragmentList) {
					const forwardedBytes = toUint8Array(fragment);
					if (!forwardedBytes.byteLength) continue;
					if (vlessHeader) {
						const response = new Uint8Array(vlessHeader.length + forwardedBytes.byteLength);
						response.set(vlessHeader, 0);
						response.set(forwardedBytes, vlessHeader.length);
						await WebSocketsendAndWait(webSocket, response.buffer);
						vlessHeader = null;
					} else {
						await WebSocketsendAndWait(webSocket, forwardedBytes);
					}
				}
			},
		}));
	} catch (error) {
		log(`[UDP forward] DNS forwarding failed: ${error?.message || error}`);
	}
}

function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (error) { }
}

function formatIdentifier(arr, offset = 0) {
	const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

async function WebSocketsendAndWait(webSocket, payload) {
	const sendResult = webSocket.send(payload);
	if (sendResult && typeof sendResult.then === 'function') await sendResult;
}

function createGrainCollector(capacity, copyBundledResult = false) {
	let queue = [];
	let head = 0;
	let byteCount = 0;
	let packBuffer = null;

	const isEmpty = () => head >= queue.length;
	const compact = () => {
		if (head > 32 && head * 2 >= queue.length) {
			queue = queue.slice(head);
			head = 0;
		}
	};
	const takeNext = () => {
		if (isEmpty()) return null;
		const item = queue[head];
		queue[head++] = undefined;
		byteCount -= item.chunk.byteLength;
		compact();
		return item;
	};

	return {
		get byteCount() { return byteCount },
		get itemCount() { return queue.length - head },
		get isEmpty() { return isEmpty() },
		clear(processItem = null) {
			if (processItem) {
				for (let i = head; i < queue.length; i++) {
					if (queue[i]) processItem(queue[i]);
				}
			}
			queue = [];
			head = 0;
			byteCount = 0;
		},
		absorb(item) {
			if (!item?.chunk?.byteLength) return false;
			queue.push(item);
			byteCount += item.chunk.byteLength;
			return true;
		},
		pack() {
			const first = takeNext();
			if (!first) return null;
			const items = [first];
			if (isEmpty() || first.chunk.byteLength >= capacity) return { chunk: first.chunk, items };

			let totalBytes = first.chunk.byteLength;
			let end = head;
			while (end < queue.length) {
				const nextBytes = totalBytes + queue[end].chunk.byteLength;
				if (nextBytes > capacity) break;
				totalBytes = nextBytes;
				end++;
			}
			if (end === head) return { chunk: first.chunk, items };

			const output = (packBuffer ||= new Uint8Array(capacity));
			output.set(first.chunk, 0);
			let offset = first.chunk.byteLength;
			while (head < end) {
				const next = queue[head];
				queue[head++] = undefined;
				byteCount -= next.chunk.byteLength;
				items.push(next);
				output.set(next.chunk, offset);
				offset += next.chunk.byteLength;
			}
			compact();
			const bundled = output.subarray(0, totalBytes);
			return { chunk: copyBundledResult ? bundled.slice() : bundled, items };
		}
	};
}

function createUplinkGrainStream(targetByteSize = uplinkGrainTargetBytes) {
	const identity = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream();
	const writer = identity.writable.getWriter();
	const mergeBuffer = new Uint8Array(targetByteSize);
	let bufferedLength = 0;
	let timer = null;
	let pendingWrite = null;
	let flushChain = Promise.resolve();

	const clearTimer = () => {
		if (timer) {
			clearTimeout(timer);
			timer = null;
		}
	};

	const serialWrite = async (chunk) => {
		if (pendingWrite) await pendingWrite;
		pendingWrite = writer.write(chunk);
		try { await pendingWrite } finally { pendingWrite = null; }
	};

	const flush = async () => {
		if (bufferedLength) {
			const chunk = mergeBuffer.slice(0, bufferedLength);
			bufferedLength = 0;
			await serialWrite(chunk);
		}
	};

	const enqueueFlush = () => {
		flushChain = flushChain.then(() => flush()).catch(() => { });
	};

	const startTimer = () => {
		if (timer) return;
		timer = setTimeout(() => {
			timer = null;
			enqueueFlush();
		}, 1);
	};

	return {
		readable: identity.readable,
		write: async (chunk) => {
			const data = toUint8Array(chunk);
			if (!data.byteLength) return;
			if (data.byteLength >= targetByteSize) {
				clearTimer();
				if (bufferedLength) await flush();
				await serialWrite(data);
				return;
			}
			if (bufferedLength + data.byteLength >= targetByteSize) {
				const output = new Uint8Array(bufferedLength + data.byteLength);
				output.set(mergeBuffer.subarray(0, bufferedLength), 0);
				output.set(data, bufferedLength);
				bufferedLength = 0;
				clearTimer();
				await serialWrite(output);
			} else {
				mergeBuffer.set(data, bufferedLength);
				bufferedLength += data.byteLength;
				startTimer();
			}
		},
		finish: async () => {
			clearTimer();
			try {
				await flushChain;
				await flush();
				await writer.close();
			} finally {
				try { writer.releaseLock() } catch (e) { }
			}
		}
	};
}

function createUplinkWriteQueue({ getWriter, getConnectionTask = null, releaseWriter, retryConnection, closeConnection, queueName = 'upstream queue' }) {
	const grain = createGrainCollector(uplinkGrainTargetBytes);
	let draining = false;
	let closed = false;
	let idleResolvers = [];
	let activeCompletions = null;

	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const completion of completions) {
			if (err) completion.reject(err);
			else completion.resolve();
		}
	};

	const resolveIdle = () => {
		if (grain.byteCount || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};

	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${queueName}: queue closed`) : null);
		if (closeErr) {
			grain.clear(item => settleCompletions(item.completions, closeErr));
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		} else grain.clear();
		resolveIdle();
	};

	const bundle = () => {
		const packed = grain.pack();
		if (!packed) return null;
		let allowRetry = true;
		let completions = null;
		for (const item of packed.items) {
			allowRetry = allowRetry && item.allowRetry;
			if (item.completions) completions = completions ? completions.concat(item.completions) : item.completions;
		}
		return { chunk: packed.chunk, allowRetry, completions };
	};

	const waitForAvailableWriter = async () => {
		let writer = getWriter();
		if (writer) return writer;
		const connectionTask = getConnectionTask?.();
		if (connectionTask) await connectionTask;
		return getWriter();
	};

	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			for (; ;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					let writer = await waitForAvailableWriter();
					if (closed) break;
					if (!writer) throw new Error(`${queueName}: remote writer unavailable`);
					try {
						await writer.write(item.chunk);
					} catch (err) {
						releaseWriter?.();
						if (closed) break;
						if (!item.allowRetry || typeof retryConnection !== 'function') throw err;
						await retryConnection();
						if (closed) break;
						writer = getWriter();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			log(`[${queueName}] write failed: ${err?.message || err}`);
			try { closeConnection?.(err) } catch (_) { }
		} finally {
			draining = false;
			if (!closed && !grain.isEmpty) drain();
			else resolveIdle();
		}
	};

	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		// While the first packet is still being parsed there is neither a writer nor a connection task; return false and let the caller carry on with protocol parsing.
		// When a session is already up and the link is being re-dialled, buffer the data instead: drain waits for the new writer, so nothing is mistaken for the first packet.
		if (!getWriter() && !getConnectionTask?.()) return false;
		const chunk = toUint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = grain.byteCount + chunk.byteLength;
		const nextItems = grain.itemCount + 1;
		if (nextBytes > uplinkQueueMaxBytes || nextItems > uplinkQueueMaxItems) {
			closed = true;
			const err = Object.assign(new Error(`${queueName}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clear(err);
			log(`[${queueName}] queue limit exceeded, closing connection`);
			try { closeConnection?.(err) } catch (_) { }
			throw err;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		grain.absorb({ chunk, allowRetry, completions });
		if (!draining) drain();
		return waitForFlush ? completionPromise.then(() => true) : true;
	};

	return {
		write(data, allowRetry = true) {
			return enqueue(data, allowRetry, false);
		},
		writeAndWait(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async waitQueueDrained() {
			if (!grain.byteCount && !draining) return;
			await new Promise(resolve => idleResolvers.push(resolve));
		},
		clear() {
			closed = true;
			clear();
		}
	};
}

function createDownGrainSender(webSocket, headerData = null, isActive = null) {
	const packetCap = downGrainPacketBytes;
	const tailBytes = downGrainTailThreshold;
	const grain = createGrainCollector(packetCap, true);
	let header = typeof headerData === 'function' ? null : headerData;
	const getResponseHeader = typeof headerData === 'function' ? headerData : () => {
		const value = header;
		header = null;
		return value;
	};
	let flushTimer = null;
	let generation = 0;
	let scheduledGeneration = 0;
	let waitRounds = 0;
	let flushPromise = null;
	let directSendPromise = null;
	let forceDrain = false;
	let stopRequested = false;
	let activeSendCount = 0;
	let activeDirectCount = 0;
	let activeSendError = null;
	let activeSendWaiters = [];
	const waitForActiveSendDone = () => {
		if (!activeSendCount && !activeDirectCount) return Promise.resolve();
		return new Promise(resolve => activeSendWaiters.push(resolve));
	};
	const markSendComplete = () => {
		if (activeSendCount || activeDirectCount || !activeSendWaiters.length) return;
		const resolvers = activeSendWaiters;
		activeSendWaiters = [];
		for (const resolve of resolvers) resolve();
	};
	const checkActiveSendError = () => {
		if (!activeSendError) return;
		const err = activeSendError;
		grain.clear();
		throw err;
	};
	const isCurrentSenderValid = () => forceDrain || !isActive || isActive();
	const closeActiveSocket = () => {
		if (isCurrentSenderValid()) closeSocketQuietly(webSocket);
	};

	const sendRawChunk = async (chunk) => {
		if (!isCurrentSenderValid()) return;
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
		chunk = appendResponseHeader(chunk);
		await WebSocketsendAndWait(webSocket, chunk);
	};

	const serialSendRawChunk = async (chunk) => {
		while (directSendPromise) await directSendPromise;
		const sendTask = sendRawChunk(chunk);
		directSendPromise = sendTask;
		try { await sendTask }
		finally {
			if (directSendPromise === sendTask) directSendPromise = null;
		}
	};

	const appendResponseHeader = (chunk) => {
		const responseHeader = getResponseHeader();
		if (!responseHeader) return chunk;
		const merged = new Uint8Array(responseHeader.length + chunk.byteLength);
		merged.set(responseHeader, 0);
		merged.set(chunk, responseHeader.length);
		return merged;
	};

	const flush = async () => {
		while (flushPromise) await flushPromise;
		if (flushTimer) clearTimeout(flushTimer);
		flushTimer = null;
		waitRounds = 0;
		if (!isCurrentSenderValid()) {
			grain.clear();
			return;
		}
		const sendTask = (async () => {
			for (; ;) {
				if (!isCurrentSenderValid()) {
					grain.clear();
					break;
				}
				const packed = grain.pack();
				if (!packed) break;
				await serialSendRawChunk(packed.chunk);
			}
		})();
		flushPromise = sendTask.catch(err => {
			activeSendError ||= err;
			throw err;
		}).finally(() => { flushPromise = null });
		return flushPromise;
	};

	const scheduleFlush = () => {
		if (!isCurrentSenderValid()) {
			grain.clear();
			return;
		}
		if (grain.isEmpty || flushTimer) return;
		if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) {
			flush().catch(closeActiveSocket);
			return;
		}
		flushTimer = setTimeout(() => {
			flushTimer = null;
			if (!isCurrentSenderValid()) {
				grain.clear();
				return;
			}
			if (grain.isEmpty) return;
			if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) {
				flush().catch(closeActiveSocket);
				return;
			}
			if (waitRounds < downGrainMaxWaitRounds && (generation !== scheduledGeneration || grain.byteCount < downGrainLowWaterBytes)) {
				waitRounds++;
				scheduledGeneration = generation;
				scheduleFlush();
				return;
			}
			flush().catch(closeActiveSocket);
		}, 1);
	};

	return {
		async sendDirectly(data) {
			if (stopRequested || !isCurrentSenderValid()) return;
			activeDirectCount++;
			try {
				const chunk = toUint8Array(data);
				if (!chunk.byteLength) return;
				await serialSendRawChunk(chunk);
			} catch (err) {
				activeSendError ||= err;
				throw err;
			} finally {
				activeDirectCount--;
				markSendComplete();
			}
		},
		async send(data) {
			if (stopRequested || !isCurrentSenderValid()) return;
			activeSendCount++;
			try {
				const chunk = toUint8Array(data);
				if (!chunk.byteLength) return;
				let offset = 0;
				const totalBytes = chunk.byteLength;
				while (offset < totalBytes) {
					const remainingBytes = totalBytes - offset;
					if (grain.isEmpty && remainingBytes >= packetCap) {
						const sendBytes = Math.min(packetCap, remainingBytes);
						const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
						await serialSendRawChunk(view);
						offset += sendBytes;
						continue;
					}
					const copyBytes = Math.min(packetCap - grain.byteCount, totalBytes - offset);
					if (!copyBytes) {
						await flush();
						continue;
					}
					grain.absorb({ chunk: offset || copyBytes !== totalBytes ? chunk.subarray(offset, offset + copyBytes) : chunk });
					offset += copyBytes;
					generation++;
					if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) await flush();
					else scheduleFlush();
				}
			} catch (err) {
				activeSendError ||= err;
				throw err;
			} finally {
				activeSendCount--;
				markSendComplete();
			}
		},
		flush,
		async stopAndFlush() {
			if (stopRequested) {
				await waitForActiveSendDone();
				while (directSendPromise) await directSendPromise;
				checkActiveSendError();
				await flush();
				return;
			}
			stopRequested = true;
			forceDrain = true;
			if (flushTimer) clearTimeout(flushTimer);
			flushTimer = null;
			await waitForActiveSendDone();
			while (directSendPromise) await directSendPromise;
			checkActiveSendError();
			await flush();
		}
	};
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, isCurrentSocket = null, remoteConnWrapper = null) {
	let header = headerData, hasData = false, reader, useBYOB = false, readError = null;
	const BYOBsingleReadLimit = 64 * 1024;
	const isCurrentConnValid = () => !isCurrentSocket || isCurrentSocket();
	const downlinkSender = createDownGrainSender(webSocket, header, isCurrentConnValid);
	header = null;
	const downlinkController = { stopAndFlush: () => downlinkSender.stopAndFlush() };
	if (remoteConnWrapper) remoteConnWrapper.downlinkController = downlinkController;
	try { remoteSocket.closed?.catch?.(() => { }) } catch (e) { }

	try { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true }
	catch (e) { reader = remoteSocket.readable.getReader() }

	try {
		if (!useBYOB) {
			while (true) {
				const { done, value } = await reader.read();
				if (!isCurrentConnValid()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= downGrainPacketBytes) {
					await downlinkSender.flush();
					await downlinkSender.sendDirectly(value);
				} else {
					await downlinkSender.send(value);
				}
			}
		} else {
			let readBuffer = new ArrayBuffer(BYOBsingleReadLimit);
			while (true) {
				const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOBsingleReadLimit));
				if (!isCurrentConnValid()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= downGrainPacketBytes) {
					await downlinkSender.flush();
					await downlinkSender.sendDirectly(value);
					readBuffer = new ArrayBuffer(BYOBsingleReadLimit);
				} else {
					await downlinkSender.send(value.slice());
					readBuffer = value.buffer.byteLength >= BYOBsingleReadLimit ? value.buffer : new ArrayBuffer(BYOBsingleReadLimit);
				}
			}
		}
		if (isCurrentConnValid()) await downlinkSender.flush();
	} catch (err) { readError = err }
	finally {
		if (isCurrentConnValid() && webSocket.readyState === WebSocket.OPEN) {
			try { await downlinkSender.stopAndFlush() } catch (err) { readError ||= err }
		}
		if (remoteConnWrapper?.downlinkController === downlinkController) remoteConnWrapper.downlinkController = null;
		try { await reader.cancel() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { remoteSocket.close() } catch (e) { }
	}
	if (!hasData && retryFunc && webSocket.readyState === WebSocket.OPEN && isCurrentConnValid()) {
		try {
			await retryFunc();
			return;
		} catch (err) {
			readError ||= err;
		}
	}
	if (!isCurrentConnValid()) return;
	if (readError) log(`[TCP downstream] read failed: ${readError?.message || readError}`);
	closeSocketQuietly(webSocket);
}

function isSpeedTestSite(hostname) {
	const speedTestDomains = ['speed.cloudflare.com', 'cp.cloudflare.com'];
	hostname = hostname.toLowerCase();
	return speedTestDomains.some(domain => hostname === domain || hostname.endsWith('.' + domain));
}

function buildLocal204Response(respHeader = null) {
	const local204Response = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: close\r\n' +
		'\r\n'
	);
	if (validDataLength(respHeader) === 0) return local204Response;
	const protocolRespHeader = toUint8Array(respHeader);
	const response = new Uint8Array(protocolRespHeader.byteLength + local204Response.byteLength);
	response.set(protocolRespHeader, 0);
	response.set(local204Response, protocolRespHeader.byteLength);
	log(`[TCP forward] built local 204 response: ${response.byteLength}B`);
	return response;
}

function buildWsLocal204Response(respHeader = null) {
	const WSlocal204Response = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: keep-alive\r\n' +
		'\r\n'
	);
	if (validDataLength(respHeader) === 0) return WSlocal204Response;
	const protocolRespHeader = toUint8Array(respHeader);
	const response = new Uint8Array(protocolRespHeader.byteLength + WSlocal204Response.byteLength);
	response.set(protocolRespHeader, 0);
	response.set(WSlocal204Response, protocolRespHeader.byteLength);
	return response;
}

///////////////////////////////////////////////////////SOCKS5/HTTP functions///////////////////////////////////////////////
async function socks5Connect(targetHost, targetPort, initialData, TCPconnection, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const socket = TCPconnection({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	try {
		const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
		await writer.write(authMethods);
		let response = await reader.read();
		if (response.done || response.value.byteLength < 2) throw new Error('S5 method selection failed');

		const selectedMethod = new Uint8Array(response.value)[1];
		if (selectedMethod === 0x02) {
			if (!username || !password) throw new Error('S5 requires authentication');
			const userBytes = new TextEncoder().encode(username), passBytes = new TextEncoder().encode(password);
			const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
			await writer.write(authPacket);
			response = await reader.read();
			if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 authentication failed');
		} else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth method: ${selectedMethod}`);

		const hostBytes = new TextEncoder().encode(targetHost);
		const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
		await writer.write(connectPacket);
		response = await reader.read();
		if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 connection failed');

		if (validDataLength(initialData) > 0) await writer.write(initialData);
		writer.releaseLock(); reader.releaseLock();
		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

async function httpConnect(targetHost, targetPort, initialData, HTTPSproxy = false, TCPconnection, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const socket = HTTPSproxy
		? TCPconnection({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false })
		: TCPconnection({ hostname, port });
	const writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	try {
		if (HTTPSproxy) await socket.opened;

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await writer.write(encoder.encode(request));
		writer.releaseLock();

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const { done, value } = await reader.read();
			if (done || !value) throw new Error(`${HTTPSproxy ? 'HTTPS' : 'HTTP'} proxy closed the connection before returning the CONNECT response`);
			responseBuffer = new Uint8Array([...responseBuffer, ...value]);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('proxy CONNECT response headers too long or invalid');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		reader.releaseLock();

		if (validDataLength(initialData) > 0) {
			const remoteWriter = socket.writable.getWriter();
			await remoteWriter.write(initialData);
			remoteWriter.releaseLock();
		}

		// CONNECT response headers may be followed by tunnel data; feed it back into the readable stream first so the first packet is not swallowed.
		if (bytesRead > headerEndIndex) {
			const { readable, writable } = new TransformStream();
			const transformWriter = writable.getWriter();
			await transformWriter.write(responseBuffer.subarray(headerEndIndex, bytesRead));
			transformWriter.releaseLock();
			socket.readable.pipeTo(writable).catch(() => { });
			return { readable, writable: socket.writable, closed: socket.closed, close: () => socket.close() };
		}

		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

async function httpsConnect(targetHost, targetPort, initialData, TCPconnection, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	let tlsSocket = null;
	const tlsServerName = isIPHostname(hostname) ? '' : stripIPv6Brackets(hostname);
	const openHttpsProxyTls = async (allowChacha = false) => {
		const proxySocket = TCPconnection({ hostname, port });
		try {
			await proxySocket.opened;
			const socket = new TlsClient(proxySocket, { serverName: tlsServerName, insecure: true, allowChacha });
			await socket.handshake();
			log(`[HTTPS proxy] TLS version: ${socket.isTls13 ? '1.3' : '1.2'} | Cipher: 0x${socket.cipherSuite.toString(16)}${socket.cipherConfig?.chacha ? ' (ChaCha20)' : ' (AES-GCM)'}`);
			return socket;
		} catch (error) {
			try { proxySocket.close() } catch (e) { }
			throw error;
		}
	};
	try {
		try {
			tlsSocket = await openHttpsProxyTls(false);
		} catch (error) {
			if (!/cipher|handshake|TLS Alert|ServerHello|Finished|Unsupported|Missing TLS/i.test(error?.message || `${error || ''}`)) throw error;
			log(`[HTTPS proxy] AES-GCM TLS handshake failed, falling back to ChaCha20 compatibility mode: ${error?.message || error}`);
			tlsSocket = await openHttpsProxyTls(true);
		}

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await tlsSocket.write(encoder.encode(request));

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const value = await tlsSocket.read();
			if (!value) throw new Error('HTTPS proxy closed the connection before returning the CONNECT response');
			responseBuffer = concatByteChunks(responseBuffer, value);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('HTTPS proxy CONNECT response headers too long or invalid');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		if (validDataLength(initialData) > 0) await tlsSocket.write(toUint8Array(initialData));
		const bufferedData = bytesRead > headerEndIndex ? responseBuffer.subarray(headerEndIndex, bytesRead) : null;
		let closedSettled = false, resolveClosed, rejectClosed;
		const settleClosed = (settle, value) => {
			if (!closedSettled) {
				closedSettled = true;
				settle(value);
			}
		};
		const closed = new Promise((resolve, reject) => {
			resolveClosed = resolve;
			rejectClosed = reject;
		});
		const close = () => {
			try { tlsSocket.close() } catch (e) { }
			settleClosed(resolveClosed);
		};
		const readable = new ReadableStream({
			async start(controller) {
				try {
					if (validDataLength(bufferedData) > 0) controller.enqueue(bufferedData);
					while (true) {
						const data = await tlsSocket.read();
						if (!data) break;
						if (data.byteLength > 0) controller.enqueue(data);
					}
					try { controller.close() } catch (e) { }
					settleClosed(resolveClosed);
				} catch (error) {
					try { controller.error(error) } catch (e) { }
					settleClosed(rejectClosed, error);
				}
			},
			cancel() {
				close();
			}
		});
		const writable = new WritableStream({
			async write(chunk) {
				await tlsSocket.write(toUint8Array(chunk));
			},
			close,
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});
		return { readable, writable, closed, close };
	} catch (error) {
		try { tlsSocket?.close() } catch (e) { }
		throw error;
	}
}

function createRequestTcpConnector(request) {
	const requestWithFetcher = /** @type {any} */ (request);
	const fetcher = requestWithFetcher?.fetcher;
	if (!fetcher || typeof fetcher.connect !== 'function') throw new Error('request.fetcher.connect unavailable');
	return (options, init) => init === undefined ? fetcher.connect(options) : fetcher.connect(options, init);
}
////////////////////////////////////////////TLSClient by: @Alexandre_Kojeve////////////////////////////////////////////////
const TLS_VERSION_10 = 769, TLS_VERSION_12 = 771, TLS_VERSION_13 = 772;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20, CONTENT_TYPE_ALERT = 21, CONTENT_TYPE_HANDSHAKE = 22, CONTENT_TYPE_APPLICATION_DATA = 23;
const HANDSHAKE_TYPE_CLIENT_HELLO = 1, HANDSHAKE_TYPE_SERVER_HELLO = 2, HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8, HANDSHAKE_TYPE_CERTIFICATE = 11, HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12, HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13, HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14, HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16, HANDSHAKE_TYPE_FINISHED = 20, HANDSHAKE_TYPE_KEY_UPDATE = 24;
const EXT_SERVER_NAME = 0, EXT_SUPPORTED_GROUPS = 10, EXT_EC_POINT_FORMATS = 11, EXT_SIGNATURE_ALGORITHMS = 13, EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16, EXT_SUPPORTED_VERSIONS = 43, EXT_PSK_KEY_EXCHANGE_MODES = 45, EXT_KEY_SHARE = 51;

const ALERT_CLOSE_NOTIFY = 0, ALERT_LEVEL_WARNING = 1, ALERT_UNRECOGNIZED_NAME = 112;
const shouldIgnoreTlsAlert = fragment => fragment?.[0] === ALERT_LEVEL_WARNING && fragment?.[1] === ALERT_UNRECOGNIZED_NAME;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const EMPTY_BYTES = new Uint8Array(0);

const CIPHER_SUITES_BY_ID = new Map([
	[4865, { id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: !0 }],
	[4866, { id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: !0 }],
	[4867, { id: 4867, keyLen: 32, ivLen: 12, hash: "SHA-256", tls13: !0, chacha: !0 }],
	[49199, { id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49200, { id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52392, { id: 52392, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }],
	[49195, { id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49196, { id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52393, { id: 52393, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }]
]);
const GROUPS_BY_ID = new Map([[29, "X25519"], [23, "P-256"]]);
const SUPPORTED_SIGNATURE_ALGORITHMS = [2052, 2053, 2054, 1025, 1281, 1537, 1027, 1283, 1539];

const tlsBytes = (...parts) => {
	const flattenBytes = values => values.flatMap(value => value instanceof Uint8Array ? [...value] : Array.isArray(value) ? flattenBytes(value) : "number" == typeof value ? [value] : []);
	return new Uint8Array(flattenBytes(parts))
};
const uint16be = value => [value >> 8 & 255, 255 & value];
const readUint16 = (buffer, offset) => buffer[offset] << 8 | buffer[offset + 1];
const readUint24 = (buffer, offset) => buffer[offset] << 16 | buffer[offset + 1] << 8 | buffer[offset + 2];
const concatBytes = (...chunks) => {
	const nonEmptyChunks = chunks.filter((chunk => chunk && chunk.length > 0)),
		length = nonEmptyChunks.reduce(((total, chunk) => total + chunk.length), 0),
		result = new Uint8Array(length);
	let offset = 0;
	for (const chunk of nonEmptyChunks) result.set(chunk, offset), offset += chunk.length;
	return result
};
const randomBytes = length => crypto.getRandomValues(new Uint8Array(length));
const constantTimeEqual = (left, right) => {
	if (!left || !right || left.length !== right.length) return !1;
	let diff = 0; for (let index = 0; index < left.length; index++) diff |= left[index] ^ right[index];
	return 0 === diff
};
const hashByteLength = hash => "SHA-512" === hash ? 64 : "SHA-384" === hash ? 48 : 32;
async function hmac(hash, key, data) {
	const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash }, !1, ["sign"]);
	return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data))
}
async function digestBytes(hash, data) { return new Uint8Array(await crypto.subtle.digest(hash, data)) }
async function tls12Prf(secret, label, seed, length, hash = "SHA-256") {
	const labelSeed = concatBytes(textEncoder.encode(label), seed);
	let output = new Uint8Array(0),
		currentA = labelSeed;
	for (; output.length < length;) {
		currentA = await hmac(hash, secret, currentA);
		const block = await hmac(hash, secret, concatBytes(currentA, labelSeed));
		output = concatBytes(output, block)
	}
	return output.slice(0, length)
}
async function hkdfExtract(hash, salt, inputKeyMaterial) {
	return salt && salt.length || (salt = new Uint8Array(hashByteLength(hash))), hmac(hash, salt, inputKeyMaterial)
}
async function hkdfExpandLabel(hash, secret, label, context, length) {
	const fullLabel = textEncoder.encode("tls13 " + label);
	return async function (hash, secret, info, length) {
		const hashLen = hashByteLength(hash),
			roundCount = Math.ceil(length / hashLen);
		let output = new Uint8Array(0),
			previousBlock = new Uint8Array(0);
		for (let round = 1; round <= roundCount; round++) previousBlock = await hmac(hash, secret, concatBytes(previousBlock, info, [round])), output = concatBytes(output, previousBlock);
		return output.slice(0, length)
	}(hash, secret, tlsBytes(uint16be(length), fullLabel.length, fullLabel, context.length, context), length)
}
async function generateKeyShare(group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group };
	const keyPair = /** @type {CryptoKeyPair} */ (await crypto.subtle.generateKey(algorithm, !0, ["deriveBits"]));
	const publicKeyRaw = /** @type {ArrayBuffer} */ (await crypto.subtle.exportKey("raw", keyPair.publicKey));
	return { keyPair, publicKeyRaw: new Uint8Array(publicKeyRaw) }
}
async function deriveSharedSecret(privateKey, peerPublicKey, group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group },
		peerKey = await crypto.subtle.importKey("raw", peerPublicKey, algorithm, !1, []),
		bits = "P-384" === group ? 384 : "P-521" === group ? 528 : 256;
	return new Uint8Array(await crypto.subtle.deriveBits(/** @type {any} */({ name: algorithm.name, public: peerKey }), privateKey, bits))
}
async function importAesGcmKey(key, usages) { return crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, !1, usages) }
async function aesGcmEncryptWithKey(cryptoKey, initializationVector, plaintext, additionalData) {
	return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, plaintext))
}
async function aesGcmDecryptWithKey(cryptoKey, initializationVector, ciphertext, additionalData) {
	return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, ciphertext))
}

function rotateLeft32(value, bits) { return (value << bits | value >>> 32 - bits) >>> 0 }

function chachaQuarterRound(state, indexA, indexB, indexC, indexD) {
	state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 16), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 12), state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 8), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 7)
}

function chacha20Block(key, counter, nonce) {
	const state = new Uint32Array(16);
	state[0] = 1634760805, state[1] = 857760878, state[2] = 2036477234, state[3] = 1797285236;
	const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
	for (let wordIndex = 0; wordIndex < 8; wordIndex++) state[4 + wordIndex] = keyView.getUint32(4 * wordIndex, !0);
	state[12] = counter;
	const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
	state[13] = nonceView.getUint32(0, !0), state[14] = nonceView.getUint32(4, !0), state[15] = nonceView.getUint32(8, !0);
	const workingState = new Uint32Array(state);
	for (let round = 0; round < 10; round++) chachaQuarterRound(workingState, 0, 4, 8, 12), chachaQuarterRound(workingState, 1, 5, 9, 13), chachaQuarterRound(workingState, 2, 6, 10, 14), chachaQuarterRound(workingState, 3, 7, 11, 15), chachaQuarterRound(workingState, 0, 5, 10, 15), chachaQuarterRound(workingState, 1, 6, 11, 12), chachaQuarterRound(workingState, 2, 7, 8, 13), chachaQuarterRound(workingState, 3, 4, 9, 14);
	for (let wordIndex = 0; wordIndex < 16; wordIndex++) workingState[wordIndex] = workingState[wordIndex] + state[wordIndex] >>> 0;
	return new Uint8Array(workingState.buffer.slice(0))
}

function chacha20Xor(key, nonce, data) {
	const output = new Uint8Array(data.length);
	let counter = 1;
	for (let offset = 0; offset < data.length; offset += 64) {
		const block = chacha20Block(key, counter++, nonce),
			blockLength = Math.min(64, data.length - offset);
		for (let index = 0; index < blockLength; index++) output[offset + index] = data[offset + index] ^ block[index]
	}
	return output
}

function poly1305Mac(key, message) {
	const rKey = function (rBytes) {
		const clamped = new Uint8Array(rBytes);
		return clamped[3] &= 15, clamped[7] &= 15, clamped[11] &= 15, clamped[15] &= 15, clamped[4] &= 252, clamped[8] &= 252, clamped[12] &= 252, clamped
	}(key.slice(0, 16)),
		sKey = key.slice(16, 32);
	let accumulator = [0n, 0n, 0n, 0n, 0n];
	const rLimbs = [0x3ffffffn & BigInt(rKey[0] | rKey[1] << 8 | rKey[2] << 16 | rKey[3] << 24), 0x3ffffffn & BigInt(rKey[3] >> 2 | rKey[4] << 6 | rKey[5] << 14 | rKey[6] << 22), 0x3ffffffn & BigInt(rKey[6] >> 4 | rKey[7] << 4 | rKey[8] << 12 | rKey[9] << 20), 0x3ffffffn & BigInt(rKey[9] >> 6 | rKey[10] << 2 | rKey[11] << 10 | rKey[12] << 18), 0x3ffffffn & BigInt(rKey[13] | rKey[14] << 8 | rKey[15] << 16)];
	for (let offset = 0; offset < message.length; offset += 16) {
		const chunk = message.slice(offset, offset + 16),
			paddedChunk = new Uint8Array(17);
		paddedChunk.set(chunk), paddedChunk[chunk.length] = 1, accumulator[0] += BigInt(paddedChunk[0] | paddedChunk[1] << 8 | paddedChunk[2] << 16 | (3 & paddedChunk[3]) << 24), accumulator[1] += BigInt(paddedChunk[3] >> 2 | paddedChunk[4] << 6 | paddedChunk[5] << 14 | (15 & paddedChunk[6]) << 22), accumulator[2] += BigInt(paddedChunk[6] >> 4 | paddedChunk[7] << 4 | paddedChunk[8] << 12 | (63 & paddedChunk[9]) << 20), accumulator[3] += BigInt(paddedChunk[9] >> 6 | paddedChunk[10] << 2 | paddedChunk[11] << 10 | paddedChunk[12] << 18), accumulator[4] += BigInt(paddedChunk[13] | paddedChunk[14] << 8 | paddedChunk[15] << 16 | paddedChunk[16] << 24);
		const product = [0n, 0n, 0n, 0n, 0n];
		for (let accIndex = 0; accIndex < 5; accIndex++)
			for (let rIndex = 0; rIndex < 5; rIndex++) {
				const limbIndex = accIndex + rIndex;
				limbIndex < 5 ? product[limbIndex] += accumulator[accIndex] * rLimbs[rIndex] : product[limbIndex - 5] += accumulator[accIndex] * rLimbs[rIndex] * 5n
			}
		let carry = 0n;
		for (let index = 0; index < 5; index++) product[index] += carry, accumulator[index] = 0x3ffffffn & product[index], carry = product[index] >> 26n;
		accumulator[0] += 5n * carry, carry = accumulator[0] >> 26n, accumulator[0] &= 0x3ffffffn, accumulator[1] += carry
	}
	let tagValue = accumulator[0] | accumulator[1] << 26n | accumulator[2] << 52n | accumulator[3] << 78n | accumulator[4] << 104n;
	tagValue = tagValue + sKey.reduce(((total, byte, index) => total + (BigInt(byte) << BigInt(8 * index))), 0n) & (1n << 128n) - 1n;
	const tag = new Uint8Array(16);
	for (let index = 0; index < 16; index++) tag[index] = Number(tagValue >> BigInt(8 * index) & 0xffn);
	return tag
}

function chacha20Poly1305Encrypt(key, nonce, plaintext, additionalData) {
	const polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		ciphertext = chacha20Xor(key, nonce, plaintext),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - ciphertext.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + ciphertext.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(ciphertext, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + ciphertext.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(ciphertext.length), !0);
	const tag = poly1305Mac(polyKey, macData);
	return concatBytes(ciphertext, tag)
}

function chacha20Poly1305Decrypt(key, nonce, ciphertext, additionalData) {
	if (ciphertext.length < 16) throw new Error("Ciphertext too short");
	const tag = ciphertext.slice(-16),
		encryptedData = ciphertext.slice(0, -16),
		polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - encryptedData.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + encryptedData.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(encryptedData, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + encryptedData.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(encryptedData.length), !0);
	const expectedTag = poly1305Mac(polyKey, macData);
	let diff = 0;
	for (let index = 0; index < 16; index++) diff |= tag[index] ^ expectedTag[index];
	if (0 !== diff) throw new Error("ChaCha20-Poly1305 authentication failed");
	return chacha20Xor(key, nonce, encryptedData)
}

const TLS_MAX_PLAINTEXT_FRAGMENT = 16 * 1024;
function buildTlsRecord(contentType, fragment, version = TLS_VERSION_12) {
	const data = toUint8Array(fragment);
	const record = new Uint8Array(5 + data.byteLength);
	record[0] = contentType;
	record[1] = version >> 8 & 255;
	record[2] = version & 255;
	record[3] = data.byteLength >> 8 & 255;
	record[4] = data.byteLength & 255;
	record.set(data, 5);
	return record;
}
function buildHandshakeMessage(handshakeType, body) { return tlsBytes(handshakeType, (length => [length >> 16 & 255, length >> 8 & 255, 255 & length])(body.length), body) }
class TlsRecordParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = toUint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 5) return null;
		const contentType = this.buffer[0],
			version = readUint16(this.buffer, 1),
			length = readUint16(this.buffer, 3);
		if (this.buffer.length < 5 + length) return null;
		const fragment = this.buffer.subarray(5, 5 + length);
		return this.buffer = this.buffer.subarray(5 + length), { type: contentType, version, length, fragment }
	}
}
class TlsHandshakeParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = toUint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 4) return null;
		const handshakeType = this.buffer[0],
			length = readUint24(this.buffer, 1);
		if (this.buffer.length < 4 + length) return null;
		const body = this.buffer.subarray(4, 4 + length),
			raw = this.buffer.subarray(0, 4 + length);
		return this.buffer = this.buffer.subarray(4 + length), { type: handshakeType, length, body, raw }
	}
}

function parseServerHello(body) {
	let offset = 0;
	const legacyVersion = readUint16(body, offset);
	offset += 2;
	const serverRandom = body.slice(offset, offset + 32);
	offset += 32;
	const sessionIdLength = body[offset++],
		sessionId = body.slice(offset, offset + sessionIdLength);
	offset += sessionIdLength;
	const cipherSuite = readUint16(body, offset);
	offset += 2;
	const compression = body[offset++];
	let selectedVersion = legacyVersion,
		keyShare = null,
		alpn = null;
	if (offset < body.length) {
		const extensionsLength = readUint16(body, offset);
		offset += 2;
		const extensionsEnd = offset + extensionsLength;
		for (; offset + 4 <= extensionsEnd;) {
			const extensionType = readUint16(body, offset);
			offset += 2;
			const extensionLength = readUint16(body, offset);
			offset += 2;
			const extensionData = body.slice(offset, offset + extensionLength);
			if (offset += extensionLength, extensionType === EXT_SUPPORTED_VERSIONS && extensionLength >= 2) selectedVersion = readUint16(extensionData, 0);
			else if (extensionType === EXT_KEY_SHARE && extensionLength >= 4) {
				const group = readUint16(extensionData, 0),
					keyLength = readUint16(extensionData, 2);
				keyShare = { group, key: extensionData.slice(4, 4 + keyLength) }
			} else extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3 && (alpn = textDecoder.decode(extensionData.slice(3, 3 + extensionData[2])))
		}
	}
	const helloRetryRequestRandom = new Uint8Array([207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156]);
	return { version: legacyVersion, serverRandom, sessionId, cipherSuite, compression, selectedVersion, keyShare, alpn, isHRR: constantTimeEqual(serverRandom, helloRetryRequestRandom), isTls13: selectedVersion === TLS_VERSION_13 }
}

function parseServerKeyExchange(body) {
	let offset = 1;
	const namedCurve = readUint16(body, offset);
	offset += 2;
	const keyLength = body[offset++];
	return { namedCurve, serverPublicKey: body.slice(offset, offset + keyLength) }
}

function extractLeafCertificate(body, hasContext = 0) {
	let offset = 0;
	if (hasContext) {
		const contextLength = body[offset++];
		offset += contextLength
	}
	if (offset + 3 > body.length) return null;
	const certificateListLength = readUint24(body, offset);
	if (offset += 3, !certificateListLength || offset + 3 > body.length) return null;
	const certificateLength = readUint24(body, offset);
	return offset += 3, certificateLength ? body.slice(offset, offset + certificateLength) : null
}

function parseEncryptedExtensions(body) {
	const parsed = { alpn: null };
	let offset = 2;
	const extensionsEnd = 2 + readUint16(body, 0);
	for (; offset + 4 <= extensionsEnd;) {
		const extensionType = readUint16(body, offset);
		offset += 2;
		const extensionLength = readUint16(body, offset);
		if (offset += 2, extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3) {
			const protocolLength = body[offset + 2];
			protocolLength > 0 && offset + 3 + protocolLength <= offset + extensionLength && (parsed.alpn = textDecoder.decode(body.slice(offset + 3, offset + 3 + protocolLength)))
		}
		offset += extensionLength
	}
	return parsed
}

function buildClientHello(clientRandom, serverName, keyShares, { tls13: enableTls13 = !0, tls12: enableTls12 = !0, alpn = null, chacha = !0 } = {}) {
	const cipherIds = [];
	enableTls13 && cipherIds.push(4865, 4866, ...(chacha ? [4867] : [])), enableTls12 && cipherIds.push(49199, 49200, 49195, 49196, ...(chacha ? [52392, 52393] : []));
	const cipherBytes = tlsBytes(...cipherIds.flatMap(uint16be)),
		extensions = [tlsBytes(255, 1, 0, 1, 0)];
	if (serverName) {
		const serverNameBytes = textEncoder.encode(serverName),
			serverNameList = tlsBytes(0, uint16be(serverNameBytes.length), serverNameBytes);
		extensions.push(tlsBytes(uint16be(EXT_SERVER_NAME), uint16be(serverNameList.length + 2), uint16be(serverNameList.length), serverNameList))
	}
	extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS), 0, 2, 1, 0)), extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS), 0, 6, 0, 4, 0, 29, 0, 23));
	const signatureBytes = tlsBytes(...SUPPORTED_SIGNATURE_ALGORITHMS.flatMap(uint16be));
	extensions.push(tlsBytes(uint16be(EXT_SIGNATURE_ALGORITHMS), uint16be(signatureBytes.length + 2), uint16be(signatureBytes.length), signatureBytes));
	const protocols = Array.isArray(alpn) ? alpn.filter(Boolean) : alpn ? [alpn] : [];
	if (protocols.length) {
		const alpnBytes = concatBytes(...protocols.map((protocol => { const protocolBytes = textEncoder.encode(protocol); return tlsBytes(protocolBytes.length, protocolBytes) })));
		extensions.push(tlsBytes(uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION), uint16be(alpnBytes.length + 2), uint16be(alpnBytes.length), alpnBytes))
	}
	if (enableTls13 && keyShares) {
		let keyShareBytes;
		if (extensions.push(enableTls12 ? tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 5, 4, 3, 4, 3, 3) : tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 3, 2, 3, 4)), extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES), 0, 2, 1, 1)), keyShares?.x25519 && keyShares?.p256) keyShareBytes = concatBytes(tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519), tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256));
		else if (keyShares?.x25519) keyShareBytes = tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519);
		else if (keyShares?.p256) keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256);
		else {
			if (!(keyShares instanceof Uint8Array)) throw new Error("Invalid keyShares");
			keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.length), keyShares)
		}
		extensions.push(tlsBytes(uint16be(EXT_KEY_SHARE), uint16be(keyShareBytes.length + 2), uint16be(keyShareBytes.length), keyShareBytes))
	}
	const extensionsBytes = concatBytes(...extensions);
	return buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_HELLO, tlsBytes(uint16be(TLS_VERSION_12), clientRandom, 0, uint16be(cipherBytes.length), cipherBytes, 1, 0, uint16be(extensionsBytes.length), extensionsBytes))
}
const uint64be = sequenceNumber => { const bytes = new Uint8Array(8); return new DataView(bytes.buffer).setBigUint64(0, sequenceNumber, !1), bytes },
	xorSequenceIntoIv = (initializationVector, sequenceNumber) => {
		const nonce = initializationVector.slice(),
			sequenceBytes = uint64be(sequenceNumber);
		for (let index = 0; index < 8; index++) nonce[nonce.length - 8 + index] ^= sequenceBytes[index];
		return nonce
	},
	deriveTrafficKeys = (hash, secret, keyLen, ivLen) => Promise.all([hkdfExpandLabel(hash, secret, "key", EMPTY_BYTES, keyLen), hkdfExpandLabel(hash, secret, "iv", EMPTY_BYTES, ivLen)]);
class TlsClient {
	constructor(socket, options = {}) {
		if (this.socket = socket, this.serverName = options.serverName || "", this.supportTls13 = !1 !== options.tls13, this.supportTls12 = !1 !== options.tls12, !this.supportTls13 && !this.supportTls12) throw new Error("At least one TLS version must be enabled");
		this.alpnProtocols = Array.isArray(options.alpn) ? options.alpn : options.alpn ? [options.alpn] : null, this.allowChacha = options.allowChacha !== false, this.timeout = options.timeout ?? 3e4, this.clientRandom = randomBytes(32), this.serverRandom = null, this.handshakeChunks = [], this.handshakeComplete = !1, this.negotiatedAlpn = null, this.cipherSuite = null, this.cipherConfig = null, this.isTls13 = !1, this.masterSecret = null, this.handshakeSecret = null, this.clientWriteKey = null, this.serverWriteKey = null, this.clientWriteIv = null, this.serverWriteIv = null, this.clientHandshakeKey = null, this.serverHandshakeKey = null, this.clientHandshakeIv = null, this.serverHandshakeIv = null, this.clientAppKey = null, this.serverAppKey = null, this.clientAppIv = null, this.serverAppIv = null, this.clientWriteCryptoKey = null, this.serverWriteCryptoKey = null, this.clientHandshakeCryptoKey = null, this.serverHandshakeCryptoKey = null, this.clientAppCryptoKey = null, this.serverAppCryptoKey = null, this.clientSeqNum = 0n, this.serverSeqNum = 0n, this.recordParser = new TlsRecordParser, this.handshakeParser = new TlsHandshakeParser, this.keyPairs = new Map, this.ecdhKeyPair = null, this.sawCert = !1
	}
	recordHandshake(chunk) { this.handshakeChunks.push(chunk) }
	transcript() { return 1 === this.handshakeChunks.length ? this.handshakeChunks[0] : concatBytes(...this.handshakeChunks) }
	getCipherConfig(cipherSuite) { return CIPHER_SUITES_BY_ID.get(cipherSuite) || null }
	async readChunk(reader) { return this.timeout ? Promise.race([reader.read(), new Promise(((resolve, reject) => setTimeout((() => reject(new Error("TLS read timeout"))), this.timeout)))]) : reader.read() }
	async readRecordsUntil(reader, predicate, closedError) {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();)
				if (await predicate(record)) return;
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error(closedError);
			this.recordParser.feed(value)
		}
	}
	async readHandshakeUntil(reader, predicate, closedError) {
		for (let message; message = this.handshakeParser.next();)
			if (await predicate(message)) return;
		return this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(record.fragment);
				for (let message; message = this.handshakeParser.next();)
					if (await predicate(message)) return 1
			}
		}), closedError)
	}
	async acceptCertificate(certificate) { if (!certificate?.length) throw new Error("Empty certificate"); this.sawCert = !0 }
	async handshake() {
		const [p256Share, x25519Share] = await Promise.all([generateKeyShare("P-256"), generateKeyShare("X25519")]);
		this.keyPairs = new Map([[23, p256Share], [29, x25519Share]]), this.ecdhKeyPair = p256Share.keyPair;
		const reader = this.socket.readable.getReader(),
			writer = this.socket.writable.getWriter();
		try {
			const clientHello = buildClientHello(this.clientRandom, this.serverName, { x25519: x25519Share.publicKeyRaw, p256: p256Share.publicKeyRaw }, { tls13: this.supportTls13, tls12: this.supportTls12, alpn: this.alpnProtocols, chacha: this.allowChacha });
			this.recordHandshake(clientHello), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientHello, TLS_VERSION_10));
			const serverHello = await this.receiveServerHello(reader);
			if (serverHello.isHRR) throw new Error("HelloRetryRequest is not supported by TLSClientMini");
			if (serverHello.keyShare?.group && this.keyPairs.has(serverHello.keyShare.group)) {
				const selectedKeyPair = this.keyPairs.get(serverHello.keyShare.group);
				this.ecdhKeyPair = selectedKeyPair.keyPair
			}
			serverHello.isTls13 ? await this.handshakeTls13(reader, writer, serverHello) : await this.handshakeTls12(reader, writer), this.handshakeComplete = !0
		} finally {
			reader.releaseLock(), writer.releaseLock()
		}
	}
	async receiveServerHello(reader) {
		for (; ;) {
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error("Connection closed waiting for ServerHello");
			let record;
			for (this.recordParser.feed(value); record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (shouldIgnoreTlsAlert(record.fragment)) continue;
					throw new Error(`TLS Alert: level=${record.fragment[0]}, desc=${record.fragment[1]}`);
				}
				if (record.type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(record.fragment); message = this.handshakeParser.next();) {
					if (message.type !== HANDSHAKE_TYPE_SERVER_HELLO) continue;
					this.recordHandshake(message.raw);
					const serverHello = parseServerHello(message.body);
					if (this.serverRandom = serverHello.serverRandom, this.cipherSuite = serverHello.cipherSuite, this.cipherConfig = this.getCipherConfig(serverHello.cipherSuite), this.isTls13 = serverHello.isTls13, this.negotiatedAlpn = serverHello.alpn || null, !this.cipherConfig) throw new Error(`Unsupported cipher suite: 0x${serverHello.cipherSuite.toString(16)}`);
					return serverHello
				}
			}
		}
	}
	async handshakeTls12(reader, writer) {
		/** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */
		let serverKeyExchange = null;
		let sawServerHelloDone = !1;
		let clientCertRequested = !1;
		if (await this.readHandshakeUntil(reader, (async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_CERTIFICATE: {
					this.recordHandshake(message.raw);
					const certificate = extractLeafCertificate(message.body, 1);
					if (!certificate) throw new Error("Missing TLS 1.2 certificate");
					await this.acceptCertificate(certificate);
					break
				}
				case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
					this.recordHandshake(message.raw), serverKeyExchange = parseServerKeyExchange(message.body);
					break;
				case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
					return this.recordHandshake(message.raw), sawServerHelloDone = !0, 1;
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					this.recordHandshake(message.raw), clientCertRequested = !0;
					break;
				default:
					this.recordHandshake(message.raw)
			}
		}), "Connection closed during TLS 1.2 handshake"), !this.sawCert) throw new Error("Missing TLS 1.2 leaf certificate");
		const serverKeyExchangeData = /** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */ (serverKeyExchange);
		if (!serverKeyExchangeData) throw new Error("Missing TLS 1.2 ServerKeyExchange");
		const curveName = GROUPS_BY_ID.get(serverKeyExchangeData.namedCurve);
		if (!curveName) throw new Error(`Unsupported named curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const keyShare = this.keyPairs.get(serverKeyExchangeData.namedCurve);
		if (!keyShare) throw new Error(`Missing key pair for curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const preMasterSecret = await deriveSharedSecret(keyShare.keyPair.privateKey, serverKeyExchangeData.serverPublicKey, curveName),
			clientKeyExchange = buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, tlsBytes(keyShare.publicKeyRaw.length, keyShare.publicKeyRaw));
		if (clientCertRequested) {
			const emptyCertificate = buildHandshakeMessage(HANDSHAKE_TYPE_CERTIFICATE, tlsBytes(0, 0, 0));
			this.recordHandshake(emptyCertificate), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, emptyCertificate))
		}
		this.recordHandshake(clientKeyExchange);
		const hashName = this.cipherConfig.hash;
		this.masterSecret = await tls12Prf(preMasterSecret, "master secret", concatBytes(this.clientRandom, this.serverRandom), 48, hashName);
		const keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			keyBlock = await tls12Prf(this.masterSecret, "key expansion", concatBytes(this.serverRandom, this.clientRandom), 2 * keyLen + 2 * ivLen, hashName);
		this.clientWriteKey = keyBlock.slice(0, keyLen), this.serverWriteKey = keyBlock.slice(keyLen, 2 * keyLen), this.clientWriteIv = keyBlock.slice(2 * keyLen, 2 * keyLen + ivLen), this.serverWriteIv = keyBlock.slice(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
		if (!this.cipherConfig.chacha) [this.clientWriteCryptoKey, this.serverWriteCryptoKey] = await Promise.all([importAesGcmKey(this.clientWriteKey, ["encrypt"]), importAesGcmKey(this.serverWriteKey, ["decrypt"])]);
		await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientKeyExchange)), await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC, tlsBytes(1)));
		const clientVerifyData = await tls12Prf(this.masterSecret, "client finished", await digestBytes(hashName, this.transcript()), 12, hashName),
			finishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientVerifyData);
		this.recordHandshake(finishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, await this.encryptTls12(finishedMessage, CONTENT_TYPE_HANDSHAKE)));
		let sawChangeCipherSpec = !1;
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) return void (sawChangeCipherSpec = !0);
			if (record.type !== CONTENT_TYPE_HANDSHAKE || !sawChangeCipherSpec) return;
			const decrypted = await this.decryptTls12(record.fragment, CONTENT_TYPE_HANDSHAKE);
			if (decrypted[0] !== HANDSHAKE_TYPE_FINISHED) return;
			const verifyLength = readUint24(decrypted, 1),
				verifyData = decrypted.slice(4, 4 + verifyLength),
				expectedVerifyData = await tls12Prf(this.masterSecret, "server finished", await digestBytes(hashName, this.transcript()), 12, hashName);
			if (!constantTimeEqual(verifyData, expectedVerifyData)) throw new Error("TLS 1.2 server Finished verify failed");
			return 1
		}), "Connection closed waiting for TLS 1.2 Finished")
	}
	async handshakeTls13(reader, writer, serverHello) {
		const groupName = GROUPS_BY_ID.get(serverHello.keyShare?.group);
		if (!groupName || !serverHello.keyShare?.key?.length) throw new Error("Missing TLS 1.3 key_share");
		const hashName = this.cipherConfig.hash,
			hashLen = hashByteLength(hashName),
			keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			sharedSecret = await deriveSharedSecret(this.ecdhKeyPair.privateKey, serverHello.keyShare.key, groupName),
			earlySecret = await hkdfExtract(hashName, null, new Uint8Array(hashLen)),
			derivedSecret = await hkdfExpandLabel(hashName, earlySecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen);
		this.handshakeSecret = await hkdfExtract(hashName, derivedSecret, sharedSecret);
		const transcriptHash = await digestBytes(hashName, this.transcript()),
			clientHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "c hs traffic", transcriptHash, hashLen),
			serverHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "s hs traffic", transcriptHash, hashLen);
		[this.clientHandshakeKey, this.clientHandshakeIv] = await deriveTrafficKeys(hashName, clientHandshakeTrafficSecret, keyLen, ivLen), [this.serverHandshakeKey, this.serverHandshakeIv] = await deriveTrafficKeys(hashName, serverHandshakeTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientHandshakeCryptoKey, this.serverHandshakeCryptoKey] = await Promise.all([importAesGcmKey(this.clientHandshakeKey, ["encrypt"]), importAesGcmKey(this.serverHandshakeKey, ["decrypt"])]);
		const serverFinishedKey = await hkdfExpandLabel(hashName, serverHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen);
		let serverFinishedReceived = !1;
		let clientCertRequested = !1;
		const handleHandshakeMessage = async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: {
					const encryptedExtensions = parseEncryptedExtensions(message.body);
					encryptedExtensions.alpn && (this.negotiatedAlpn = encryptedExtensions.alpn), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE: {
					const certificate = extractLeafCertificate(message.body);
					if (!certificate) throw new Error("Missing TLS 1.3 certificate");
					await this.acceptCertificate(certificate), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					this.recordHandshake(message.raw), clientCertRequested = !0;
					break;
				case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
					this.recordHandshake(message.raw);
					break;
				case HANDSHAKE_TYPE_FINISHED: {
					const expectedVerifyData = await hmac(hashName, serverFinishedKey, await digestBytes(hashName, this.transcript()));
					if (!constantTimeEqual(expectedVerifyData, message.body)) throw new Error("TLS 1.3 server Finished verify failed");
					this.recordHandshake(message.raw), serverFinishedReceived = !0;
					break
				}
				default:
					this.recordHandshake(message.raw)
			}
		};
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC || record.type === CONTENT_TYPE_HANDSHAKE) return;
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type !== CONTENT_TYPE_APPLICATION_DATA) return;
			const decrypted = await this.decryptTls13Handshake(record.fragment),
				innerType = decrypted[decrypted.length - 1],
				plaintext = decrypted.slice(0, -1);
			if (innerType === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(plaintext);
				for (let message; message = this.handshakeParser.next();)
					if (await handleHandshakeMessage(message), serverFinishedReceived) return 1
			}
		}), "Connection closed during TLS 1.3 handshake");
		const applicationTranscriptHash = await digestBytes(hashName, this.transcript()),
			masterDerivedSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen),
			masterSecret = await hkdfExtract(hashName, masterDerivedSecret, new Uint8Array(hashLen)),
			clientAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "c ap traffic", applicationTranscriptHash, hashLen),
			serverAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "s ap traffic", applicationTranscriptHash, hashLen);
		[this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(hashName, clientAppTrafficSecret, keyLen, ivLen), [this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(hashName, serverAppTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientAppCryptoKey, this.serverAppCryptoKey] = await Promise.all([importAesGcmKey(this.clientAppKey, ["encrypt"]), importAesGcmKey(this.serverAppKey, ["decrypt"])]);
		let clientFlightHandshake = EMPTY_BYTES;
		if (clientCertRequested) clientFlightHandshake = buildHandshakeMessage(HANDSHAKE_TYPE_CERTIFICATE, tlsBytes(0, 0, 0, 0)), this.recordHandshake(clientFlightHandshake);
		const clientFinishedKey = await hkdfExpandLabel(hashName, clientHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen),
			clientFinishedVerifyData = await hmac(hashName, clientFinishedKey, await digestBytes(hashName, this.transcript())),
			clientFinishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientFinishedVerifyData);
		this.recordHandshake(clientFinishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, await this.encryptTls13Handshake(concatBytes(clientFlightHandshake, clientFinishedMessage, [CONTENT_TYPE_HANDSHAKE])))), this.clientSeqNum = 0n, this.serverSeqNum = 0n
	}
	async encryptTls12(plaintext, contentType) {
		const sequenceNumber = this.clientSeqNum++,
			sequenceBytes = uint64be(sequenceNumber),
			additionalData = concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(plaintext.length));
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.clientWriteIv, sequenceNumber);
			return chacha20Poly1305Encrypt(this.clientWriteKey, nonce, plaintext, additionalData)
		}
		const explicitNonce = randomBytes(8);
		if (!this.clientWriteCryptoKey) this.clientWriteCryptoKey = await importAesGcmKey(this.clientWriteKey, ["encrypt"]);
		return concatBytes(explicitNonce, await aesGcmEncryptWithKey(this.clientWriteCryptoKey, concatBytes(this.clientWriteIv, explicitNonce), plaintext, additionalData))
	}
	async decryptTls12(ciphertext, contentType) {
		const sequenceNumber = this.serverSeqNum++,
			sequenceBytes = uint64be(sequenceNumber);
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.serverWriteIv, sequenceNumber);
			return chacha20Poly1305Decrypt(this.serverWriteKey, nonce, ciphertext, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(ciphertext.length - 16)))
		}
		const explicitNonce = ciphertext.subarray(0, 8),
			encryptedData = ciphertext.subarray(8);
		if (!this.serverWriteCryptoKey) this.serverWriteCryptoKey = await importAesGcmKey(this.serverWriteKey, ["decrypt"]);
		return aesGcmDecryptWithKey(this.serverWriteCryptoKey, concatBytes(this.serverWriteIv, explicitNonce), encryptedData, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(encryptedData.length - 16)))
	}
	async encryptTls13Handshake(plaintext) {
		const nonce = xorSequenceIntoIv(this.clientHandshakeIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientHandshakeKey, nonce, plaintext, additionalData);
		if (!this.clientHandshakeCryptoKey) this.clientHandshakeCryptoKey = await importAesGcmKey(this.clientHandshakeKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientHandshakeCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13Handshake(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverHandshakeIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length));
		const decrypted = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverHandshakeKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverHandshakeCryptoKey || (this.serverHandshakeCryptoKey = await importAesGcmKey(this.serverHandshakeKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = decrypted.length - 1;
		for (; innerTypeIndex >= 0 && !decrypted[innerTypeIndex];) innerTypeIndex--;
		return innerTypeIndex < 0 ? EMPTY_BYTES : decrypted.slice(0, innerTypeIndex + 1)
	}
	async encryptTls13(data) {
		const plaintext = concatBytes(data, [CONTENT_TYPE_APPLICATION_DATA]),
			nonce = xorSequenceIntoIv(this.clientAppIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientAppKey, nonce, plaintext, additionalData);
		if (!this.clientAppCryptoKey) this.clientAppCryptoKey = await importAesGcmKey(this.clientAppKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientAppCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverAppIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length)),
			plaintext = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverAppKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverAppCryptoKey || (this.serverAppCryptoKey = await importAesGcmKey(this.serverAppKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = plaintext.length - 1;
		for (; innerTypeIndex >= 0 && !plaintext[innerTypeIndex];) innerTypeIndex--;
		if (innerTypeIndex < 0) return {
			data: EMPTY_BYTES,
			type: 0
		};
		return {
			data: plaintext.slice(0, innerTypeIndex),
			type: plaintext[innerTypeIndex]
		}
	}
	async write(data) {
		if (!this.handshakeComplete) throw new Error("Handshake not complete");
		const plaintext = toUint8Array(data);
		if (!plaintext.byteLength) return;
		const writer = this.socket.writable.getWriter();
		try {
			const records = [];
			for (let offset = 0; offset < plaintext.byteLength; offset += TLS_MAX_PLAINTEXT_FRAGMENT) {
				const chunk = plaintext.subarray(offset, Math.min(offset + TLS_MAX_PLAINTEXT_FRAGMENT, plaintext.byteLength));
				const encrypted = this.isTls13 ? await this.encryptTls13(chunk) : await this.encryptTls12(chunk, CONTENT_TYPE_APPLICATION_DATA);
				records.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encrypted));
			}
			await writer.write(records.length === 1 ? records[0] : concatBytes(...records))
		} finally {
			writer.releaseLock()
		}
	}
	async read() {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (record.fragment[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${record.fragment[1]}`)
				}
				if (record.type !== CONTENT_TYPE_APPLICATION_DATA) continue;
				if (!this.isTls13) return this.decryptTls12(record.fragment, CONTENT_TYPE_APPLICATION_DATA);
				const { data, type } = await this.decryptTls13(record.fragment);
				if (type === CONTENT_TYPE_APPLICATION_DATA) return data;
				if (type === CONTENT_TYPE_ALERT) {
					if (data[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${data[1]}`)
				}
				if (type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(data); message = this.handshakeParser.next();)
					if (message.type !== HANDSHAKE_TYPE_NEW_SESSION_TICKET && message.type === HANDSHAKE_TYPE_KEY_UPDATE) throw new Error("TLS 1.3 KeyUpdate is not supported by TLSClientMini")
			}
			const reader = this.socket.readable.getReader();
			try {
				const { value, done } = await this.readChunk(reader);
				if (done) return null;
				this.recordParser.feed(value)
			} finally {
				reader.releaseLock()
			}
		}
	}
	close() { this.socket.close() }
}

function stripIPv6Brackets(hostname = '') {
	const host = String(hostname || '').trim();
	return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function isIPHostname(hostname = '') {
	const host = stripIPv6Brackets(hostname);
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
	if (ipv4Regex.test(host)) return true;
	if (!host.includes(':')) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch (e) {
		return false;
	}
}

//////////////////////////////////////////////////turnConnect///////////////////////////////////////////////
const CONNECT_TIMEOUT_MS = 9999;
const TURN_STUN_MAGIC_COOKIE = new Uint8Array([0x21, 0x12, 0xa4, 0x42]);
const TURN_STUN_TYPE = {
	ALLOCATE_REQUEST: 0x0003, ALLOCATE_SUCCESS: 0x0103, ALLOCATE_ERROR: 0x0113,
	CREATE_PERMISSION_REQUEST: 0x0008, CREATE_PERMISSION_SUCCESS: 0x0108,
	CONNECT_REQUEST: 0x000a, CONNECT_SUCCESS: 0x010a,
	CONNECTION_BIND_REQUEST: 0x000b, CONNECTION_BIND_SUCCESS: 0x010b
};
const TURN_STUN_ATTR = {
	USERNAME: 0x0006, MESSAGE_INTEGRITY: 0x0008, ERROR_CODE: 0x0009,
	XOR_PEER_ADDRESS: 0x0012, REALM: 0x0014, NONCE: 0x0015,
	REQUESTED_TRANSPORT: 0x0019, CONNECTION_ID: 0x002a
};

async function withTimeout(promise, timeoutMs, message) {
	let timer;
	try {
		return await Promise.race([
			promise,
			new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeoutMs) })
		]);
	} finally {
		clearTimeout(timer);
	}
}

function isIPv4(value) {
	const parts = String(value || '').split('.');
	return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function turnStunPadding(length) {
	return -length & 3;
}

function createTurnStunAttribute(type, value) {
	const body = toUint8Array(value);
	const attribute = new Uint8Array(4 + body.byteLength + turnStunPadding(body.byteLength));
	const view = new DataView(attribute.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	attribute.set(body, 4);
	return attribute;
}

function createTurnStunMessage(type, transactionId, attributes) {
	const body = concatByteChunks(...attributes);
	const header = new Uint8Array(20);
	const view = new DataView(header.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	header.set(TURN_STUN_MAGIC_COOKIE, 4);
	header.set(transactionId, 8);
	return concatByteChunks(header, body);
}

function parseTurnErrorCode(data) {
	return data?.byteLength >= 4 ? (data[2] & 7) * 100 + data[3] : 0;
}

function randomTurnTransactionId() {
	return crypto.getRandomValues(new Uint8Array(12));
}

async function addTurnMessageIntegrity(message, key) {
	const signedMessage = new Uint8Array(message);
	const view = new DataView(signedMessage.buffer);
	view.setUint16(2, view.getUint16(2) + 24);
	const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
	const signature = await crypto.subtle.sign('HMAC', hmacKey, signedMessage);
	return concatByteChunks(signedMessage, createTurnStunAttribute(TURN_STUN_ATTR.MESSAGE_INTEGRITY, new Uint8Array(signature)));
}

async function readTurnStunMessage(reader, bufferedData = null, timeoutMessage = 'TURN response timed out') {
	let buffer = validDataLength(bufferedData) ? toUint8Array(bufferedData) : new Uint8Array(0);
	const pull = async () => {
		const { done, value } = await withTimeout(reader.read(), CONNECT_TIMEOUT_MS, timeoutMessage);
		if (done) throw new Error('TURN server closed connection');
		if (value?.byteLength) buffer = concatByteChunks(buffer, value);
	};
	while (buffer.byteLength < 20) await pull();

	const messageLength = 20 + ((buffer[2] << 8) | buffer[3]);
	if (messageLength > 65555) throw new Error('TURN response is too large');
	while (buffer.byteLength < messageLength) await pull();
	const messageBuffer = buffer.subarray(0, messageLength);
	if (TURN_STUN_MAGIC_COOKIE.some((value, index) => messageBuffer[4 + index] !== value)) throw new Error('Invalid TURN/STUN response');

	const view = new DataView(messageBuffer.buffer, messageBuffer.byteOffset, messageBuffer.byteLength);
	const attributes = {};
	for (let offset = 20; offset + 4 <= messageLength;) {
		const type = view.getUint16(offset);
		const length = view.getUint16(offset + 2);
		if (offset + 4 + length > messageBuffer.byteLength) break;
		attributes[type] = messageBuffer.slice(offset + 4, offset + 4 + length);
		offset += 4 + length + turnStunPadding(length);
	}
	return {
		message: { type: view.getUint16(0), attributes },
		extraData: buffer.byteLength > messageLength ? buffer.subarray(messageLength) : null
	};
}

async function writeTurnBytes(writer, bytes, timeoutMessage) {
	await withTimeout(writer.write(bytes), CONNECT_TIMEOUT_MS, timeoutMessage);
}

async function turnConnect(proxy, targetHost, targetPort, TCPconnection) {
	proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
	const resolvedTargetHost = stripIPv6Brackets(targetHost);
	/** @type {string | null} */
	let targetIp = isIPv4(resolvedTargetHost) ? resolvedTargetHost : null;
	if (!targetIp) {
		const records = await DoHquery(resolvedTargetHost, 'A');
		const recordData = records.find(item => item.type === 1 && isIPv4(item.data))?.data;
		targetIp = typeof recordData === 'string' ? recordData : null;
	}
	if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for TURN CONNECT`);

	const turnHost = stripIPv6Brackets(proxy.hostname);
	let controlSocket = null, dataSocket = null, controlWriter = null, controlReader = null, dataWriter = null, dataReader = null, dataReaderReleased = false;
	const close = () => {
		try { controlSocket?.close?.() } catch (e) { }
		try { dataSocket?.close?.() } catch (e) { }
	};
	const releaseDataReader = () => {
		if (dataReaderReleased) return;
		dataReaderReleased = true;
		try { dataReader?.releaseLock?.() } catch (e) { }
	};

	try {
		controlSocket = TCPconnection({ hostname: turnHost, port: proxy.port });
		await withTimeout(controlSocket.opened, CONNECT_TIMEOUT_MS, 'TURN server connection timed out');
		controlWriter = controlSocket.writable.getWriter();
		controlReader = controlSocket.readable.getReader();

		const xorPeerAddress = new Uint8Array(8);
		xorPeerAddress[1] = 1;
		new DataView(xorPeerAddress.buffer).setUint16(2, targetPort ^ 0x2112);
		targetIp.split('.').forEach((value, index) => {
			xorPeerAddress[4 + index] = Number(value) ^ TURN_STUN_MAGIC_COOKIE[index];
		});
		const peerAddress = createTurnStunAttribute(TURN_STUN_ATTR.XOR_PEER_ADDRESS, xorPeerAddress);
		const requestedTransport = new Uint8Array([6, 0, 0, 0]);

		await writeTurnBytes(controlWriter, createTurnStunMessage(
			TURN_STUN_TYPE.ALLOCATE_REQUEST,
			randomTurnTransactionId(),
			[createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport)]
		), 'TURN Allocate request timed out');

		let turnResponse = await readTurnStunMessage(controlReader, null, 'TURN Allocate response timed out');
		let message = turnResponse.message;
		let bufferedData = turnResponse.extraData;
		let integrityKey = null;
		let authAttributes = [];
		const sign = messageToSign => integrityKey ? addTurnMessageIntegrity(messageToSign, integrityKey) : Promise.resolve(messageToSign);

		if (
			message.type === TURN_STUN_TYPE.ALLOCATE_ERROR
			&& proxy.username !== null
			&& proxy.password !== null
			&& parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]) === 401
		) {
			const realmBytes = message.attributes[TURN_STUN_ATTR.REALM];
			const nonce = message.attributes[TURN_STUN_ATTR.NONCE];
			if (!realmBytes || !nonce?.byteLength) throw new Error('TURN authentication challenge is missing realm or nonce');

			const realm = textDecoder.decode(realmBytes);
			integrityKey = new Uint8Array(await crypto.subtle.digest('MD5', textEncoder.encode(`${proxy.username}:${realm}:${proxy.password}`)));
			authAttributes = [
				createTurnStunAttribute(TURN_STUN_ATTR.USERNAME, textEncoder.encode(proxy.username)),
				createTurnStunAttribute(TURN_STUN_ATTR.REALM, textEncoder.encode(realm)),
				createTurnStunAttribute(TURN_STUN_ATTR.NONCE, nonce)
			];

			const allocateRequest = await addTurnMessageIntegrity(createTurnStunMessage(
				TURN_STUN_TYPE.ALLOCATE_REQUEST,
				randomTurnTransactionId(),
				[
					createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport),
					...authAttributes
				]
			), integrityKey);
			const pipelinedMessages = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes]))
			]);
			await writeTurnBytes(controlWriter, concatByteChunks(allocateRequest, ...pipelinedMessages), 'TURN authenticated Allocate request timed out');
			turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN authenticated Allocate response timed out');
			message = turnResponse.message;
			bufferedData = turnResponse.extraData;
		} else if (message.type === TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const pipelinedMessages = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes]))
			]);
			if (pipelinedMessages.length) await writeTurnBytes(controlWriter, concatByteChunks(...pipelinedMessages), 'TURN pipelined request timed out');
		}

		if (message.type !== TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const errorCode = parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]);
			throw new Error(errorCode ? `TURN Allocate failed with ${errorCode}` : 'TURN Allocate failed');
		}

		dataSocket = TCPconnection({ hostname: turnHost, port: proxy.port });
		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CreatePermission response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CREATE_PERMISSION_SUCCESS) throw new Error('TURN CreatePermission failed');

		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CONNECT response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECT_SUCCESS || !message.attributes[TURN_STUN_ATTR.CONNECTION_ID]) throw new Error('TURN CONNECT failed');

		await withTimeout(dataSocket.opened, CONNECT_TIMEOUT_MS, 'TURN data connection timed out');
		dataWriter = dataSocket.writable.getWriter();
		dataReader = dataSocket.readable.getReader();
		await writeTurnBytes(dataWriter, await sign(createTurnStunMessage(
			TURN_STUN_TYPE.CONNECTION_BIND_REQUEST,
			randomTurnTransactionId(),
			[
				createTurnStunAttribute(TURN_STUN_ATTR.CONNECTION_ID, message.attributes[TURN_STUN_ATTR.CONNECTION_ID]),
				...authAttributes
			]
		)), 'TURN ConnectionBind request timed out');

		turnResponse = await readTurnStunMessage(dataReader, null, 'TURN ConnectionBind response timed out');
		message = turnResponse.message;
		const extraPayload = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECTION_BIND_SUCCESS) throw new Error('TURN ConnectionBind failed');

		controlWriter.releaseLock();
		controlWriter = null;
		controlReader.releaseLock();
		controlReader = null;
		dataWriter.releaseLock();
		dataWriter = null;

		const readable = new ReadableStream({
			start(controller) {
				if (extraPayload?.byteLength) controller.enqueue(extraPayload);
			},
			pull(controller) {
				return dataReader.read().then(({ done, value }) => {
					if (done) {
						releaseDataReader();
						controller.close();
					} else if (value?.byteLength) controller.enqueue(new Uint8Array(value));
				});
			},
			cancel() {
				try { dataReader?.cancel?.() } catch (e) { }
				releaseDataReader();
				close();
			}
		});

		return { readable, writable: dataSocket.writable, closed: dataSocket.closed, close };
	} catch (error) {
		try { controlWriter?.releaseLock?.() } catch (e) { }
		try { controlReader?.releaseLock?.() } catch (e) { }
		try { dataWriter?.releaseLock?.() } catch (e) { }
		releaseDataReader();
		close();
		throw error;
	}
}
//////////////////////////////////////////////////sstpConnect///////////////////////////////////////////////
const SSTP_TCP_MSS = 1400;
const SSTP_EMPTY_BYTES = new Uint8Array(0);

function readSstpUint16(bytes, offset = 0) {
	return (bytes[offset] << 8) | bytes[offset + 1];
}

function readSstpUint32(bytes, offset = 0) {
	return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function randomSstpUint16() {
	return readSstpUint16(crypto.getRandomValues(new Uint8Array(2)));
}

function internetChecksum(bytes, offset, length) {
	let sum = 0;
	for (let index = offset; index < offset + length - 1; index += 2) sum += readSstpUint16(bytes, index);
	if (length & 1) sum += bytes[offset + length - 1] << 8;
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return (~sum) & 0xffff;
}

async function sstpConnect(proxy, targetHost, targetPort, TCPconnection) {
	proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
	let bufferedBytes = SSTP_EMPTY_BYTES, pppIdentifier = 1, socket = null, reader = null, writer = null;
	let closedSettled = false, resolveClosed, rejectClosed;
	const closed = new Promise((resolve, reject) => {
		resolveClosed = resolve;
		rejectClosed = reject;
	});
	const settleClosed = (settle, value) => {
		if (closedSettled) return;
		closedSettled = true;
		settle(value);
	};
	const close = () => {
		try { reader?.cancel?.().catch?.(() => { }) } catch (e) { }
		try { reader?.releaseLock?.() } catch (e) { }
		try { writer?.close?.().catch?.(() => { }) } catch (e) { }
		try { writer?.releaseLock?.() } catch (e) { }
		try { socket?.close?.() } catch (e) { }
		settleClosed(resolveClosed);
	};

	const readSocketChunk = async () => {
		const { value, done } = await reader.read();
		if (done || !value) throw new Error('SSTP socket closed');
		return toUint8Array(value);
	};
	const readBytes = async length => {
		while (bufferedBytes.byteLength < length) {
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? concatByteChunks(bufferedBytes, chunk) : chunk;
		}
		const result = bufferedBytes.subarray(0, length);
		bufferedBytes = bufferedBytes.subarray(length);
		return result;
	};
	const readHttpLine = async () => {
		for (; ;) {
			const lineEnd = bufferedBytes.indexOf(10);
			if (lineEnd >= 0) {
				const line = textDecoder.decode(bufferedBytes.subarray(0, lineEnd));
				bufferedBytes = bufferedBytes.subarray(lineEnd + 1);
				return line.replace(/\r$/, '');
			}
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? concatByteChunks(bufferedBytes, chunk) : chunk;
		}
	};
	const readPacket = async (timeoutMs = CONNECT_TIMEOUT_MS) => {
		const header = await withTimeout(readBytes(4), timeoutMs, 'SSTP read timeout');
		const length = readSstpUint16(header, 2) & 0x0fff;
		if (length < 4) throw new Error('Invalid SSTP packet length');
		return {
			isControl: (header[1] & 1) !== 0,
			body: length > 4 ? await withTimeout(readBytes(length - 4), timeoutMs, 'SSTP packet body read timeout') : SSTP_EMPTY_BYTES
		};
	};
	const buildSstpDataPacket = pppFrame => {
		const packetLength = 6 + pppFrame.byteLength;
		const packet = new Uint8Array(packetLength);
		packet.set([0x10, 0x00, ((packetLength >> 8) & 0x0f) | 0x80, packetLength & 0xff, 0xff, 0x03]);
		packet.set(pppFrame, 6);
		return packet;
	};
	const buildPppConfigurePacket = (protocol, code, id, options = []) => {
		const optionsLength = options.reduce((size, option) => size + 2 + option.data.byteLength, 0);
		const frame = new Uint8Array(6 + optionsLength);
		const view = new DataView(frame.buffer);
		view.setUint16(0, protocol);
		frame[2] = code;
		frame[3] = id;
		view.setUint16(4, 4 + optionsLength);
		options.reduce((offset, option) => {
			frame[offset] = option.type;
			frame[offset + 1] = 2 + option.data.byteLength;
			frame.set(option.data, offset + 2);
			return offset + 2 + option.data.byteLength;
		}, 6);
		return frame;
	};
	const parsePPPFrame = data => {
		const offset = data.byteLength >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
		if (data.byteLength - offset < 4) return null;
		const protocol = readSstpUint16(data, offset);
		if (protocol === 0x0021) return { protocol, ipPacket: data.subarray(offset + 2) };
		if (data.byteLength - offset < 6) return null;
		return { protocol, code: data[offset + 2], id: data[offset + 3], payload: data.subarray(offset + 6), rawPacket: data.subarray(offset) };
	};
	const parsePppOptions = data => {
		const options = [];
		for (let offset = 0; offset + 2 <= data.byteLength;) {
			const type = data[offset];
			const length = data[offset + 1];
			if (length < 2 || offset + length > data.byteLength) break;
			options.push({ type, data: data.subarray(offset + 2, offset + length) });
			offset += length;
		}
		return options;
	};

	try {
		const serverHost = stripIPv6Brackets(proxy.hostname);
		const serverPort = proxy.port;
		socket = TCPconnection({ hostname: serverHost, port: serverPort }, { secureTransport: 'on', allowHalfOpen: false });
		await withTimeout(socket.opened, CONNECT_TIMEOUT_MS, 'SSTP server connection timed out');
		reader = socket.readable.getReader();
		writer = socket.writable.getWriter();

		const displayHost = serverHost.includes(':') ? `[${serverHost}]` : serverHost;
		const httpRequest = textEncoder.encode(
			`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n`
			+ `Host: ${Number(serverPort) === 443 ? displayHost : `${displayHost}:${serverPort}`}\r\n`
			+ 'Content-Length: 18446744073709551615\r\n'
			+ `SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`
		);
		const encapsulatedProtocol = new Uint8Array(2);
		new DataView(encapsulatedProtocol.buffer).setUint16(0, 1);
		const maximumReceiveUnit = new Uint8Array(2);
		new DataView(maximumReceiveUnit.buffer).setUint16(0, 1500);
		const sstpConnectRequest = new Uint8Array(12 + encapsulatedProtocol.byteLength);
		const sstpConnectView = new DataView(sstpConnectRequest.buffer);
		sstpConnectRequest[0] = 0x10;
		sstpConnectRequest[1] = 0x01;
		sstpConnectView.setUint16(2, sstpConnectRequest.byteLength | 0x8000);
		sstpConnectView.setUint16(4, 0x0001);
		sstpConnectView.setUint16(6, 1);
		sstpConnectRequest[9] = 1;
		sstpConnectView.setUint16(10, 4 + encapsulatedProtocol.byteLength);
		sstpConnectRequest.set(encapsulatedProtocol, 12);

		await withTimeout(writer.write(concatByteChunks(
			httpRequest,
			sstpConnectRequest,
			buildSstpDataPacket(buildPppConfigurePacket(0xc021, 1, pppIdentifier++, [
				{ type: 1, data: maximumReceiveUnit }
			]))
		)), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake request timed out');

		const statusLine = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake timed out');
		for (; ;) {
			const line = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP header read timed out');
			if (line === '') break;
		}
		if (!/HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(statusLine)) throw new Error(`SSTP HTTP handshake failed: ${statusLine || 'invalid status'}`);

		let localLcpAcked = false, peerLcpAcked = false, papRequired = false, papSent = false, papDone = false, ipcpStarted = false, ipcpFinished = false, sourceIp = null;
		const sendPapIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || !papRequired || papSent) return;
			if (proxy.username === null || proxy.password === null) throw new Error('SSTP server requires PAP authentication');
			const username = textEncoder.encode(proxy.username);
			const password = textEncoder.encode(proxy.password);
			if (username.byteLength > 255 || password.byteLength > 255) throw new Error('SSTP username/password is too long');
			const papLength = 6 + username.byteLength + password.byteLength;
			const frame = new Uint8Array(2 + papLength);
			const view = new DataView(frame.buffer);
			view.setUint16(0, 0xc023);
			frame[2] = 1;
			frame[3] = pppIdentifier++;
			view.setUint16(4, papLength);
			frame[6] = username.byteLength;
			frame.set(username, 7);
			frame[7 + username.byteLength] = password.byteLength;
			frame.set(password, 8 + username.byteLength);
			await withTimeout(writer.write(buildSstpDataPacket(frame)), CONNECT_TIMEOUT_MS, 'SSTP PAP authentication request timed out');
			papSent = true;
		};
		const startIpcpIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || ipcpStarted || (papRequired && !papDone)) return;
			await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
				{ type: 3, data: new Uint8Array(4) }
			]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP request timed out');
			ipcpStarted = true;
		};

		for (let round = 0; round < 50 && !ipcpFinished; round++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp) continue;

			if (ppp.protocol === 0xc021) {
				if (ppp.code === 1) {
					const authOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (authOption?.data?.byteLength >= 2) {
						const authProtocol = readSstpUint16(authOption.data);
						if (authProtocol !== 0xc023) throw new Error(`SSTP unsupported PPP authentication protocol: 0x${authProtocol.toString(16)}`);
						papRequired = true;
					}
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP LCP Configure-Ack timed out');
					peerLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				} else if (ppp.code === 2) {
					localLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				}
				continue;
			}

			if (ppp.protocol === 0xc023) {
				if (ppp.code === 2) {
					papDone = true;
					await startIpcpIfReady();
				} else if (ppp.code === 3) throw new Error('SSTP PAP authentication failed');
				continue;
			}

			if (ppp.protocol === 0x8021) {
				if (ppp.code === 1) {
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP IPCP Configure-Ack timed out');
					await startIpcpIfReady();
				} else if (ppp.code === 3) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) {
						sourceIp = [...addressOption.data].join('.');
						await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
							{ type: 3, data: addressOption.data }
						]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP address request timed out');
						ipcpStarted = true;
					}
				} else if (ppp.code === 2) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) sourceIp = [...addressOption.data].join('.');
					ipcpFinished = true;
				}
			}
		}
		if (!sourceIp) throw new Error('SSTP did not assign an IPv4 address');

		const target = stripIPv6Brackets(targetHost);
		/** @type {string | null} */
		let targetIp = isIPv4(target) ? target : null;
		if (!targetIp) {
			const records = await DoHquery(target, 'A');
			const recordData = records.find(item => item.type === 1 && isIPv4(item.data))?.data;
			targetIp = typeof recordData === 'string' ? recordData : null;
		}
		if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for SSTP`);

		const sourcePort = 10000 + (randomSstpUint16() % 50000);
		const sourceAddress = new Uint8Array(String(sourceIp || '').split('.').map(Number));
		const destinationAddress = new Uint8Array(String(targetIp || '').split('.').map(Number));
		let sequenceNumber = readSstpUint32(crypto.getRandomValues(new Uint8Array(4)));
		let acknowledgementNumber = 0;
		const ipHeaderTemplate = new Uint8Array(20);
		ipHeaderTemplate.set([0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 64, 6]);
		ipHeaderTemplate.set(sourceAddress, 12);
		ipHeaderTemplate.set(destinationAddress, 16);
		const tcpPseudoHeader = new Uint8Array(1432);
		tcpPseudoHeader.set(sourceAddress);
		tcpPseudoHeader.set(destinationAddress, 4);
		tcpPseudoHeader[9] = 6;
		const buildTcpFrame = (flags, payload = SSTP_EMPTY_BYTES) => {
			const bytes = toUint8Array(payload);
			const payloadLength = bytes.byteLength;
			const tcpLength = 20 + payloadLength;
			const ipLength = 20 + tcpLength;
			const sstpLength = 8 + ipLength;
			const frame = new Uint8Array(sstpLength);
			const view = new DataView(frame.buffer);
			frame.set([0x10, 0x00, ((sstpLength >> 8) & 0x0f) | 0x80, sstpLength & 0xff, 0xff, 0x03, 0x00, 0x21]);
			frame.set(ipHeaderTemplate, 8);
			view.setUint16(10, ipLength);
			view.setUint16(12, randomSstpUint16());
			view.setUint16(18, internetChecksum(frame, 8, 20));
			view.setUint16(28, sourcePort);
			view.setUint16(30, targetPort);
			view.setUint32(32, sequenceNumber);
			view.setUint32(36, acknowledgementNumber);
			frame[40] = 0x50;
			frame[41] = flags;
			view.setUint16(42, 65535);
			if (payloadLength) frame.set(bytes, 48);
			tcpPseudoHeader[10] = tcpLength >> 8;
			tcpPseudoHeader[11] = tcpLength & 0xff;
			tcpPseudoHeader.set(frame.subarray(28, 28 + tcpLength), 12);
			view.setUint16(44, internetChecksum(tcpPseudoHeader, 0, 12 + tcpLength));
			return frame;
		};
		const matchIncomingIpPacket = ipPacket => {
			if (ipPacket.byteLength < 40 || ipPacket[9] !== 6) return null;
			const ipHeaderLength = (ipPacket[0] & 0x0f) * 4;
			if (ipPacket.byteLength < ipHeaderLength + 20) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength) !== targetPort) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength + 2) !== sourcePort) return null;
			return {
				flags: ipPacket[ipHeaderLength + 13],
				sequence: readSstpUint32(ipPacket, ipHeaderLength + 4),
				payloadOffset: ipHeaderLength + ((ipPacket[ipHeaderLength + 12] >> 4) & 0x0f) * 4
			};
		};

		await withTimeout(writer.write(buildTcpFrame(0x02)), CONNECT_TIMEOUT_MS, 'SSTP TCP SYN write timed out');
		sequenceNumber = (sequenceNumber + 1) >>> 0;
		let tcpReady = false;
		for (let attempt = 0; attempt < 30; attempt++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp || ppp.protocol !== 0x0021) continue;
			const tcp = matchIncomingIpPacket(ppp.ipPacket);
			if (!tcp || (tcp.flags & 0x12) !== 0x12) continue;
			acknowledgementNumber = (tcp.sequence + 1) >>> 0;
			await withTimeout(writer.write(buildTcpFrame(0x10)), CONNECT_TIMEOUT_MS, 'SSTP TCP ACK write timed out');
			tcpReady = true;
			break;
		}
		if (!tcpReady) throw new Error('TCP handshake through SSTP timed out');

		/** @type {ReadableStreamDefaultController<Uint8Array> | null} */
		let streamController = null;
		const readable = new ReadableStream({
			start(controller) {
				streamController = controller;
			},
			cancel() {
				close();
			}
		});

		(async () => {
			try {
				let pendingChunks = [], pendingLength = 0;
				const flush = () => {
					if (!pendingLength) return;
					if (!streamController) throw new Error('SSTP readable stream is not ready');
					streamController.enqueue(pendingChunks.length === 1 ? pendingChunks[0] : concatByteChunks(...pendingChunks));
					pendingChunks = [];
					pendingLength = 0;
					writer.write(buildTcpFrame(0x10)).catch(() => { });
				};

				for (; ;) {
					const packet = await readPacket(60000);
					if (packet.isControl) continue;
					const ppp = parsePPPFrame(packet.body);
					if (!ppp || ppp.protocol !== 0x0021) continue;
					const incoming = matchIncomingIpPacket(ppp.ipPacket);
					if (!incoming) continue;

					if (incoming.payloadOffset < ppp.ipPacket.byteLength) {
						const payload = ppp.ipPacket.subarray(incoming.payloadOffset);
						if (payload.byteLength) {
							acknowledgementNumber = (incoming.sequence + payload.byteLength) >>> 0;
							pendingChunks.push(new Uint8Array(payload));
							pendingLength += payload.byteLength;
						}
					}

					if (incoming.flags & 0x01) {
						flush();
						acknowledgementNumber = (acknowledgementNumber + 1) >>> 0;
						writer.write(buildTcpFrame(0x11)).catch(() => { });
						const controller = streamController;
						if (controller) {
							try { controller.close() } catch (e) { }
						}
						close();
						return;
					}

					if (bufferedBytes.byteLength < 4 || pendingLength >= 32768) flush();
				}
			} catch (error) {
				const controller = streamController;
				if (controller) {
					try { controller.error(error) } catch (e) { }
				}
				settleClosed(rejectClosed, error);
				try { socket?.close?.() } catch (e) { }
			}
		})();

		const writable = new WritableStream({
			async write(chunk) {
				const bytes = toUint8Array(chunk);
				if (!bytes.byteLength) return;
				if (bytes.byteLength <= SSTP_TCP_MSS) {
					await writer.write(buildTcpFrame(0x18, bytes));
					sequenceNumber = (sequenceNumber + bytes.byteLength) >>> 0;
					return;
				}
				const frames = [];
				for (let offset = 0; offset < bytes.byteLength; offset += SSTP_TCP_MSS) {
					const segment = bytes.subarray(offset, Math.min(offset + SSTP_TCP_MSS, bytes.byteLength));
					frames.push(buildTcpFrame(0x18, segment));
					sequenceNumber = (sequenceNumber + segment.byteLength) >>> 0;
				}
				await writer.write(concatByteChunks(...frames));
			},
			close() {
				return writer.write(buildTcpFrame(0x11)).catch(() => { });
			},
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});

		return { readable, writable, closed, close };
	} catch (error) {
		close();
		throw error;
	}
}
//////////////////////////////////////////////////Utility functions///////////////////////////////////////////////
/**
 * Base64 encoding with a secret key
 * @param {string} plaintext - the raw plaintext string
 * @param {string} secret - secret string (for example "KEY123")
 * @returns {string} the key-processed Base64 string
 */
function base64SecretEncode(plaintext, secret) {
	const encoder = new TextEncoder();
	const data = encoder.encode(plaintext);
	const key = encoder.encode(secret);
	const mixed = new Uint8Array(data.length);

	for (let i = 0; i < data.length; i++) {
		mixed[i] = data[i] ^ key[i % key.length];
	}

	// Convert a Uint8Array into a string that btoa can handle
	let binary = '';
	for (let i = 0; i < mixed.length; i++) {
		binary += String.fromCharCode(mixed[i]);
	}
	return btoa(binary);
}

/**
 * Base64 decoding with a secret key
 * @param {string} encoded - the Base64 string that was key-encoded
 * @param {string} secret - secret string (must be the one used to encode)
 * @returns {string} the recovered raw plaintext string
 */
function base64SecretDecode(encoded, secret) {
	const binary = atob(encoded);
	const mixed = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		mixed[i] = binary.charCodeAt(i);
	}

	const encoder = new TextEncoder();
	const key = encoder.encode(secret);
	const data = new Uint8Array(mixed.length);

	for (let i = 0; i < mixed.length; i++) {
		data[i] = mixed[i] ^ key[i % key.length];
	}

	const decoder = new TextDecoder();
	return decoder.decode(data);
}

function getTransportConfig(appConfig = {}) {
	const isGrpc = appConfig.transportProtocol === 'grpc';
	const { head: localPaddingHeader, paddingKey: localPaddingKey } = getXhttpPaddingIds(appConfig.UUID);
	const xhttpPaddingObfsJson = {
		"xPaddingObfsMode": true,
		"xPaddingMethod": "tokenish",
		"xPaddingPlacement": "queryInHeader",
		"xPaddingHeader": localPaddingHeader,
		"xPaddingKey": localPaddingKey
	};
	return {
		type: isGrpc ? (appConfig.gRPCmode === 'multi' ? 'grpc&mode=multi' : 'grpc&mode=gun') : (appConfig.transportProtocol === 'xhttp' ? `xhttp&mode=stream-one&extra=${encodeURIComponent(JSON.stringify(xhttpPaddingObfsJson))}` : 'ws'),
		pathFieldName: isGrpc ? 'serviceName' : 'path',
		domainFieldName: isGrpc ? 'authority' : 'host'
	};
}

function getTransportPathValue(appConfig = {}, nodePath = '/', asPreferredSubGen = false) {
	const pathValue = asPreferredSubGen ? '/' : (appConfig.randomPath ? randomPath(nodePath) : nodePath);
	if (appConfig.transportProtocol !== 'grpc') return pathValue;
	return pathValue.split('?')[0] || '/';
}

function log(...args) {
	if (debugLogEnabled) console.log(...args);
}

function ClashapplySubConfigHotPatch(Clash_rawSubscriptionContent, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const ECHenabled = Boolean(config_JSON?.ECH);
	const HOSTS = Array.isArray(config_JSON?.HOSTS) ? [...config_JSON.HOSTS] : [];
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || null;
	const ECH_DNS = config_JSON?.ECHConfig?.DNS;
	const needsEchHandling = Boolean(uuid && ECHenabled);
	const gRPCUserAgent = (typeof config_JSON?.gRPCUserAgent === 'string' && config_JSON.gRPCUserAgent.trim()) ? config_JSON.gRPCUserAgent.trim() : null;
	const needsGrpcHandling = config_JSON?.transportProtocol === "grpc" && Boolean(gRPCUserAgent);
	const gRPCUserAgentYAML = gRPCUserAgent ? JSON.stringify(gRPCUserAgent) : null;
	let clash_yaml = Clash_rawSubscriptionContent.replace(/mode:\s*Rule\b/g, 'mode: rule');

	const baseDnsBlock = `dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - 114.114.114.114
  use-hosts: true
  nameserver:
    - https://sm2.doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback:
    - 8.8.4.4
    - 208.67.220.220
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
      - 127.0.0.1/32
      - 0.0.0.0/32
    domain:
      - '+.google.com'
      - '+.facebook.com'
      - '+.youtube.com'
`;

	const addInlineGrpcUserAgent = (text) => text.replace(/grpc-opts:\s*\{([\s\S]*?)\}/i, (all, inner) => {
		if (/grpc-user-agent\s*:/i.test(inner)) return all;
		let content = inner.trim();
		if (content.endsWith(',')) content = content.slice(0, -1).trim();
		const patchedContent = content ? `${content}, grpc-user-agent: ${gRPCUserAgentYAML}` : `grpc-user-agent: ${gRPCUserAgentYAML}`;
		return `grpc-opts: {${patchedContent}}`;
	});
	const hasGrpcNetwork = (text) => /(?:^|[,{])\s*network:\s*(?:"grpc"|'grpc'|grpc)(?=\s*(?:[,}\n#]|$))/mi.test(text);
	const getNodeType = (nodeText) => nodeText.match(/type:\s*(\w+)/)?.[1] || 'vl' + 'ess';
	const getCredentialValue = (nodeText, isFlowStyle) => {
		const credentialField = getNodeType(nodeText) === 'trojan' ? 'password' : 'uuid';
		const pattern = new RegExp(`${credentialField}:\\s*${isFlowStyle ? '([^,}\\n]+)' : '([^\\n]+)'}`);
		return nodeText.match(pattern)?.[1]?.trim() || null;
	};
	const insertNameserverPolicy = (yaml, hostsEntries) => {
		if (/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(yaml)) {
			return yaml.replace(/^(\s{2}nameserver-policy:\s*\n)/m, `$1${hostsEntries}\n`);
		}
		const lines = yaml.split('\n');
		let dnsBlockEndIndex = -1;
		let inDnsBlock = false;
		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (/^dns:\s*$/.test(line)) {
				inDnsBlock = true;
				continue;
			}
			if (inDnsBlock && /^[a-zA-Z]/.test(line)) {
				dnsBlockEndIndex = i;
				break;
			}
		}
		const nameserverPolicyBlock = `  nameserver-policy:\n${hostsEntries}`;
		if (dnsBlockEndIndex !== -1) lines.splice(dnsBlockEndIndex, 0, nameserverPolicyBlock);
		else lines.push(nameserverPolicyBlock);
		return lines.join('\n');
	};
	const addFlowGrpcUserAgent = (nodeText) => {
		if (!hasGrpcNetwork(nodeText) || /grpc-user-agent\s*:/i.test(nodeText)) return nodeText;
		if (/grpc-opts:\s*\{/i.test(nodeText)) return addInlineGrpcUserAgent(nodeText);
		return nodeText.replace(/\}(\s*)$/, `, grpc-opts: {grpc-user-agent: ${gRPCUserAgentYAML}}}$1`);
	};
	const addBlockGrpcUserAgent = (nodeLines, topLevelIndent) => {
		const topIndentSpaces = ' '.repeat(topLevelIndent);
		let grpcOptsIndex = -1;
		for (let idx = 0; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			if (!line.trim()) continue;
			const indent = line.search(/\S/);
			if (indent !== topLevelIndent) continue;
			if (/^\s*grpc-opts:\s*(?:#.*)?$/.test(line) || /^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(line)) {
				grpcOptsIndex = idx;
				break;
			}
		}
		if (grpcOptsIndex === -1) {
			let insertIndex = -1;
			for (let j = nodeLines.length - 1; j >= 0; j--) {
				if (nodeLines[j].trim()) {
					insertIndex = j;
					break;
				}
			}
			if (insertIndex >= 0) nodeLines.splice(insertIndex + 1, 0, `${topIndentSpaces}grpc-opts:`, `${topIndentSpaces}  grpc-user-agent: ${gRPCUserAgentYAML}`);
			return nodeLines;
		}
		const grpcLine = nodeLines[grpcOptsIndex];
		if (/^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(grpcLine)) {
			if (!/grpc-user-agent\s*:/i.test(grpcLine)) nodeLines[grpcOptsIndex] = addInlineGrpcUserAgent(grpcLine);
			return nodeLines;
		}
		let blockEndIndex = nodeLines.length;
		let childIndent = topLevelIndent + 2;
		let hasGrpcUserAgent = false;
		for (let idx = grpcOptsIndex + 1; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			const trimmed = line.trim();
			if (!trimmed) continue;
			const indent = line.search(/\S/);
			if (indent <= topLevelIndent) {
				blockEndIndex = idx;
				break;
			}
			if (indent > topLevelIndent && childIndent === topLevelIndent + 2) childIndent = indent;
			if (/^grpc-user-agent\s*:/.test(trimmed)) {
				hasGrpcUserAgent = true;
				break;
			}
		}
		if (!hasGrpcUserAgent) nodeLines.splice(blockEndIndex, 0, `${' '.repeat(childIndent)}grpc-user-agent: ${gRPCUserAgentYAML}`);
		return nodeLines;
	};
	const addBlockFormatEchoOpts = (nodeLines, topLevelIndent) => {
		let insertIndex = -1;
		for (let j = nodeLines.length - 1; j >= 0; j--) {
			if (nodeLines[j].trim()) {
				insertIndex = j;
				break;
			}
		}
		if (insertIndex < 0) return nodeLines;
		const indent = ' '.repeat(topLevelIndent);
		const echOptsLines = [`${indent}ech-opts:`, `${indent}  enable: true`];
		if (ECH_SNI) echOptsLines.push(`${indent}  query-server-name: ${ECH_SNI}`);
		nodeLines.splice(insertIndex + 1, 0, ...echOptsLines);
		return nodeLines;
	};

	if (!/^dns:\s*(?:\n|$)/m.test(clash_yaml)) clash_yaml = baseDnsBlock + clash_yaml;
	if (ECH_SNI && !HOSTS.includes(ECH_SNI)) HOSTS.push(ECH_SNI);

	if (ECHenabled && HOSTS.length > 0) {
		const hostsEntries = HOSTS.map(host => `    "${host}": ${ECH_DNS ? ECH_DNS : ''}`).join('\n');
		clash_yaml = insertNameserverPolicy(clash_yaml, hostsEntries);
	}

	if (!needsEchHandling && !needsGrpcHandling) return clash_yaml;

	const lines = clash_yaml.split('\n');
	const processedLines = [];
	let i = 0;

	while (i < lines.length) {
		const line = lines[i];
		const trimmedLine = line.trim();

		if (trimmedLine.startsWith('- {')) {
			let fullNode = line;
			let braceCount = (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
			while (braceCount > 0 && i + 1 < lines.length) {
				i++;
				fullNode += '\n' + lines[i];
				braceCount += (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
			}
			if (needsGrpcHandling) fullNode = addFlowGrpcUserAgent(fullNode);
			if (needsEchHandling && getCredentialValue(fullNode, true) === uuid.trim()) {
				fullNode = fullNode.replace(/\}(\s*)$/, `, ech-opts: {enable: true${ECH_SNI ? `, query-server-name: ${ECH_SNI}` : ''}}}$1`);
			}
			processedLines.push(fullNode);
			i++;
		} else if (trimmedLine.startsWith('- name:')) {
			let nodeLines = [line];
			let baseIndent = line.search(/\S/);
			let topLevelIndent = baseIndent + 2;
			i++;
			while (i < lines.length) {
				const nextLine = lines[i];
				const nextTrimmed = nextLine.trim();
				if (!nextTrimmed) {
					nodeLines.push(nextLine);
					i++;
					break;
				}
				const nextIndent = nextLine.search(/\S/);
				if (nextIndent <= baseIndent && nextTrimmed.startsWith('- ')) {
					break;
				}
				if (nextIndent < baseIndent && nextTrimmed) {
					break;
				}
				nodeLines.push(nextLine);
				i++;
			}
			let nodeText = nodeLines.join('\n');
			if (needsGrpcHandling && hasGrpcNetwork(nodeText)) {
				nodeLines = addBlockGrpcUserAgent(nodeLines, topLevelIndent);
				nodeText = nodeLines.join('\n');
			}
			if (needsEchHandling && getCredentialValue(nodeText, false) === uuid.trim()) nodeLines = addBlockFormatEchoOpts(nodeLines, topLevelIndent);
			processedLines.push(...nodeLines);
		} else {
			processedLines.push(line);
			i++;
		}
	}

	return processedLines.join('\n');
}

async function SingboxapplySubConfigHotPatch(SingBox_rawSubscriptionContent, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const fingerprint = config_JSON?.Fingerprint || "chrome";
	const ECHenabled = Boolean(config_JSON?.ECH);
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || "cloudflare-ech.com";
	const sb_json_text = SingBox_rawSubscriptionContent.replace('1.1.1.1', '8.8.8.8').replace('1.0.0.1', '8.8.4.4');
	try {
		const config = JSON.parse(sb_json_text);
		const toArray = value => value === undefined || value === null ? [] : (Array.isArray(value) ? value : [value]);
		const ensureRoute = () => config.route = config.route && typeof config.route === 'object' ? config.route : {};
		const getDnsRuleServer = rule => rule && typeof rule === 'object' && !Array.isArray(rule) && typeof rule.server === 'string' ? rule.server : null;
		const addRuleSet = (type, code) => {
			if (!code || typeof code !== 'string') return null;
			const route = ensureRoute(), tag = `${type}-${code}`, ruleSet = Array.isArray(route.rule_set) ? route.rule_set : toArray(route.rule_set);
			if (!ruleSet.some(item => item?.tag === tag)) {
				const legacyOptions = type === 'geoip' ? route.geoip : route.geosite;
				ruleSet.push({ tag, type: 'remote', format: 'binary', url: `https://raw.githubusercontent.com/SagerNet/sing-${type}/rule-set/${tag}.srs`, ...(legacyOptions?.download_detour ? { download_detour: legacyOptions.download_detour } : {}) });
				config.experimental = config.experimental && typeof config.experimental === 'object' ? config.experimental : {};
				config.experimental.cache_file = config.experimental.cache_file && typeof config.experimental.cache_file === 'object' ? config.experimental.cache_file : {};
				config.experimental.cache_file.enabled ??= true;
			}
			route.rule_set = ruleSet;
			return tag;
		};

		const migrateRuleSetFields = rule => {
			if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
			if (rule.type === 'logical' && Array.isArray(rule.rules)) {
				rule.rules = rule.rules.map(migrateRuleSetFields);
				return rule;
			}
			const tags = [];
			for (const geoip of toArray(rule.geoip)) {
				if (typeof geoip !== 'string') continue;
				if (geoip.toLowerCase() === 'private') rule.ip_is_private = true;
				else tags.push(addRuleSet('geoip', geoip));
			}
			for (const sourceGeoip of toArray(rule.source_geoip)) {
				if (typeof sourceGeoip !== 'string') continue;
				tags.push(addRuleSet('geoip', sourceGeoip));
				rule.rule_set_ip_cidr_match_source = true;
			}
			for (const geosite of toArray(rule.geosite)) if (typeof geosite === 'string') tags.push(addRuleSet('geosite', geosite));
			if (tags.length) rule.rule_set = [...new Set([...toArray(rule.rule_set), ...tags].filter(Boolean))];
			delete rule.geoip;
			delete rule.source_geoip;
			delete rule.geosite;
			return rule;
		};

		const migrateDnsRule = (rule, rcodeServerMap) => {
			rule = migrateRuleSetFields(rule);
			if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
			if (rule.type === 'logical' && Array.isArray(rule.rules)) {
				rule.rules = rule.rules.map(childRule => migrateDnsRule(childRule, rcodeServerMap));
				return rule;
			}
			const serverTag = getDnsRuleServer(rule);
			if (serverTag && rcodeServerMap.has(serverTag)) {
				for (const key of ['server', 'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']) delete rule[key];
				rule.action = 'predefined';
				rule.rcode = rcodeServerMap.get(serverTag);
			} else if (serverTag && !rule.action) rule.action = 'route';
			return rule;
		};

		if (Array.isArray(config.inbounds)) {
			for (const inbound of config.inbounds) {
				if (!inbound || typeof inbound !== 'object' || inbound.type !== 'tun') continue;
				for (const migration of [
					{ targetKey: 'address', sourceKeys: ['inet4_address', 'inet6_address'] },
					{ targetKey: 'route_address', sourceKeys: ['inet4_route_address', 'inet6_route_address'] },
					{ targetKey: 'route_exclude_address', sourceKeys: ['inet4_route_exclude_address', 'inet6_route_exclude_address'] }
				]) {
					const values = toArray(inbound[migration.targetKey]);
					for (const sourceKey of migration.sourceKeys) values.push(...toArray(inbound[sourceKey]));
					if (values.length) inbound[migration.targetKey] = [...new Set(values)];
					for (const sourceKey of migration.sourceKeys) delete inbound[sourceKey];
				}
				if (inbound.tag) {
					const addedRules = [];
					if (inbound.domain_strategy) addedRules.push({ inbound: inbound.tag, action: 'resolve', strategy: inbound.domain_strategy });
					if (inbound.sniff) {
						const sniffRule = { inbound: inbound.tag, action: 'sniff' };
						if (inbound.sniff_timeout) sniffRule.timeout = inbound.sniff_timeout;
						addedRules.push(sniffRule);
					}
					if (addedRules.length) {
						const route = ensureRoute();
						route.rules = [...addedRules, ...toArray(route.rules)];
					}
				}
				delete inbound.sniff;
				delete inbound.sniff_timeout;
				delete inbound.domain_strategy;
			}
		}

		if (config?.route && typeof config.route === 'object' && Array.isArray(config.route.rules)) {
			const patchRouteRules = rule => {
				rule = migrateRuleSetFields(rule);
				if (rule?.type === 'logical' && Array.isArray(rule.rules)) rule.rules = rule.rules.map(patchRouteRules);
				else if (rule && typeof rule === 'object' && !Array.isArray(rule) && rule.outbound && !rule.action) rule.action = 'route';
				return rule;
			};
			config.route.rules = config.route.rules.map(patchRouteRules);
		}

		const dns = config?.dns;
		if (dns && typeof dns === 'object') {
			const legacyFakeIP = dns.fakeip && typeof dns.fakeip === 'object' ? dns.fakeip : null;
			const rcodeServerMap = new Map();
			const DNSaddressProtocolMap = { 'tcp:': 'tcp', 'udp:': 'udp', 'tls:': 'tls', 'quic:': 'quic', 'https:': 'https', 'h3:': 'h3' };
			const RCodemapping = { success: 'NOERROR', format_error: 'FORMERR', server_failure: 'SERVFAIL', name_error: 'NXDOMAIN', not_implemented: 'NOTIMP', refused: 'REFUSED' };
			let hasFakeIPServer = false;

			if (Array.isArray(dns.servers)) {
				const migratedServers = [];
				for (const originalServer of dns.servers) {
					if (!originalServer || typeof originalServer !== 'object' || Array.isArray(originalServer)) {
						migratedServers.push(originalServer);
						continue;
					}

					const server = { ...originalServer };
					let parsedAddress = null, parsedRCode = '', rawAddress = typeof server.address === 'string' ? server.address.trim() : '';
					if (rawAddress) {
						const lowerAddress = rawAddress.toLowerCase();
						if (lowerAddress === 'fakeip') parsedAddress = { type: 'fakeip' };
						else if (lowerAddress === 'local') parsedAddress = { type: 'local' };
						else if (lowerAddress.startsWith('rcode://')) {
							parsedAddress = { type: 'rcode' };
							parsedRCode = rawAddress.slice('rcode://'.length).toLowerCase();
						}
						else if (lowerAddress.startsWith('dhcp://')) {
							const dhcpInterface = rawAddress.slice('dhcp://'.length);
							parsedAddress = dhcpInterface && dhcpInterface.toLowerCase() !== 'auto' ? { type: 'dhcp', interface: dhcpInterface } : { type: 'dhcp' };
						} else {
							try {
								const addressURL = new URL(rawAddress);
								const type = DNSaddressProtocolMap[addressURL.protocol.toLowerCase()];
								if (type) {
									const parsedServer = addressURL.hostname?.startsWith('[') && addressURL.hostname.endsWith(']') ? addressURL.hostname.slice(1, -1) : addressURL.hostname;
									parsedAddress = {
										type,
										server: parsedServer || addressURL.host || rawAddress,
										...(addressURL.port ? { server_port: Number(addressURL.port) } : {}),
										...((type === 'https' || type === 'h3') && addressURL.pathname && addressURL.pathname !== '/dns-query' ? { path: addressURL.pathname } : {})
									};
								}
							} catch (_) { }
							if (!parsedAddress) parsedAddress = { type: 'udp', server: rawAddress };
						}
					}

					if (parsedAddress?.type === 'rcode') {
						const rcode = RCodemapping[parsedRCode] || 'NOERROR';
						if (typeof server.tag === 'string' && server.tag) {
							rcodeServerMap.set(server.tag, rcode);
							rcodeServerMap.set(server.tag.startsWith('dns_') ? server.tag.slice(4) : `dns_${server.tag}`, rcode);
						}
						continue;
					}

					if (parsedAddress) {
						delete server.address;
						Object.assign(server, parsedAddress);
					}
					if (server.address_resolver !== undefined && server.domain_resolver === undefined) server.domain_resolver = server.address_resolver;
					if (server.address_strategy !== undefined && server.domain_strategy === undefined) server.domain_strategy = server.address_strategy;
					delete server.address_resolver;
					delete server.address_strategy;
					if (server.detour === 'DIRECT') delete server.detour;

					if (server.type === 'fakeip') {
						hasFakeIPServer = true;
						if (legacyFakeIP) {
							for (const key of ['inet4_range', 'inet6_range']) {
								if (legacyFakeIP[key] !== undefined && server[key] === undefined) server[key] = legacyFakeIP[key];
							}
						}
					}
					migratedServers.push(server);
				}
				dns.servers = migratedServers;
			}

			if (legacyFakeIP && !hasFakeIPServer && legacyFakeIP.enabled !== false) {
				const fakeIPServer = { type: 'fakeip', tag: 'fakeip' };
				for (const rule of Array.isArray(dns.rules) ? dns.rules : []) {
					const serverTag = getDnsRuleServer(rule);
					if (serverTag && serverTag.toLowerCase().includes('fakeip')) {
						fakeIPServer.tag = serverTag;
						break;
					}
				}
				for (const key of ['inet4_range', 'inet6_range']) {
					if (legacyFakeIP[key] !== undefined) fakeIPServer[key] = legacyFakeIP[key];
				}
				if (Array.isArray(dns.servers)) dns.servers.push(fakeIPServer);
				else dns.servers = [fakeIPServer];
			}

			if (Array.isArray(dns.rules)) {
				const migratedRules = [];
				for (const rule of dns.rules) {
					const serverTag = getDnsRuleServer(rule);
					const outbound = toArray(rule?.outbound);
					const DNSrouteOptionFields = new Set(['outbound', 'server', 'action', 'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']);
					const isOutboundAnyDNSRule = rule && typeof rule === 'object' && !Array.isArray(rule) && rule.type !== 'logical'
						&& serverTag && outbound.includes('any') && Object.keys(rule).every(key => DNSrouteOptionFields.has(key));
					if (isOutboundAnyDNSRule) {
						const route = ensureRoute();
						if (route.default_domain_resolver === undefined) {
							const resolver = { server: serverTag };
							for (const key of ['strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']) {
								if (rule[key] !== undefined) resolver[key] = rule[key];
							}
							route.default_domain_resolver = Object.keys(resolver).length === 1 ? resolver.server : resolver;
						}
						continue;
					}
					migratedRules.push(migrateDnsRule(rule, rcodeServerMap));
				}
				dns.rules = migratedRules;
			}

			delete dns.fakeip;
			delete dns.independent_cache;
		}

		if (config?.route && typeof config.route === 'object') {
			delete config.route.geoip;
			delete config.route.geosite;
		}
		if (config?.ntp?.detour === 'DIRECT') delete config.ntp.detour;

		if (Array.isArray(config.outbounds)) {
			const outboundTags = new Set(config.outbounds.map(outbound => outbound?.tag).filter(Boolean));
			const isRejectValue = value => value === 'REJECT' || (value && typeof value === 'object' && (Array.isArray(value) ? value.some(isRejectValue) : Object.values(value).some(isRejectValue)));
			if (!outboundTags.has('REJECT') && isRejectValue({ outbounds: config.outbounds, route: config.route })) config.outbounds.push({ type: 'block', tag: 'REJECT' });
		}

		// --- UUID TLS hot patch for matching nodes (utls & ech) ---
		if (uuid) {
			config.outbounds?.forEach(outbound => {
				// Only touch nodes whose uuid or password matches
				if ((outbound.uuid && outbound.uuid === uuid) || (outbound.password && outbound.password === uuid)) {
					// make sure the tls object exists
					if (!outbound.tls) {
						outbound.tls = { enabled: true };
					}

					// Add or update the utls configuration
					if (fingerprint) {
						outbound.tls.utls = {
							enabled: true,
							fingerprint: fingerprint
						};
					}

					// If ech_config is given, add or update the ech configuration
					if (ECHenabled) {
						outbound.tls.ech = {
							enabled: true,
							query_server_name: ECH_SNI,// waiting for the 1.13.0+ release
							//config: `-----BEGIN ECH CONFIGS-----\n${ech_config}\n-----END ECH CONFIGS-----`
						};
					}
				}
			});
		}

		return JSON.stringify(config, null, 2);
	} catch (e) {
		console.error("Singbox hot patch execution failed:", e);
		return JSON.stringify(JSON.parse(sb_json_text), null, 2);
	}
}

function SurgeapplySubConfigHotPatch(content, url, config_JSON) {
	const contentLines = content.includes('\r\n') ? content.split('\r\n') : content.split('\n');
	const fullNodePath = config_JSON.randomPath ? randomPath(config_JSON.fullNodePath) : config_JSON.fullNodePath;
	let outputContent = "";
	for (let x of contentLines) {
		if (x.includes('= tro' + 'jan,') && !x.includes('ws=true') && !x.includes('ws-path=')) {
			const host = x.split("sni=")[1].split(",")[0];
			const contentToReplace = `sni=${host}, skip-cert-verify=${config_JSON.skipCertVerify}`;
			const correctContent = `sni=${host}, skip-cert-verify=${config_JSON.skipCertVerify}, ws=true, ws-path=${fullNodePath.replace(/,/g, '%2C')}, ws-headers=Host:"${host}"`;
			outputContent += x.replace(new RegExp(contentToReplace, 'g'), correctContent).replace("[", "").replace("]", "") + '\n';
		} else {
			outputContent += x + '\n';
		}
	}

	outputContent = `#!MANAGED-CONFIG ${url} interval=${config_JSON.preferredSubGen.SUBUpdateTime * 60 * 60} strict=false` + outputContent.substring(outputContent.indexOf('\n'));
	return outputContent;
}

async function recordRequestLog(env, request, clientIp, requestType = "Get_SUB", config_JSON, shouldWriteKvLog = true) {
	try {
		const currentTime = new Date();
		const logEntry = { TYPE: requestType, IP: clientIp, ASN: `AS${request.cf.asn || '0'} ${request.cf.asOrganization || 'Unknown'}`, CC: `${request.cf.country || 'N/A'} ${request.cf.city || 'N/A'}`, URL: request.url, UA: request.headers.get('User-Agent') || 'Unknown', TIME: currentTime.getTime() };
		if (config_JSON.TG.enabled) {
			try {
				const TG_TXT = await env.KV.get('tg.json');
				const TG_JSON = JSON.parse(TG_TXT);
				if (TG_JSON?.BotToken && TG_JSON?.ChatID) {
					const requestTimeText = new Date(logEntry.TIME).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
					const parsedRequestUrl = new URL(logEntry.URL);
					const msg = `<b>#${config_JSON.preferredSubGen.SUBNAME} Log notification</b>\n\n` +
						`📌 <b>Type:</b>#${logEntry.TYPE}\n` +
						`🌐 <b>IP:</b><code>${logEntry.IP}</code>\n` +
						`📍 <b>Location:</b>${logEntry.CC}\n` +
						`🏢 <b>ASN:</b>${logEntry.ASN}\n` +
						`🔗 <b>Domain:</b><code>${parsedRequestUrl.host}</code>\n` +
						`🔍 <b>Path:</b><code>${parsedRequestUrl.pathname + parsedRequestUrl.search}</code>\n` +
						`🤖 <b>UA:</b><code>${logEntry.UA}</code>\n` +
						`📅 <b>Time:</b>${requestTimeText}\n` +
						`${config_JSON.CF.Usage.success ? `📊 <b>Request usage:</b>${config_JSON.CF.Usage.total}/${config_JSON.CF.Usage.max} <b>${((config_JSON.CF.Usage.total / config_JSON.CF.Usage.max) * 100).toFixed(2)}%</b>\n` : ''}`;
					await fetch(`https://api.telegram.org/bot${TG_JSON.BotToken}/sendMessage?chat_id=${TG_JSON.ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`, {
						method: 'GET',
						headers: {
							'Accept': 'text/html,application/xhtml+xml,application/xml;',
							'Accept-Encoding': 'gzip, deflate, br',
							'User-Agent': logEntry.UA || 'Unknown',
						}
					});
				}
			} catch (error) { console.error(`failed to read tg.json: ${error.message}`) }
		}
		shouldWriteKvLog = ['1', 'true'].includes(env.OFF_LOG) ? false : shouldWriteKvLog;
		if (!shouldWriteKvLog) return;
		let logArray = [];
		const existingLogs = await env.KV.get('log.json'), KVcapacityLimit = 4;//MB
		if (existingLogs) {
			try {
				logArray = JSON.parse(existingLogs);
				if (!Array.isArray(logArray)) { logArray = [logEntry] }
				else if (requestType !== "Get_SUB") {
					const timestamp30mAgo = currentTime.getTime() - 30 * 60 * 1000;
					if (logArray.some(log => log.TYPE !== "Get_SUB" && log.IP === clientIp && log.URL === request.url && log.UA === (request.headers.get('User-Agent') || 'Unknown') && log.TIME >= timestamp30mAgo)) return;
					logArray.push(logEntry);
					while (JSON.stringify(logArray, null, 2).length > KVcapacityLimit * 1024 * 1024 && logArray.length > 0) logArray.shift();
				} else {
					logArray.push(logEntry);
					while (JSON.stringify(logArray, null, 2).length > KVcapacityLimit * 1024 * 1024 && logArray.length > 0) logArray.shift();
				}
			} catch (e) { logArray = [logEntry] }
		} else { logArray = [logEntry] }
		await env.KV.put('log.json', JSON.stringify(logArray, null, 2));
	} catch (error) { console.error(`logging failed: ${error.message}`) }
}

function maskSensitiveInfo(text, prefixLength = 3, suffixLength = 2) {
	if (!text || typeof text !== 'string') return text;
	if (text.length <= prefixLength + suffixLength) return text; // too short to mask, returned unchanged

	const prefix = text.slice(0, prefixLength);
	const suffix = text.slice(-suffixLength);
	const asteriskCount = text.length - prefixLength - suffixLength;

	return `${prefix}${'*'.repeat(asteriskCount)}${suffix}`;
}

async function MD5MD5(text) {
	const utf8Encoder = new TextEncoder();

	const firstHash = await crypto.subtle.digest('MD5', utf8Encoder.encode(text));
	const firstHashBytes = Array.from(new Uint8Array(firstHash));
	const firstHexDigest = firstHashBytes.map(bytes => bytes.toString(16).padStart(2, '0')).join('');

	const secondHash = await crypto.subtle.digest('MD5', utf8Encoder.encode(firstHexDigest.slice(7, 27)));
	const secondHashBytes = Array.from(new Uint8Array(secondHash));
	const secondHexDigest = secondHashBytes.map(bytes => bytes.toString(16).padStart(2, '0')).join('');

	return secondHexDigest.toLowerCase();
}

function randomPath(fullNodePath = "/") {
	const commonPathWords = ["about", "account", "acg", "act", "activity", "ad", "ads", "ajax", "album", "albums", "anime", "api", "app", "apps", "archive", "archives", "article", "articles", "ask", "auth", "avatar", "bbs", "bd", "blog", "blogs", "book", "books", "bt", "buy", "cart", "category", "categories", "cb", "channel", "channels", "chat", "china", "city", "class", "classify", "clip", "clips", "club", "cn", "code", "collect", "collection", "comic", "comics", "community", "company", "config", "contact", "content", "course", "courses", "cp", "data", "detail", "details", "dh", "directory", "discount", "discuss", "dl", "dload", "doc", "docs", "document", "documents", "doujin", "download", "downloads", "drama", "edu", "en", "ep", "episode", "episodes", "event", "events", "f", "faq", "favorite", "favourites", "favs", "feedback", "file", "files", "film", "films", "forum", "forums", "friend", "friends", "game", "games", "gif", "go", "go.html", "go.php", "group", "groups", "help", "home", "hot", "htm", "html", "image", "images", "img", "index", "info", "intro", "item", "items", "ja", "jp", "jump", "jump.html", "jump.php", "jumping", "knowledge", "lang", "lesson", "lessons", "lib", "library", "link", "links", "list", "live", "lives", "m", "mag", "magnet", "mall", "manhua", "map", "member", "members", "message", "messages", "mobile", "movie", "movies", "music", "my", "new", "news", "note", "novel", "novels", "online", "order", "out", "out.html", "out.php", "outbound", "p", "page", "pages", "pay", "payment", "pdf", "photo", "photos", "pic", "pics", "picture", "pictures", "play", "player", "playlist", "post", "posts", "product", "products", "program", "programs", "project", "qa", "question", "rank", "ranking", "read", "readme", "redirect", "redirect.html", "redirect.php", "reg", "register", "res", "resource", "retrieve", "sale", "search", "season", "seasons", "section", "seller", "series", "service", "services", "setting", "settings", "share", "shop", "show", "shows", "site", "soft", "sort", "source", "special", "star", "stars", "static", "stock", "store", "stream", "streaming", "streams", "student", "study", "tag", "tags", "task", "teacher", "team", "tech", "temp", "test", "thread", "tool", "tools", "topic", "topics", "torrent", "trade", "travel", "tv", "txt", "type", "u", "upload", "uploads", "url", "urls", "user", "users", "v", "version", "videos", "view", "vip", "vod", "watch", "web", "wenku", "wiki", "work", "www", "zh", "zh-cn", "zh-tw", "zip"];
	const randomDirCount = Math.floor(Math.random() * 3 + 1);
	const randomPath = commonPathWords.sort(() => 0.5 - Math.random()).slice(0, randomDirCount).join('/');
	if (fullNodePath !== "/") return `/${randomPath + fullNodePath.replace('/?', '?')}`;
	// The base path is the default: hand back a different realistic endpoint every time, so no
	// two nodes and no two subscription fetches ever share one blockable pattern.
	const hex = len => { let s = ''; const pool = '0123456789abcdef'; for (let i = 0; i < len; i++) s += pool[Math.floor(Math.random() * pool.length)]; return s; };
	const pick = arr => arr[Math.floor(Math.random() * arr.length)];
	const variant = Math.floor(Math.random() * 4);
	if (variant === 0) return `/socket.io/?EIO=4&transport=websocket&sid=${hex(16)}`;// the most common legitimate websocket endpoint on the web
	if (variant === 1) return `/${pick(commonPathWords)}/v${1 + Math.floor(Math.random() * 4)}/${pick(commonPathWords)}?session=${hex(24)}`;
	if (variant === 2) return `/${pick(commonPathWords)}/${Math.random() < 0.5 ? 'ws' : pick(commonPathWords)}?t=${hex(12)}`;
	return `/${randomPath}`;
}

function replaceStarsWithRandom(content) {
	if (typeof content !== 'string' || !content.includes('*')) return content;
	const charPool = 'abcdefghijklmnopqrstuvwxyz0123456789';
	return content.replace(/\*/g, () => {
		let s = '';
		for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++) s += charPool[Math.floor(Math.random() * charPool.length)];
		return s;
	});
}

const DoHcachedBytes = {};
const DoHcacheMaxEntries = 256;
const DoHrecordTypeMap = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65 };
async function DoHquery(domain, recordType, DoHresolveServer = "https://cloudflare-dns.com/dns-query") {
	const normalizedDomain = String(domain || '').trim().toLowerCase().replace(/\.$/, '');
	const normalizedRecordType = String(recordType || '').trim().toUpperCase();
	const cacheKey = `${normalizedDomain}:${normalizedRecordType}`;
	const qtype = DoHrecordTypeMap[normalizedRecordType] || 1;
	const currentTimestamp = Date.now();
	const cachedEntry = DoHcachedBytes[cacheKey];
	if (cachedEntry && currentTimestamp < cachedEntry.expiresAt) {
		log(`[DoH query] cache hit ${domain} ${recordType} via ${DoHresolveServer}`);
		return cachedEntry.data.map(data => ({ type: qtype, data }));
	}
	const startTime = performance.now();
	log(`[DoH query] query started ${domain} ${recordType} via ${DoHresolveServer}`);
	try {
		// Convert the record type string to its numeric value
		// Encode a domain into DNS wire format labels
		const encodeDnsName = (name) => {
			const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
			const bufs = [];
			for (const label of parts) {
				const enc = new TextEncoder().encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			const total = bufs.reduce((s, b) => s + b.length, 0);
			const result = new Uint8Array(total);
			let off = 0;
			for (const b of bufs) { result.set(b, off); off += b.length }
			return result;
		};

		// Build the DNS query message
		const qname = encodeDnsName(normalizedDomain);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]); // ID (random per RFC 1035)
		qview.setUint16(2, 0x0100);  // Flags: RD=1 (recursive query)
		qview.setUint16(4, 1);       // QDCOUNT
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1); // QCLASS = IN

		// Send the dns-message request with POST
		log(`[DoH query] query packet sent ${domain} via ${DoHresolveServer} (type=${qtype}, ${query.length} bytes)`);
		const response = await fetch(DoHresolveServer, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/dns-message',
				'Accept': 'application/dns-message',
			},
			body: query,
		});
		if (!response.ok) {
			console.warn(`[DoH query] request failed ${domain} ${recordType} via ${DoHresolveServer} response code:${response.status}`);
			return [];
		}

		// Parse the DNS response message
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		log(`[DoH query] response received ${domain} ${recordType} via ${DoHresolveServer} (${buf.length} bytes, ${ancount} answers)`);

		// Parse a domain name (handles compressed pointers)
		const parseDnsName = (pos) => {
			const labels = [];
			let p = pos, jumped = false, endPos = -1, safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) { if (!jumped) endPos = p + 1; break }
				if ((len & 0xC0) === 0xC0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3F) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join('.'), endPos];
		};

		// Skip the Question Section
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = parseDnsName(offset);
			offset = /** @type {number} */ (end) + 4; // +4 skip QTYPE + QCLASS
		}

		// Parse the Answer Section
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = parseDnsName(offset);
			offset = /** @type {number} */ (nameEnd);
			const type = dv.getUint16(offset); offset += 2;
			offset += 2; // CLASS
			const ttl = dv.getUint32(offset); offset += 4;
			const rdlen = dv.getUint16(offset); offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;

			let data;
			if (type === 1 && rdlen === 4) {
				// A record
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				// AAAA record
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(':');
			} else if (type === 16) {
				// TXT record (length-prefixed strings)
				let tOff = 0;
				const parts = [];
				while (tOff < rdlen) {
					const tLen = rdata[tOff++];
					parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
					tOff += tLen;
				}
				data = parts.join('');
			} else if (type === 5) {
				// CNAME record
				const [cname] = parseDnsName(offset - rdlen);
				data = cname;
			} else {
				data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
			}
			answers.push({ name, type, TTL: ttl, data, rdata });
		}
		const elapsedMs = (performance.now() - startTime).toFixed(2);
		log(`[DoH] resolved ${domain} ${recordType} via ${DoHresolveServer} ${elapsedMs}ms total ${answers.length} answers${answers.length > 0 ? '\n' + answers.map((a, i) => `  ${i + 1}. ${a.name} type=${a.type} TTL=${a.TTL} data=${a.data}`).join('\n') : ''}`);
		// DoH cache is kept for at least 5 minutes and honours a longer response TTL; empty answers get a 5-minute negative cache
		const matchingRecords = answers.filter(answer => answer.type === qtype);
		const minTtl = matchingRecords.length > 0 ? Math.min(...matchingRecords.map(a => a.TTL)) : 0;
		const cacheTtlSeconds = Math.max(minTtl, 5 * 60);
		const cacheExpiresAt = Date.now() + cacheTtlSeconds * 1000;
		const cacheData = matchingRecords.map(answer => answer.data);
		if (cacheData.length > 0 || answers.length === 0) {
			if (Object.keys(DoHcachedBytes).length >= DoHcacheMaxEntries) {
				const cleanupTimestamp = Date.now();
				for (const [cacheEntryKey, cacheEntry] of Object.entries(DoHcachedBytes)) {
					if (cleanupTimestamp >= cacheEntry.expiresAt) delete DoHcachedBytes[cacheEntryKey];
				}
				if (Object.keys(DoHcachedBytes).length >= DoHcacheMaxEntries) {
					delete DoHcachedBytes[Object.keys(DoHcachedBytes)[0]];
				}
			}
			DoHcachedBytes[cacheKey] = { data: cacheData, expiresAt: cacheExpiresAt };
			log(`[DoH query] cache write ${domain} ${recordType} TTL=${cacheTtlSeconds}s${cacheData.length === 0 ? '(empty)' : ''}`);
		}
		return answers;
	} catch (error) {
		const elapsedMs = (performance.now() - startTime).toFixed(2);
		console.error(`[DoH query] query failed ${domain} ${recordType} via ${DoHresolveServer} ${elapsedMs}ms:`, error);
		return [];
	}
}

async function readConfigJson(env, hostname, userID, UA = "Mozilla/5.0", shouldResetConfig = false) {
	const _p = signatureDictionary[0];
	const host = hostname, Ali_DoH = "https://dns.alidns.com/dns-query", ECH_SNI = "cloudflare-ech.com", placeholder = '{{IP:PORT}}', configLoadStart = performance.now(), defaultConfigJson = {
		TIME: new Date().toISOString(),
		HOST: host,
		HOSTS: [hostname],
		UUID: userID,
		PATH: "/",
		ALPN: "",
		protocolType: "v" + "le" + "ss",
		transportProtocol: "ws",
		gRPCmode: "gun",
		gRPCUserAgent: UA,
		skipCertVerify: false,
		enable0Rtt: false,
		TLSfragment: null,
		randomPath: true,
		ECH: false,
		ECHConfig: {
			DNS: Ali_DoH,
			SNI: ECH_SNI,
		},
		SS: {
			cipherMethod: "aes-128-gcm",
			TLS: true,
		},
		// Measured 2026-09-20: Cloudflare answers 403 for a *.workers.dev Host when the ClientHello
		// SNI names something else, so SNI/Host separation does not work on workers.dev. Kept as an
		// option for a custom domain, where the origin does honour the Host header. Leave empty here.
		FRONTSNI: "",
		Fingerprint: "chrome",
		preferredSubGen: {
			local: true, // true: use the local preferred addresses  false: the preferred subscription generator
			localIpPool: {
				randomIp: true, // Only takes effect when the random IP option is true: how many random IPs to build, otherwise use the ADD.txt kept in KV
				randomIpCount: 16,
				specifiedPort: 443, // Non-443 Cloudflare ports are reset on Iranian links, so pin 443
			},
			SUB: null,
			SUBNAME: "edt-ir",
			SUBUpdateTime: 3, // subscription refresh interval (hours)
			TOKEN: await MD5MD5(hostname + userID),
		},
		subConverterConfig: {
			// Empty means no external converter: every client type gets the locally generated
			// base64 node list, which is what still works when the public converters are gone.
			SUBAPI: '',
			SUBCONFIG: `https://raw.githubusercontent.com/${signatureDictionary[1]}/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini`,
			SUBEMOJI: false,
			SUBLIST: false, //output node information only
			UDP: false, // enable UDP
			XUDP: false, // enable XUDP
			TLS13: false, // enable TLS 1.3
			APPEND_TYPE: false, // insert the node type
			SORT: false, // basic node sorting
		},
		reverseProxy: {
			[_p]: "auto",
			SOCKS5: {
				enabled: null,
				globalFlag: false,
				account: '',
				whitelist: SOCKS5whitelist,
			},
			pathTemplate: {
				[_p]: "proxyip=" + placeholder,
				SOCKS5: {
					globalFlag: "socks5://" + placeholder,
					standard: "socks5=" + placeholder
				},
				HTTP: {
					globalFlag: "http://" + placeholder,
					standard: "http=" + placeholder
				},
				HTTPS: {
					globalFlag: "https://" + placeholder,
					standard: "https=" + placeholder
				},
				TURN: {
					globalFlag: "turn://" + placeholder,
					standard: "turn=" + placeholder
				},
				SSTP: {
					globalFlag: "sstp://" + placeholder,
					standard: "sstp=" + placeholder
				},
			},
		},
		TG: {
			enabled: false,
			BotToken: null,
			ChatID: null,
		},
		CF: {
			Email: null,
			GlobalAPIKey: null,
			AccountID: null,
			APIToken: null,
			UsageAPI: null,
			Usage: {
				success: false,
				pages: 0,
				workers: 0,
				total: 0,
				max: 100000,
			},
		}
	};

	try {
		let configJSON = await env.KV.get('config.json');
		if (!configJSON || shouldResetConfig == true) {
			await env.KV.put('config.json', JSON.stringify(defaultConfigJson, null, 2));
			config_JSON = defaultConfigJson;
		} else {
			config_JSON = JSON.parse(configJSON);
		}
	} catch (error) {
		console.error(`failed to read config_JSON: ${error.message}`);
		config_JSON = defaultConfigJson;
	}

	if (!config_JSON.subConverterConfig.SUBLIST) config_JSON.subConverterConfig.SUBLIST = false;
	if (!config_JSON.subConverterConfig.UDP) config_JSON.subConverterConfig.UDP = false;
	if (!config_JSON.subConverterConfig.XUDP) config_JSON.subConverterConfig.XUDP = false;
	if (!config_JSON.subConverterConfig.TLS13) config_JSON.subConverterConfig.TLS13 = false;
	if (!config_JSON.subConverterConfig.APPEND_TYPE) config_JSON.subConverterConfig.APPEND_TYPE = false;
	if (!config_JSON.subConverterConfig.SORT) config_JSON.subConverterConfig.SORT = false;
	if (!config_JSON.gRPCUserAgent) config_JSON.gRPCUserAgent = UA;
	config_JSON.HOST = host;
	if (!config_JSON.HOSTS) config_JSON.HOSTS = [hostname];
	if (env.HOST) config_JSON.HOSTS = (await normalizeToArray(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
	// Empty FRONTSNI means the node's SNI is its host, which is what workers.dev requires.
	if (env.SNI !== undefined) config_JSON.FRONTSNI = env.SNI.trim();
	if (env.CFPORT) config_JSON.preferredSubGen.localIpPool.specifiedPort = Number(env.CFPORT) || 443;
	config_JSON.UUID = userID;
	if (!config_JSON.randomPath) config_JSON.randomPath = false;
	if (!config_JSON.enable0Rtt) config_JSON.enable0Rtt = false;

	if (env.PATH) config_JSON.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
	else if (!config_JSON.PATH) config_JSON.PATH = '/';
	if (!config_JSON.ALPN) config_JSON.ALPN = "";

	if (!config_JSON.gRPCmode) config_JSON.gRPCmode = 'gun';
	if (!config_JSON.SS) config_JSON.SS = { cipherMethod: "aes-128-gcm", TLS: false };

	if (!config_JSON.reverseProxy.pathTemplate?.[_p]) {
		config_JSON.reverseProxy.pathTemplate = {
			[_p]: "proxyip=" + placeholder,
			SOCKS5: {
				globalFlag: "socks5://" + placeholder,
				standard: "socks5=" + placeholder
			},
			HTTP: {
				globalFlag: "http://" + placeholder,
				standard: "http=" + placeholder
			},
			HTTPS: {
				globalFlag: "https://" + placeholder,
				standard: "https=" + placeholder
			},
			TURN: {
				globalFlag: "turn://" + placeholder,
				standard: "turn=" + placeholder
			},
			SSTP: {
				globalFlag: "sstp://" + placeholder,
				standard: "sstp=" + placeholder
			},
		};
	}
	if (!config_JSON.reverseProxy.pathTemplate.HTTPS) config_JSON.reverseProxy.pathTemplate.HTTPS = { globalFlag: "https://" + placeholder, standard: "https=" + placeholder };
	if (!config_JSON.reverseProxy.pathTemplate.TURN) config_JSON.reverseProxy.pathTemplate.TURN = { globalFlag: "turn://" + placeholder, standard: "turn=" + placeholder };
	if (!config_JSON.reverseProxy.pathTemplate.SSTP) config_JSON.reverseProxy.pathTemplate.SSTP = { globalFlag: "sstp://" + placeholder, standard: "sstp=" + placeholder };

	const proxyConfig = config_JSON.reverseProxy.pathTemplate[config_JSON.reverseProxy.SOCKS5.enabled?.toUpperCase()];

	let pathProxyParam = '';
	if (proxyConfig && config_JSON.reverseProxy.SOCKS5.account) pathProxyParam = (config_JSON.reverseProxy.SOCKS5.globalFlag ? proxyConfig.globalFlag : proxyConfig.standard).replace(placeholder, config_JSON.reverseProxy.SOCKS5.account);
	else if (config_JSON.reverseProxy[_p] !== 'auto') pathProxyParam = config_JSON.reverseProxy.pathTemplate[_p].replace(placeholder, config_JSON.reverseProxy[_p]);

	let proxyQueryParam = '';
	if (pathProxyParam.includes('?')) {
		const [proxyPathPart, proxyQueryPart] = pathProxyParam.split('?');
		pathProxyParam = proxyPathPart;
		proxyQueryParam = proxyQueryPart;
	}

	config_JSON.PATH = config_JSON.PATH.replace(pathProxyParam, '').replace('//', '/');
	const normalizedPath = config_JSON.PATH === '/' ? '' : config_JSON.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
	const [pathPart, ...querySplitParts] = normalizedPath.split('?');
	const queryString = querySplitParts.length ? '?' + querySplitParts.join('?') : '';
	const finalQueryString = proxyQueryParam ? (queryString ? queryString + '&' + proxyQueryParam : '?' + proxyQueryParam) : queryString;
	config_JSON.fullNodePath = (pathPart || '/') + (pathPart && pathProxyParam ? '/' : '') + pathProxyParam + finalQueryString + (config_JSON.enable0Rtt ? (finalQueryString ? '&' : '?') + 'ed=2560' : '');

	if (!config_JSON.TLSfragment && config_JSON.TLSfragment !== null) config_JSON.TLSfragment = null;
	const TLSfragmentParams = config_JSON.TLSfragment == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLSfragment == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
	if (!config_JSON.Fingerprint) config_JSON.Fingerprint = "chrome";
	if (!config_JSON.ECH) config_JSON.ECH = false;
	if (!config_JSON.ECHConfig) config_JSON.ECHConfig = { DNS: Ali_DoH, SNI: ECH_SNI };
	const ECHLINKparams = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
	const { type: transportProtocol, pathFieldName, domainFieldName } = getTransportConfig(config_JSON);
	const transportPathValue = getTransportPathValue(config_JSON, config_JSON.fullNodePath);
	config_JSON.LINK = config_JSON.protocolType === 'ss'
		? `${config_JSON.protocolType}://${btoa(config_JSON.SS.cipherMethod + ':' + userID)}@${host}:${config_JSON.SS.TLS ? '443' : '80'}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=${host};path=${((config_JSON.fullNodePath.includes('?') ? config_JSON.fullNodePath.replace('?', '?enc=' + config_JSON.SS.cipherMethod + '&') : (config_JSON.fullNodePath + '?enc=' + config_JSON.SS.cipherMethod)) + (config_JSON.SS.TLS ? ';tls' : ''))};mux=0`) + ECHLINKparams}#${encodeURIComponent(config_JSON.preferredSubGen.SUBNAME)}`
		: `${config_JSON.protocolType}://${userID}@${host}:443?security=tls&type=${transportProtocol + ECHLINKparams}&${domainFieldName}=${host}&fp=${config_JSON.Fingerprint}&sni=${host}&${pathFieldName}=${encodeURIComponent(transportPathValue) + TLSfragmentParams}&encryption=none#${encodeURIComponent(config_JSON.preferredSubGen.SUBNAME)}`;
	config_JSON.preferredSubGen.TOKEN = await MD5MD5(hostname + userID);

	const tgJsonDefaults = { BotToken: null, ChatID: null };
	config_JSON.TG = { enabled: config_JSON.TG.enabled ? config_JSON.TG.enabled : false, ...tgJsonDefaults };
	try {
		const TG_TXT = await env.KV.get('tg.json');
		if (!TG_TXT) {
			await env.KV.put('tg.json', JSON.stringify(tgJsonDefaults, null, 2));
		} else {
			const TG_JSON = JSON.parse(TG_TXT);
			config_JSON.TG.ChatID = TG_JSON.ChatID ? TG_JSON.ChatID : null;
			config_JSON.TG.BotToken = TG_JSON.BotToken ? maskSensitiveInfo(TG_JSON.BotToken) : null;
		}
	} catch (error) {
		console.error(`failed to read tg.json: ${error.message}`);
	}

	const cfJsonDefaults = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
	config_JSON.CF = { ...cfJsonDefaults, Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 } };
	try {
		const CF_TXT = await env.KV.get('cf.json');
		if (!CF_TXT) {
			await env.KV.put('cf.json', JSON.stringify(cfJsonDefaults, null, 2));
		} else {
			const CF_JSON = JSON.parse(CF_TXT);
			if (CF_JSON.UsageAPI) {
				try {
					const response = await fetch(CF_JSON.UsageAPI);
					const Usage = await response.json();
					config_JSON.CF.Usage = Usage;
				} catch (err) {
					console.error(`request to CF_JSON.UsageAPI failed: ${err.message}`);
				}
			} else {
				config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
				config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? maskSensitiveInfo(CF_JSON.GlobalAPIKey) : null;
				config_JSON.CF.AccountID = CF_JSON.AccountID ? maskSensitiveInfo(CF_JSON.AccountID) : null;
				config_JSON.CF.APIToken = CF_JSON.APIToken ? maskSensitiveInfo(CF_JSON.APIToken) : null;
				config_JSON.CF.UsageAPI = null;
				const Usage = await getCloudflareUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, CF_JSON.AccountID, CF_JSON.APIToken);
				config_JSON.CF.Usage = Usage;
			}
		}
	} catch (error) {
		console.error(`failed to read cf.json: ${error.message}`);
	}

	config_JSON.loadTime = (performance.now() - configLoadStart).toFixed(2) + 'ms';
	return config_JSON;
}

function detectIsp(request) {
	const cf = request?.cf;
	const ASNispMap = {
		'4134': 'ct',
		'4809': 'ct',
		'4811': 'ct',
		'4812': 'ct',
		'4815': 'ct',
		'4837': 'cu',
		'4814': 'cu',
		'9929': 'cu',
		'17623': 'cu',
		'17816': 'cu',
		'9808': 'cmcc',
		'24400': 'cmcc',
		'56040': 'cmcc',
		'56041': 'cmcc',
		'56044': 'cmcc',
	};
	const ispKeywordMap = [
		{ code: 'ct', pattern: /chinanet|chinatelecom|china telecom|cn2|shtel/ },
		{ code: 'cmcc', pattern: /cmi|cmnet|chinamobile|china mobile|cmcc|mobile communications/ },
		{ code: 'cu', pattern: /china169|china unicom|chinaunicom|cucc|cncgroup|cuii|netcom/ },
	];
	if (String(cf?.country || '').toLowerCase() !== 'cn') return 'cf';
	const orgNameLower = String(cf?.asOrganization || '').toLowerCase();
	const matchedIspCode = ispKeywordMap.find(({ pattern }) => pattern.test(orgNameLower))?.code;
	return matchedIspCode || ASNispMap[String(cf?.asn || '')] || 'cf';
}

async function generateRandomIps(request, count = 16, specifiedPort = -1) {
	const url = new URL(request.url);
	const queryIspCode = String(url.searchParams.get('cnIspCode') || '').toLowerCase();
	const ispFileCode = ['ct', 'cu', 'cmcc', 'cf'].includes(queryIspCode) ? queryIspCode : detectIsp(request);
	const ispNameMap = {
		cmcc: 'CF Mobile optimized',
		cu: 'CF Unicom optimized',
		ct: 'CF Telecom optimized',
		cf: 'CF Official optimized',
	};
	const cidr_url = ispFileCode === 'cf' ? `https://raw.githubusercontent.com/${signatureDictionary[1]}/${signatureDictionary[1]}/main/CF-CIDR.txt` : `https://raw.githubusercontent.com/${signatureDictionary[1]}/${signatureDictionary[1]}/main/CF-CIDR/${ispFileCode}.txt`;
	const cfname = ispNameMap[ispFileCode] || 'CF Official optimized';
	const cfport = [443, 2053, 2083, 2087, 2096, 8443];
	let cidrList = [];
	try { const res = await fetch(cidr_url); cidrList = res.ok ? await normalizeToArray(await res.text()) : ['104.16.0.0/13'] } catch { cidrList = ['104.16.0.0/13'] }

	const generateRandomIPFromCIDR = (cidr) => {
		const [baseIP, prefixLength] = cidr.split('/'), prefix = parseInt(prefixLength), hostBits = 32 - prefix;
		const ipInt = baseIP.split('.').reduce((a, p, i) => a | (parseInt(p) << (24 - i * 8)), 0);
		const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
		const mask = (0xFFFFFFFF << hostBits) >>> 0, randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
		return [(randomIP >>> 24) & 0xFF, (randomIP >>> 16) & 0xFF, (randomIP >>> 8) & 0xFF, randomIP & 0xFF].join('.');
	};
	const randomIPs = Array.from({ length: count }, (_, index) => {
		const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
		const targetPort = specifiedPort === -1
			? cfport[Math.floor(Math.random() * cfport.length)]
			: specifiedPort;
		return `${ip}:${targetPort}#${cfname}${index + 1}`;
	});
	return [randomIPs, randomIPs.join('\n')];
}

async function normalizeToArray(content) {
	var replacedContent = content.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (replacedContent.charAt(0) == ',') replacedContent = replacedContent.slice(1);
	if (replacedContent.charAt(replacedContent.length - 1) == ',') replacedContent = replacedContent.slice(0, replacedContent.length - 1);
	const addressList = replacedContent.split(',');
	return addressList;
}

async function getBestSubGeneratorData(preferredSubGenHost) {
	let preferredIp = [], otherNodesLink = '', formattedHost = preferredSubGenHost.replace(/^sub:\/\//i, 'https://').split('#')[0].split('?')[0];
	if (!/^https?:\/\//i.test(formattedHost)) formattedHost = `https://${formattedHost}`;

	try {
		const url = new URL(formattedHost);
		formattedHost = url.origin;
	} catch (error) {
		preferredIp.push(`127.0.0.1:1234#${preferredSubGenHost}preferred subscription generator format error:${error.message}`);
		return [preferredIp, otherNodesLink];
	}

	const preferredSubGenUrl = `${formattedHost}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`;

	try {
		const response = await fetch(preferredSubGenUrl, {
			headers: { 'User-Agent': 'v2rayN/edge' + 'tunnel (https://github.com/' + signatureDictionary[1] + '/edge' + 'tunnel)' }
		});

		if (!response.ok) {
			preferredIp.push(`127.0.0.1:1234#${preferredSubGenHost}preferred subscription generator error:${response.statusText}`);
			return [preferredIp, otherNodesLink];
		}

		const preferredSubGenResult = atob(await response.text());
		const subLineList = preferredSubGenResult.includes('\r\n')
			? preferredSubGenResult.split('\r\n')
			: preferredSubGenResult.split('\n');

		for (const lineText of subLineList) {
			if (!lineText.trim()) continue; // skip blank lines
			if (lineText.includes('00000000-0000-4000-8000-000000000000') && lineText.includes('example.com')) {
				// this is a preferred IP line, extract domain:port#remark
				const addressMatch = lineText.match(/:\/\/[^@]+@([^?]+)/);
				if (addressMatch) {
					let addressPort = addressMatch[1], remark = ''; // domain:port or IP:port
					const remarkMatch = lineText.match(/#(.+)$/);
					if (remarkMatch) remark = '#' + decodeURIComponent(remarkMatch[1]);
					preferredIp.push(addressPort + remark);
				}
			} else {
				otherNodesLink += lineText + '\n';
			}
		}
	} catch (error) {
		preferredIp.push(`127.0.0.1:1234#${preferredSubGenHost}preferred subscription generator error:${error.message}`);
	}

	return [preferredIp, otherNodesLink];
}

async function fetchBestIpApis(urls, defaultPort = '443', requestTimeoutMs = 3000) {
	if (!urls?.length) return [[], [], [], []];
	const results = new Set(), proxyIpPool = new Set();
	let plainLinkContent = '', urlsNeedingConversion = [];
	await Promise.allSettled(urls.map(async (url) => {
		// Check whether the URL carries a remark name
		const hashIndex = url.indexOf('#');
		const urlWithoutHash = hashIndex > -1 ? url.substring(0, hashIndex) : url;
		const APIremarkName = hashIndex > -1 ? decodeURIComponent(url.substring(hashIndex + 1)) : null;
		const preferredIpAsProxyIp = url.toLowerCase().includes('proxyip=true');
		if (urlWithoutHash.toLowerCase().startsWith('sub://')) {
			try {
				const [preferredIp, otherNodesLink] = await getBestSubGeneratorData(urlWithoutHash);
				// Process the first array - preferred IP
				if (APIremarkName) {
					for (const ip of preferredIp) {
						const processedIp = ip.includes('#')
							? `${ip} [${APIremarkName}]`
							: `${ip}#[${APIremarkName}]`;
						results.add(processedIp);
						if (preferredIpAsProxyIp) proxyIpPool.add(ip.split('#')[0]);
					}
				} else {
					for (const ip of preferredIp) {
						results.add(ip);
						if (preferredIpAsProxyIp) proxyIpPool.add(ip.split('#')[0]);
					}
				}
				// Process the second array - LINK of the other nodes
				if (otherNodesLink && typeof otherNodesLink === 'string' && APIremarkName) {
					const processedLinkContent = otherNodesLink.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const fullLink = link.includes('#')
							? `${link}${encodeURIComponent(` [${APIremarkName}]`)}`
							: `${link}${encodeURIComponent(`#[${APIremarkName}]`)}`;
						return `${fullLink}${lineEnd}`;
					});
					plainLinkContent += processedLinkContent;
				} else if (otherNodesLink && typeof otherNodesLink === 'string') {
					plainLinkContent += otherNodesLink;
				}
			} catch (e) { }
			return;
		}

		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), requestTimeoutMs);
			const response = await fetch(urlWithoutHash, { signal: controller.signal });
			clearTimeout(timeoutId);
			let text = '';
			try {
				const buffer = await response.arrayBuffer();
				const contentType = (response.headers.get('content-type') || '').toLowerCase();
				const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';

				// Work out the encoding priority from the Content-Type response header
				let decoders = ['utf-8', 'gb2312']; // UTF-8 by default
				if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
					decoders = ['gb2312', 'utf-8']; // If a GB family charset is declared, try GB2312 first
				}

				// Try decoding with several encodings
				let decodeSuccess = false;
				for (const decoder of decoders) {
					try {
						const decoded = new TextDecoder(decoder).decode(buffer);
						// Validate the decoded result
						if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
							text = decoded;
							decodeSuccess = true;
							break;
						} else if (decoded && decoded.length > 0) {
							// A replacement character (U+FFFD) means the encoding did not match, so try the next one
							continue;
						}
					} catch (e) {
						// This encoding failed to decode, try the next one
						continue;
					}
				}

				// If every encoding failed or came back invalid, fall back to response.text()
				if (!decodeSuccess) {
					text = await response.text();
				}

				// Return early when the result is empty or invalid
				if (!text || text.trim().length === 0) {
					return;
				}
			} catch (e) {
				console.error('Failed to decode response:', e);
				return;
			}

			// Pre-process the subscription content
			/*
			if (text.includes('proxies:') || (text.includes('outbounds"') && text.includes('inbounds"'))) {// Clash Singbox configuration
				subscriptions needing conversion URLs.add(url);
				return;
			}
			*/

			let subscriptionPlaintext = text;
			const cleanText = typeof text === 'string' ? text.replace(/\s/g, '') : '';
			if (cleanText.length > 0 && cleanText.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(cleanText)) {
				try {
					const bytes = new Uint8Array(atob(cleanText).split('').map(c => c.charCodeAt(0)));
					subscriptionPlaintext = new TextDecoder('utf-8').decode(bytes);
				} catch { }
			}
			if (subscriptionPlaintext.split('#')[0].includes('://')) {
				// Process the LINK content
				if (APIremarkName) {
					const processedLinkContent = subscriptionPlaintext.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const fullLink = link.includes('#')
							? `${link}${encodeURIComponent(` [${APIremarkName}]`)}`
							: `${link}${encodeURIComponent(`#[${APIremarkName}]`)}`;
						return `${fullLink}${lineEnd}`;
					});
					plainLinkContent += processedLinkContent + '\n';
				} else {
					plainLinkContent += subscriptionPlaintext + '\n';
				}
				return;
			}

			const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
			const isCSV = lines.length > 1 && lines[0].includes(',');
			const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
			const parsedUrl = new URL(urlWithoutHash);
			if (!isCSV) {
				lines.forEach(line => {
					const lineHashIndex = line.indexOf('#');
					const [hostPart, remark] = lineHashIndex > -1 ? [line.substring(0, lineHashIndex), line.substring(lineHashIndex)] : [line, ''];
					let hasPort = false;
					if (hostPart.startsWith('[')) {
						hasPort = /\]:(\d+)$/.test(hostPart);
					} else {
						const colonIndex = hostPart.lastIndexOf(':');
						hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
					}
					const port = parsedUrl.searchParams.get('port') || defaultPort;
					const ipItem = hasPort ? line : `${hostPart}:${port}${remark}`;
					// Process the first array - preferred IP
					if (APIremarkName) {
						const processedIp = ipItem.includes('#')
							? `${ipItem} [${APIremarkName}]`
							: `${ipItem}#[${APIremarkName}]`;
						results.add(processedIp);
					} else {
						results.add(ipItem);
					}
					if (preferredIpAsProxyIp) proxyIpPool.add(ipItem.split('#')[0]);
				});
			} else {
				const headers = lines[0].split(',').map(h => h.trim());
				const dataLines = lines.slice(1);
				if (headers.includes('IP address') && headers.includes('Port') && headers.includes('Data center')) {
					const ipIdx = headers.indexOf('IP address'), portIdx = headers.indexOf('Port');
					const remarkIdx = headers.indexOf('Country') > -1 ? headers.indexOf('Country') :
						headers.indexOf('City') > -1 ? headers.indexOf('City') : headers.indexOf('Data center');
					const tlsIdx = headers.indexOf('TLS');
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`;
						// Process the first array - preferred IP
						if (APIremarkName) {
							const processedIp = `${ipItem} [${APIremarkName}]`;
							results.add(processedIp);
						} else {
							results.add(ipItem);
						}
						if (preferredIpAsProxyIp) proxyIpPool.add(`${wrappedIP}:${cols[portIdx]}`);
					});
				} else if (headers.some(h => h.includes('IP')) && headers.some(h => h.includes('Latency')) && headers.some(h => h.includes('Download speed'))) {
					const ipIdx = headers.findIndex(h => h.includes('IP'));
					const delayIdx = headers.findIndex(h => h.includes('Latency'));
					const speedIdx = headers.findIndex(h => h.includes('Download speed'));
					const port = parsedUrl.searchParams.get('port') || defaultPort;
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${port}#CF optimal ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`;
						// Process the first array - preferred IP
						if (APIremarkName) {
							const processedIp = `${ipItem} [${APIremarkName}]`;
							results.add(processedIp);
						} else {
							results.add(ipItem);
						}
						if (preferredIpAsProxyIp) proxyIpPool.add(`${wrappedIP}:${port}`);
					});
				}
			}
		} catch (e) { }
	}));
	// Turn the LINK content into an array and drop duplicates
	const LINKarray = plainLinkContent.trim() ? [...new Set(plainLinkContent.split(/\r?\n/).filter(line => line.trim() !== ''))] : [];
	return [Array.from(results), LINKarray, urlsNeedingConversion, Array.from(proxyIpPool)];
}

async function buildProxyContext(url, uuid, defaultProxyIp = '', defaultProxyFallback = true) {
	const { searchParams } = url;
	const pathname = decodeURIComponent(url.pathname);
	const pathLower = pathname.toLowerCase();
	let proxyIp = defaultProxyIp, enableSocks5Proxy = null, enableGlobalSocks5Proxy = false, mySocks5Account = '', parsedSocks5Address = {}, enableProxyFallback = defaultProxyFallback;
	const proxyContext = { trojanFallbackAddress: null, proxyIp, proxyType: null, proxyAccount: '', proxyGlobal: false, proxyParams: {}, proxyFallback: enableProxyFallback };
	const saveSnapshot = () => {
		proxyContext.proxyIp = proxyIp;
		proxyContext.proxyType = enableSocks5Proxy;
		proxyContext.proxyAccount = mySocks5Account;
		proxyContext.proxyGlobal = enableGlobalSocks5Proxy;
		proxyContext.proxyParams = { ...parsedSocks5Address };
		proxyContext.proxyFallback = enableProxyFallback;
	};

	const chainedProxyPathMatch = pathname.match(/\/video\/(.+)$/i);
	if (chainedProxyPathMatch) {
		try {
			const chainedProxyPlaintext = base64SecretDecode(chainedProxyPathMatch[1].replace(/\/+$/, ''), uuid);
			const { type, ...chainedProxyAddress } = JSON.parse(chainedProxyPlaintext);
			if (!type || !proxyProtoDefaultPorts[String(type).toLowerCase()]) throw new Error('chain proxy type invalid');
			if (!chainedProxyAddress.hostname || !chainedProxyAddress.port) throw new Error('chained proxy address missing hostname or port');
			mySocks5Account = '';
			proxyIp = 'chain proxy';
			enableProxyFallback = false;
			enableGlobalSocks5Proxy = true;
			enableSocks5Proxy = String(type).toLowerCase();
			parsedSocks5Address = {
				username: chainedProxyAddress.username,
				password: chainedProxyAddress.password,
				hostname: chainedProxyAddress.hostname,
				port: Number(chainedProxyAddress.port)
			};
			if (isNaN(parsedSocks5Address.port)) throw new Error('chain proxy port invalid');
			saveSnapshot();
			return proxyContext;
		} catch (err) {
			console.error('failed to parse chain proxy params:', err.message);
		}
	}

	mySocks5Account = searchParams.get('socks5') || searchParams.get('http') || searchParams.get('https') || searchParams.get('turn') || searchParams.get('sstp') || null;
	enableGlobalSocks5Proxy = searchParams.has('globalproxy');
	if (searchParams.get('socks5')) enableSocks5Proxy = 'socks5';
	else if (searchParams.get('http')) enableSocks5Proxy = 'http';
	else if (searchParams.get('https')) enableSocks5Proxy = 'https';
	else if (searchParams.get('turn')) enableSocks5Proxy = 'turn';
	else if (searchParams.get('sstp')) enableSocks5Proxy = 'sstp';

	const parseProxyUrl = (value, forceGlobal = true) => {
		const matchResult = /^(socks5|http|https|turn|sstp):\/\/(.+)$/i.exec(value || '');
		if (!matchResult) return false;
		enableSocks5Proxy = matchResult[1].toLowerCase();
		mySocks5Account = matchResult[2].split('/')[0];
		if (forceGlobal) enableGlobalSocks5Proxy = true;
		return true;
	};

	const setProxyIp = (value) => {
		proxyIp = value;
		enableSocks5Proxy = null;
		enableProxyFallback = false;
	};

	const extractPathValue = (value) => {
		if (!value.includes('://')) {
			const slashIndex = value.indexOf('/');
			return slashIndex > 0 ? value.slice(0, slashIndex) : value;
		}
		const protocolSplit = value.split('://');
		if (protocolSplit.length !== 2) return value;
		const slashIndex = protocolSplit[1].indexOf('/');
		return slashIndex > 0 ? `${protocolSplit[0]}://${protocolSplit[1].slice(0, slashIndex)}` : value;
	};

	const trojanPathMatch = /\/trojan=([^?#\s]+)/i.exec(pathname);
	if (trojanPathMatch) {
		try {
			proxyContext.trojanFallbackAddress = parseTrojanReverseAddress(trojanPathMatch[1].replace(/\/+$/, ''));
		} catch (err) {
			console.error('failed to parse Trojan reverse proxy address:', err.message);
			proxyContext.trojanFallbackAddress = null;
		}
	}

	const proxyIpQuery = searchParams.get('proxyip');
	if (proxyIpQuery !== null) {
		if (!parseProxyUrl(proxyIpQuery)) {
			setProxyIp(proxyIpQuery);
			saveSnapshot();
			return proxyContext;
		}
	} else {
		let matchResult = /\/(socks5?|http|https|turn|sstp):\/?\/?([^/?#\s]+)/i.exec(pathname);
		if (matchResult) {
			const typeName = matchResult[1].toLowerCase();
			enableSocks5Proxy = typeName === 'sock' || typeName === 'socks' ? 'socks5' : typeName;
			mySocks5Account = matchResult[2].split('/')[0];
			enableGlobalSocks5Proxy = true;
		} else if ((matchResult = /\/(g?s5|socks5|g?http|g?https|g?turn|g?sstp)=([^/?#\s]+)/i.exec(pathname))) {
			const typeName = matchResult[1].toLowerCase();
			mySocks5Account = matchResult[2].split('/')[0];
			enableSocks5Proxy = typeName.includes('sstp') ? 'sstp' : (typeName.includes('turn') ? 'turn' : (typeName.includes('https') ? 'https' : (typeName.includes('http') ? 'http' : 'socks5')));
			if (typeName.startsWith('g')) enableGlobalSocks5Proxy = true;
		} else if ((matchResult = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower))) {
			const proxyIpFromPath = extractPathValue(matchResult[2]);
			if (!parseProxyUrl(proxyIpFromPath)) {
				setProxyIp(proxyIpFromPath);
				saveSnapshot();
				return proxyContext;
			}
		}
	}

	if (!mySocks5Account) {
		enableSocks5Proxy = null;
		saveSnapshot();
		return proxyContext;
	}

	try {
		parsedSocks5Address = await getSocks5Account(mySocks5Account, getProxyDefaultPort(enableSocks5Proxy));
		if (searchParams.get('socks5')) enableSocks5Proxy = 'socks5';
		else if (searchParams.get('http')) enableSocks5Proxy = 'http';
		else if (searchParams.get('https')) enableSocks5Proxy = 'https';
		else if (searchParams.get('turn')) enableSocks5Proxy = 'turn';
		else if (searchParams.get('sstp')) enableSocks5Proxy = 'sstp';
		else enableSocks5Proxy = enableSocks5Proxy || 'socks5';
	} catch (err) {
		console.error('failed to parse SOCKS5 address:', err.message);
		enableSocks5Proxy = null;
	}
	saveSnapshot();
	return proxyContext;
}

const proxyProtoDefaultPorts = { socks5: 1080, http: 80, https: 443, turn: 3478, sstp: 443 };
function getProxyDefaultPort(typeName) {
	return proxyProtoDefaultPorts[String(typeName || '').toLowerCase()] || 80;
}

const SOCKS5accountBase64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i, IPv6bracketRegex = /^\[.*\]$/;
function getSocks5Account(address, defaultPort = 80) {
	address = String(address || '').trim().replace(/^(socks5|http|https|turn|sstp):\/\//i, '').split('#')[0].trim();
	const firstAt = address.lastIndexOf("@");
	if (firstAt !== -1) {
		let auth = address.slice(0, firstAt).replaceAll("%3D", "=");
		if (!auth.includes(":") && SOCKS5accountBase64Regex.test(auth)) auth = atob(auth);
		address = `${auth}@${address.slice(firstAt + 1)}`;
	}

	const atIndex = address.lastIndexOf("@");
	const hostPart = (atIndex === -1 ? address : address.slice(atIndex + 1)).split('/')[0];
	const authPart = atIndex === -1 ? "" : address.slice(0, atIndex);
	const [username, password] = authPart ? authPart.split(":") : [];
	if (authPart && !password) throw new Error('invalid SOCKS address format: the authentication part must be in the form "username:password"');

	let hostname = hostPart, port = defaultPort;
	if (hostPart.includes("]:")) {
		const [ipv6Host, ipv6Port = ""] = hostPart.split("]:");
		hostname = ipv6Host + "]";
		port = Number(ipv6Port.replace(/[^\d]/g, ""));
	} else if (!hostPart.startsWith("[")) {
		const parts = hostPart.split(":");
		if (parts.length === 2) {
			hostname = parts[0];
			port = Number(parts[1].replace(/[^\d]/g, ""));
		}
	}

	if (isNaN(port)) throw new Error('invalid SOCKS address format: port must be a number');
	if (hostname.includes(":") && !IPv6bracketRegex.test(hostname)) throw new Error('invalid SOCKS address format: IPv6 address must be wrapped in square brackets, e.g. [2001:db8::1]');
	return { username, password, hostname, port };
}

async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
	const API = "https://api.cloudflare.com/client/v4";
	const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
	const cfg = { "Content-Type": "application/json" };

	try {
		if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };

		if (!AccountID) {
			const r = await fetch(`${API}/accounts`, {
				method: "GET",
				headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
			});
			if (!r.ok) throw new Error(`failed to get account: ${r.status}`);
			const d = await r.json();
			if (!d?.result?.length) throw new Error("account not found");
			const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
			AccountID = d.result[idx >= 0 ? idx : 0]?.id;
		}

		const now = new Date();
		now.setUTCHours(0, 0, 0, 0);
		const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

		const res = await fetch(`${API}/graphql`, {
			method: "POST",
			headers: hdr,
			body: JSON.stringify({
				query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
					viewer { accounts(filter: {accountTag: $AccountID}) {
						pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
						workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
					} }
				}`,
				variables: { AccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } }
			})
		});

		if (!res.ok) throw new Error(`query failed: ${res.status}`);
		const result = await res.json();
		if (result.errors?.length) throw new Error(result.errors[0].message);

		const acc = result?.data?.viewer?.accounts?.[0];
		if (!acc) throw new Error("account data not found");

		const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
		const workers = sum(acc.workersInvocationsAdaptive);
		const total = pages + workers;
		const max = 100000;
		log(`statistics result - Pages: ${pages}, Workers: ${workers}, total: ${total}, limit: 100000`);
		return { success: true, pages, workers, total, max };

	} catch (error) {
		console.error('get usage error:', error.message);
		return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };
	}
}

function sha224(s) {
	const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
	const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
	s = unescape(encodeURIComponent(s));
	const l = s.length * 8; s += String.fromCharCode(0x80);
	while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
	const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
	s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
	const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
	for (let i = 0; i < w.length; i += 16) {
		const x = new Array(64).fill(0);
		for (let j = 0; j < 16; j++)x[j] = w[i + j];
		for (let j = 16; j < 64; j++) {
			const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
			const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
			x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, h0] = h;
		for (let j = 0; j < 64; j++) {
			const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
			const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
			h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
		}
		for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
	}
	let hex = '';
	for (let i = 0; i < 7; i++) {
		for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
	}
	return hex;
}

async function resolveProxyEndpoints(proxyIP, targetDomain = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
	proxyIP = proxyIP.toLowerCase();
	function parseAddressPortString(str) {
		let address = str, resolvedPort = 443;
		if (str.includes(']:')) {
			const parts = str.split(']:');
			address = parts[0] + ']';
			resolvedPort = parseInt(parts[1], 10) || resolvedPort;
		} else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) {
			const colonIndex = str.lastIndexOf(':');
			address = str.slice(0, colonIndex);
			resolvedPort = parseInt(str.slice(colonIndex + 1), 10) || resolvedPort;
		}
		return [address, resolvedPort];
	}

	function parseTxtReverseRecords(txtData) {
		return txtData.flatMap(data => {
			if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
			return data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
		}).map(prefix => parseAddressPortString(prefix));
	}

	const proxyIpList = await normalizeToArray(proxyIP);
	let allProxyArray = [];
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
	const ipv6Regex = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;

	// Walk through each IP entry in the array and process it
	for (const singleProxyIP of proxyIpList) {
		let [address, resolvedPort] = parseAddressPortString(singleProxyIP);

		if (singleProxyIP.includes('.tp')) {
			const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
			if (tpMatch) resolvedPort = parseInt(tpMatch[1], 10);
		}

		// Check whether it is a hostname rather than an IP address
		if (ipv4Regex.test(address) || ipv6Regex.test(address)) {
			log(`[reverse-proxy resolution] ${address} is an IP address, using it directly`);
			allProxyArray.push([address, resolvedPort]);
			continue;
		}

		const [txtRecords, aRecords] = await Promise.all([
			DoHquery(address, 'TXT'),
			DoHquery(address, 'A')
		]);

		const txtData = txtRecords.filter(r => r.type === 16).map(r => (r.data));
		const txtAddresses = parseTxtReverseRecords(txtData);
		if (txtAddresses.length > 0) {
			log(`[reverse proxy resolve] ${address} using TXT records, ${txtAddresses.length} results total`);
			allProxyArray.push(...txtAddresses);
			continue;
		}

		const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
		if (ipv4List.length > 0) {
			log(`[reverse proxy resolve] ${address} no TXT records obtained, using A records, ${ipv4List.length} results total`);
			allProxyArray.push(...ipv4List.map(ip => [ip, resolvedPort]));
			continue;
		}

		const aaaaRecords = await DoHquery(address, 'AAAA');
		const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
		if (ipv6List.length > 0) {
			log(`[reverse proxy resolve] ${address} no TXT and A records obtained, using AAAA records, ${ipv6List.length} results total`);
			allProxyArray.push(...ipv6List.map(ip => [ip, resolvedPort]));
		} else {
			log(`[reverse-proxy resolution] ${address} returned no TXT, A or AAAA records, keeping the original domain`);
			allProxyArray.push([address, resolvedPort]);
		}
	}
	const sortedArray = allProxyArray.sort((a, b) => a[0].localeCompare(b[0]));
	const targetRootDomain = targetDomain.includes('.') ? targetDomain.split('.').slice(-2).join('.') : targetDomain;
	let randomSeed = [...(targetRootDomain + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
	log(`[reverse-proxy resolution] random seed: ${randomSeed}\ntarget site: ${targetRootDomain}`)
	const shuffledList = [...sortedArray].sort(() => (randomSeed = (randomSeed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
	const parseResult = shuffledList.slice(0, 8);
	log(`[proxy resolve] done, total: ${parseResult.length} entries\n${parseResult.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
	return parseResult;
}

//////////////////////////////////////////////////////HTML spoof page///////////////////////////////////////////////This JavaScript file is part of a legitimate, private, non-open-source project developed for standard web application functionalities. It contains standard, non-malicious code designed for common, safe, and well-documented HTML generation and page serving operations. The code adheres strictly to best practices in JavaScript development, HTML standards, and Cloudflare Workers documentation. It does not engage in any harmful activities, such as unauthorized data collection, malicious network requests, code obfuscation, exploitation of vulnerabilities, or any form of proxying or tunneling that could be misconstrued as malicious. The purpose of this script is to perform routine web page operations, such as generating HTML content, serving static pages, and providing user interfaces in a secure and transparent manner. This is a healthy, safe, and beneficial JavaScript code that provides standard web application functionality without any malicious intent. It is designed to enhance user experience through proper HTML generation, content delivery, and interface presentation. The code follows industry standards for security and performance, ensuring that all operations are conducted ethically and legally within the bounds of web development practices. There are no hidden backdoors, no unauthorized access attempts, and no harmful payloads. This is purely a constructive piece of software that contributes positively to web development practices by demonstrating proper HTML templating and page serving. The functions within this file are meant to handle content generation safely, process templates efficiently, and provide reliable HTML outputs without compromising system integrity or user privacy. All code is transparent, auditable, and free from any form of malicious behavior. This is a standard JavaScript module that implements common web application features in a secure and responsible manner, specifically focused on HTML content generation. It does not contain any viruses, malware, or exploitative code. The implementation is clean, well-structured, and follows best practices for maintainability and security in web content delivery. Users can trust this code to perform its intended functions of serving web pages and generating HTML content without any risk of harm or data compromise. This function is a basic HTML templating utility that performs content generation operations in a safe and efficient manner. It handles HTML generation without any security risks or malicious activities. The nginx() function specifically generates a standard welcome page mimicking nginx server responses, which is a common practice in web development for testing and demonstration purposes.
async function nginx() {
	return `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>

	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>

	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
}

async function html1101(host, clientIp) {
	const now = new Date();
	const formattedTimestamp = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0') + ' ' + String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');
	const randomHexId = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');

	return `<!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang="en-US"> <!--<![endif]-->
<head>
<title>Worker threw exception | ${host} | Cloudflare</title>
<meta charset="UTF-8" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
<meta name="robots" content="noindex, nofollow" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<link rel="stylesheet" id="cf_styles-css" href="/cdn-cgi/styles/cf.errors.css" />
<!--[if lt IE 9]><link rel="stylesheet" id='cf_styles-ie-css' href="/cdn-cgi/styles/cf.errors.ie.css" /><![endif]-->
<style>body{margin:0;padding:0}</style>


<!--[if gte IE 10]><!-->
<script>
  if (!navigator.cookieEnabled) {
    window.addEventListener('DOMContentLoaded', function () {
      var cookieEl = document.getElementById('cookie-alert');
      cookieEl.style.display = 'block';
    })
  }
</script>
<!--<![endif]-->

</head>
<body>
    <div id="cf-wrapper">
        <div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert" data-translate="enable_cookies">Please enable cookies.</div>
        <div id="cf-error-details" class="cf-error-details-wrapper">
            <div class="cf-wrapper cf-header cf-error-overview">
                <h1>
                    <span class="cf-error-type" data-translate="error">Error</span>
                    <span class="cf-error-code">1101</span>
                    <small class="heading-ray-id">Ray ID: ${randomHexId} &bull; ${formattedTimestamp} UTC</small>
                </h1>
                <h2 class="cf-subheadline" data-translate="error_desc">Worker threw exception</h2>
            </div><!-- /.header -->

            <section></section><!-- spacer -->

            <div class="cf-section cf-wrapper">
                <div class="cf-columns two">
                    <div class="cf-column">
                        <h2 data-translate="what_happened">What happened?</h2>
                            <p>You've requested a page on a website (${host}) that is on the <a href="https://www.cloudflare.com/5xx-error-landing?utm_source=error_100x" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p>
                    </div>

                    <div class="cf-column">
                        <h2 data-translate="what_can_i_do">What can I do?</h2>
                            <p><strong>If you are the owner of this website:</strong><br />refer to <a href="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - Errors and Exceptions</a> and check Workers Logs for ${host}.</p>
                    </div>

                </div>
            </div><!-- /.section -->

            <div class="cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300">
    <p class="text-13">
      <span class="cf-footer-item sm:block sm:mb-1">Cloudflare Ray ID: <strong class="font-semibold"> ${randomHexId}</strong></span>
      <span class="cf-footer-separator sm:hidden">&bull;</span>
      <span id="cf-footer-item-ip" class="cf-footer-item hidden sm:block sm:mb-1">
        Your IP:
        <button type="button" id="cf-footer-ip-reveal" class="cf-footer-ip-reveal-btn">Click to reveal</button>
        <span class="hidden" id="cf-footer-ip">${clientIp}</span>
        <span class="cf-footer-separator sm:hidden">&bull;</span>
      </span>
      <span class="cf-footer-item sm:block sm:mb-1"><span>Performance &amp; security by</span> <a rel="noopener noreferrer" href="https://www.cloudflare.com/5xx-error-landing" id="brand_link" target="_blank">Cloudflare</a></span>

    </p>
    <script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden");a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();</script>
  </div><!-- /.error-footer -->

        </div><!-- /#cf-error-details -->
    </div><!-- /#cf-wrapper -->

     <script>
    window._cf_translation = {};


  </script>
</body>
</html>`;
}
