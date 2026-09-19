// Builds dist/_worker.js: the upstream edgetunnel worker with the Iran pool layer applied.
// Upstream _worker.js is never edited, so the Upstream Sync workflow keeps merging cleanly.
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, unlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const 根目录 = join(dirname(fileURLToPath(import.meta.url)), '..');
const 源文件 = join(根目录, '_worker.js');
const 输出目录 = join(根目录, 'dist');
const 输出文件 = join(输出目录, '_worker.js');

const { pool: 反代池, updated: 池更新日期 } = JSON.parse(readFileSync(join(根目录, 'iran', 'pool.json'), 'utf8'));
if (!Array.isArray(反代池) || 反代池.some(h => typeof h !== 'string' || !h.trim())) {
	throw new Error('iran/pool.json: "pool" must be a non-empty array of hostname strings');
}

const 头注入 = {
	name: 'iran-pool-header',
	anchor: `const Pages静态页面 = 'https://edt-pages.github.io';`,
	insert: [
		``,
		`///////////////////////////////////////////////////////IRAN POOL (build-time injected)///////////////////////////////////////////////`,
		`const IRAN_POOL = ${JSON.stringify(反代池.map(h => h.trim().toLowerCase()))};`,
		`const IRAN_POOL_UPDATED = ${JSON.stringify(池更新日期 || '')};`,
		`const IRAN_乱序 = (数组) => { for (let i = 数组.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [数组[i], 数组[j]] = [数组[j], 数组[i]]; } return 数组; };`,
	].join('\r\n'),
};

const 拨号补丁 = {
	name: 'iran-pool-dial',
	// upstream picks ONE random entry from PROXYIP and switches the built-in fallback off,
	// so a dead entry kills the connection and public-pool users get no failover at all.
	find: /if \(env\.PROXYIP\) \{[^}]*默认反代IP = proxyIPs\[[^\]]*\];[^}]*默认反代兜底 = false;[^}]*\};/,
	replace: [
		`if (env.PROXYIP) {`,
		`			const proxyIPs = [...new Set((await 整理成数组(env.PROXYIP)).map(s => s.trim()))].filter(Boolean);`,
		`			if (proxyIPs.length) {`,
		`				默认反代IP = IRAN_乱序(proxyIPs).join(',');`,
		`				默认反代兜底 = false;`,
		`			};`,
		`		} else if (IRAN_POOL.length) {`,
		`			const proxyIPs = IRAN_乱序([默认反代IP, ...IRAN_POOL]);`,
		`			默认反代IP = [...new Set(proxyIPs)].join(',');`,
		`			默认反代兜底 = true;`,
		`		};`,
	].join('\r\n'),
};

function 应用补丁(内容, 补丁) {
	if (补丁.find instanceof RegExp) {
		const 命中 = 内容.match(new RegExp(补丁.find.source, 补丁.find.flags.includes('g') ? 补丁.find.flags : 补丁.find.flags + 'g'));
		if (!命中 || 命中.length !== 1) throw new Error(`${补丁.name}: expected 1 match, found ${命中 ? 命中.length : 0} — upstream code moved, review the patch before deploying`);
		return 内容.replace(补丁.find, 补丁.replace);
	}
	const 位置 = 内容.indexOf(补丁.anchor);
	if (位置 === -1 || 内容.indexOf(补丁.anchor, 位置 + 1) !== -1) throw new Error(`${补丁.name}: anchor is not unique — upstream code moved, review the patch before deploying`);
	return 内容.slice(0, 位置 + 补丁.anchor.length) + 补丁.insert + 内容.slice(位置 + 补丁.anchor.length);
}

let 输出 = readFileSync(源文件, 'utf8');
for (const 补丁 of [头注入, 拨号补丁]) 输出 = 应用补丁(输出, 补丁);

for (const 标记 of ['const IRAN_POOL = [', '} else if (IRAN_POOL.length) {']) {
	if (!输出.includes(标记)) throw new Error(`sanity check failed: ${标记} missing from the build output`);
}

mkdirSync(输出目录, { recursive: true });
writeFileSync(输出文件, 输出, 'utf8');
copyFileSync(join(根目录, 'iran', 'pool.json'), join(输出目录, 'iran-pool.json'));

const 语法检查 = join(输出目录, '_syntax-check.mjs');
copyFileSync(输出文件, 语法检查);
const 结果 = spawnSync(process.execPath, ['--check', 语法检查], { encoding: 'utf8' });
unlinkSync(语法检查);
if (结果.status !== 0) throw new Error(`dist/_worker.js failed node --check:\n${结果.stderr}`);

console.log(`built ${输出文件} (${(输出.length / 1024).toFixed(0)} KB) with ${反代池.length} pool endpoints`);
