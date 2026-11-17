/**
 * Beamio API 基址回归测试（本地隔离，不出网）。
 *
 * 运行方式（先编译）：
 *   npm run build && node --test scripts/test-beamio-api-base.cjs
 *
 * 隔离手段：
 * - phin 被替换为记录函数，不发送任何 HTTP；
 * - ethers JSON-RPC 的 _send 在本地应答，不访问 CoNET RPC；
 * - http/https/net/tls 对非回环主机的连接一律抛错，保证不会触达 beamio.ca / beamio.app 或任何外部主机；
 * - 节点私钥每次随机生成，不写入仓库。
 */
const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('path')
const fs = require('fs')
const Module = require('module')
const http = require('http')
const https = require('https')
const net = require('net')
const tls = require('tls')

const DIST = path.join(__dirname, '..', 'dist', 'util')
if (!fs.existsSync(path.join(DIST, 'util.js'))) {
	throw new Error('dist/util/util.js 不存在，请先运行 npm run build')
}

// ---- 网络守卫 ----
const isLoopback = (h) => h === '127.0.0.1' || h === 'localhost' || h === '::1'
const guard = (h, what) => {
	if (!isLoopback(String(h || ''))) throw new Error(`test blocked outbound ${what} to non-loopback host`)
}
http.request = new Proxy(http.request, { apply(t, th, a) { const o = a[0]; guard(typeof o === 'string' ? new URL(o).hostname : (o && (o.hostname || o.host)), 'http'); return Reflect.apply(t, th, a) } })
https.request = new Proxy(https.request, { apply(t, th, a) { const o = a[0]; guard(typeof o === 'string' ? new URL(o).hostname : (o && (o.hostname || o.host)), 'https'); return Reflect.apply(t, th, a) } })
net.connect = new Proxy(net.connect, { apply(t, th, a) { const o = a[0]; guard(typeof o === 'object' ? (o.host || o.hostname) : a[1], 'net'); return Reflect.apply(t, th, a) } })
tls.connect = new Proxy(tls.connect, { apply(t, th, a) { const o = a[0]; guard(typeof o === 'object' ? (o.host || o.hostname || o.servername) : a[1], 'tls'); return Reflect.apply(t, th, a) } })

// ---- phin 替身 ----
let phinMode = 'ok' // 'ok' | 'redirect'
const phinCalls = []
const fakePhin = async (opts) => {
	const u = new URL(opts.url)
	phinCalls.push({ url: opts.url, hostname: u.hostname, protocol: u.protocol, method: opts.method, headers: opts.headers, data: opts.data, timeout: opts.timeout, parse: opts.parse, followRedirects: opts.followRedirects })
	if (phinMode === 'redirect') return { statusCode: 302, headers: { location: 'https://beamio.app/api/redirected' }, body: undefined }
	return { statusCode: 200, headers: {}, body: u.pathname === '/api/nativeWakeable' ? { success: true, nativeWakeable: true } : { success: true } }
}
const origLoad = Module._load
Module._load = function (request, parent, isMain) {
	if (request === 'phin') return fakePhin
	return origLoad.call(this, request, parent, isMain)
}

// ---- ethers 本地 JSON-RPC ----
const ethers = require('ethers')
const CHAIN_EOA = '0x1111111111111111111111111111111111111111'
const abiCoder = ethers.AbiCoder.defaultAbiCoder()
const localSend = async function (payload) {
	const list = Array.isArray(payload) ? payload : [payload]
	return list.map((p) => {
		let result
		switch (p.method) {
			case 'eth_chainId': result = '0x36c66'; break
			case 'net_version': result = '224422'; break
			case 'eth_call': result = abiCoder.encode(['address'], [CHAIN_EOA]); break
			default: result = '0x0'
		}
		return { id: p.id, jsonrpc: '2.0', result }
	})
}
for (const cls of [ethers.JsonRpcApiProvider, ethers.JsonRpcProvider]) {
	if (cls && cls.prototype) cls.prototype._send = localSend
}

// ---- 被测模块 ----
const util = require(path.join(DIST, 'util.js'))
const beamioApi = require(path.join(DIST, 'beamioApi.js'))

const NODE_KEY = ethers.Wallet.createRandom().privateKey
util.initPGPRouteManager(NODE_KEY)
const nodeAddress = new ethers.Wallet(NODE_KEY).address

const logs = []
const origLog = console.log
const wait = (ms) => new Promise((r) => setTimeout(r, ms))

const runFourCalls = async () => {
	phinCalls.length = 0
	logs.length = 0
	console.log = (...a) => { logs.push(a.map(String).join(' ')) }
	try {
		util.notifyOfflineChatPush('pgp-key-test-1', 2)
		await wait(300)
		util.notifyVoiceCallPush({ callId: 'call-test-1', sessionId: 'sess-test-1', calleeEoa: '0x2222222222222222222222222222222222222222', expiresAt: 1790000300, timestamp: 1790000000 })
		await wait(300)
		const wakeable = await util.queryNativeWakeable('0x3333333333333333333333333333333333333333')
		util.notifyPushDeviceRegistration({ eoa: CHAIN_EOA, deviceToken: 'device-token-test', platform: 'ios', bundleId: 'test.bundle.id', pgpKeyId: 'pgp-key-test-1', timestamp: 1790000000, signature: '0xtestsignature', capabilities: { nativeCallUi: true } })
		await wait(300)
		return { calls: phinCalls.slice(), wakeable, logs: logs.slice() }
	} finally {
		console.log = origLog
	}
}

const withEnv = async (value, fn) => {
	const prev = process.env.BEAMIO_API_BASE
	if (value === undefined) delete process.env.BEAMIO_API_BASE
	else process.env.BEAMIO_API_BASE = value
	try {
		return await fn()
	} finally {
		if (prev === undefined) delete process.env.BEAMIO_API_BASE
		else process.env.BEAMIO_API_BASE = prev
	}
}

const EXPECTED_PATHS = ['/api/notifyOfflineChat', '/api/voiceCallPush', '/api/nativeWakeable', '/api/registerPushDevice']

test('classifyBeamioApiBase: 仅严格的 https://beamio.ca 可接受', () => {
	for (const ok of ['https://beamio.ca', 'https://beamio.ca/', 'HTTPS://BEAMIO.CA']) {
		assert.equal(beamioApi.classifyBeamioApiBase(ok), null, ok)
	}
	const rejected = {
		'https://beamio.app': 'retired-domain',
		'https://www.beamio.app': 'retired-domain',
		'https://api.beamio.app': 'retired-domain',
		'http://beamio.app': 'retired-domain',
		'https://beamio.ca@beamio.app': 'retired-domain',
		'http://beamio.ca': 'not-https',
		'wss://beamio.ca': 'not-https',
		'https://beamio.ca.evil.example': 'not-allowed-host',
		'https://notbeamio.app.example': 'not-allowed-host',
		'https://beamio.app.evil.example': 'not-allowed-host',
		'https://user:pw@beamio.ca': 'credentials',
		'https://beamio.ca:8443': 'port',
		'https://beamio.ca/proxy': 'path',
		'https://beamio.ca/?x=1': 'path',
		'not a url': 'unparseable',
	}
	for (const [v, reason] of Object.entries(rejected)) {
		assert.equal(beamioApi.classifyBeamioApiBase(v), reason, v)
	}
})

test('默认与合法 beamio.ca 配置：四个调用 URL/方法/头/请求体/超时一致，签名有效，不跟随重定向', async () => {
	for (const env of [undefined, '', 'https://beamio.ca', 'https://beamio.ca/']) {
		await withEnv(env, async () => {
			const { calls, wakeable } = await runFourCalls()
			assert.equal(calls.length, 4, `env=${env}`)
			assert.deepEqual(calls.map((c) => c.url.replace('https://beamio.ca', '')), EXPECTED_PATHS)
			for (const c of calls) {
				assert.equal(c.protocol, 'https:')
				assert.equal(c.hostname, 'beamio.ca')
				assert.equal(c.method, 'POST')
				assert.deepEqual(c.headers, { 'Content-Type': 'application/json' })
				assert.equal(c.timeout, 8000)
				assert.equal(c.parse, 'json')
				assert.equal(c.followRedirects, false)
			}
			const [notify, voice, wake, device] = calls.map((c) => JSON.parse(c.data))
			// 签名字节须能由同一节点私钥对固定消息恢复出节点地址
			const notifyMsg = ['Beamio notifyOfflineChat', 'pgpKeyId:pgp-key-test-1', `eoa:${CHAIN_EOA}`, `timestamp:${notify.timestamp}`].join('\n')
			assert.equal(ethers.verifyMessage(notifyMsg, notify.signature), nodeAddress)
			assert.deepEqual(Object.keys(notify), ['pgpKeyId', 'eoa', 'timestamp', 'signature', 'count'])
			assert.equal(notify.count, 2)
			const voiceMsg = ['CoNET voiceCallPush relay', 'callId:call-test-1', 'sessionId:sess-test-1', 'calleeEoa:0x2222222222222222222222222222222222222222', 'expiresAt:1790000300', `timestamp:${voice.timestamp}`, `nodeWallet:${nodeAddress.toLowerCase()}`].join('\n')
			assert.equal(ethers.verifyMessage(voiceMsg, voice.signature), nodeAddress)
			assert.deepEqual(Object.keys(voice), ['callId', 'sessionId', 'calleeEoa', 'expiresAt', 'timestamp', 'nodeWallet', 'signature'])
			const wakeMsg = ['Beamio nativeWakeable', `eoa:${'0x3333333333333333333333333333333333333333'}`, `timestamp:${wake.timestamp}`].join('\n')
			assert.equal(ethers.verifyMessage(wakeMsg, wake.signature), nodeAddress)
			assert.equal(wakeable, true)
			assert.equal(device.eoa, CHAIN_EOA)
			assert.deepEqual(Object.keys(device), ['eoa', 'deviceToken', 'platform', 'bundleId', 'pgpKeyId', 'timestamp', 'signature', 'capabilities'])
		})
	}
})

test('旧域、http、相似域名、带账号信息/端口/路径等配置：所有出站请求只到 https://beamio.ca/api/*，并给出不含原值的告警', async () => {
	const bad = [
		'https://beamio.app',
		'https://www.beamio.app',
		'https://api.beamio.app',
		'http://beamio.app',
		'http://beamio.ca',
		'https://beamio.ca.evil.example',
		'https://notbeamio.app.example',
		'https://beamio.app.evil.example',
		'https://beamio.ca@beamio.app',
		'https://beamio.ca:8443',
		'https://beamio.ca/proxy',
		'not a url',
	]
	for (const env of bad) {
		await withEnv(env, async () => {
			const { calls, logs: out } = await runFourCalls()
			assert.equal(calls.length, 4, env)
			for (const c of calls) {
				assert.equal(c.protocol, 'https:', env)
				assert.equal(c.hostname, 'beamio.ca', env)
				assert.equal(c.followRedirects, false, env)
			}
			assert.deepEqual(calls.map((c) => c.url.replace('https://beamio.ca', '')), EXPECTED_PATHS)
			const warn = out.filter((l) => l.includes('BEAMIO_API_BASE rejected'))
			assert.ok(warn.length <= 1, `同一原因只告警一次: ${env}`)
			// 告警与日志不得回显环境变量原值中的主机或凭据片段
			for (const l of out) {
				assert.ok(!/beamio\.app/.test(l), `log must not echo retired host: ${l}`)
				assert.ok(!/evil\.example|8443|user:pw|proxy|@/.test(l), `log must not echo raw value: ${l}`)
			}
		})
	}
})

test('服务端 3xx 指向旧域：不跟随，四个调用均显式报错，queryNativeWakeable 返回 null', async () => {
	phinMode = 'redirect'
	try {
		for (const env of [undefined, 'https://beamio.ca']) {
			await withEnv(env, async () => {
				const { calls, wakeable, logs: out } = await runFourCalls()
				assert.equal(calls.length, 4, `no second request after 3xx: env=${env}`)
				for (const c of calls) assert.equal(c.hostname, 'beamio.ca')
				assert.equal(wakeable, null)
				const failed = out.filter((l) => l.includes('Beamio API redirect refused (HTTP 302)'))
				assert.equal(failed.length, 4)
			})
		}
	} finally {
		phinMode = 'ok'
	}
})
