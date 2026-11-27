/**
 * Node key material must never reach the log (stdout / stderr).
 *
 * Run (build first):  npm run build && node --test scripts/test-no-key-logging.cjs
 *
 * All secrets are generated here (fake PGP key with multi-line armor, fake wallet keystore, fake
 * password); no real node file is read and nothing leaves the machine except what the node itself
 * does when its worker is up (public RPC lookups, which do not matter here).
 *
 * Cases:
 *   1. setupSummary() allow-list on a fully populated fake setup (all depth levels of inspect).
 *   2. start.js certificate-renewal path (start.ts sslCertificate), certbot stubbed to FAIL.
 *   3. start.js certificate-renewal path, certbot stubbed to SUCCEED, then the worker starts.
 *   4. start.js normal start path (fresh certificate date), worker starts and loads the keys.
 *   5. self-test: the secret matcher does flag a raw dump of the same fake setup (so a pass above
 *      cannot be a blind matcher).
 * `sudo` is replaced by a stub, so certbot / chown / systemctl / reboot never run.
 */
const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const fs = require('node:fs')
const os = require('node:os')
const crypto = require('node:crypto')
const { spawn } = require('node:child_process')
const { inspect } = require('node:util')

const root = path.join(__dirname, '..')
const startJs = path.join(root, 'dist', 'start.js')
const summaryJs = path.join(root, 'dist', 'util', 'setupSummary.js')
if (!fs.existsSync(startJs) || !fs.existsSync(summaryJs)) {
	throw new Error('dist/start.js or dist/util/setupSummary.js missing; run npm run build first')
}
const { generateKey } = require(path.join(root, 'node_modules/openpgp'))
const { Wallet } = require(path.join(root, 'node_modules/ethers'))

const stripAnsi = (s) => s.replace(/\u001b\[[0-9;]*m/g, '')

// Every string leaf of a JSON value (used to expand the keystore into individual secrets).
const leaves = (v, out = []) => {
	if (typeof v === 'string') out.push(v)
	else if (v && typeof v === 'object') for (const x of Object.values(v)) leaves(x, out)
	return out
}

const makeFake = async () => {
	const passwd = `fake-test-pass-${crypto.randomBytes(8).toString('hex')}`
	const wallet = Wallet.createRandom()
	const keychain = await wallet.encrypt(passwd)
	const { privateKey, publicKey } = await generateKey({
		type: 'ecc',
		curve: 'curve25519Legacy',
		userIDs: [{ name: wallet.address }],
		passphrase: passwd,
		format: 'armored',
	})
	const setup = {
		keychain,
		ipV4: '127.0.0.1',
		ipV6: '',
		ipV4Port: 20000 + Math.floor(Math.random() * 20000),
		ipV6Port: 0,
		storage_price: 0,
		outbound_price: 0,
		pgpKey: { privateKey, publicKey, keyID: 'FAKEKEYID' },
		DL_registeredData: '',
		cpus: 1,
		passwd,
		platform_verison: 'test',
		dl_publicKeyArmored: '',
		restartBlockNumber: 0,
	}

	// Needles: whole values, JSON-escaped forms, and every individual armor line / keystore field.
	const armorLines = privateKey.split('\n').map(l => l.trim()).filter(l => l.length >= 20 && !l.startsWith('-----'))
	assert.ok(armorLines.length >= 3, 'fake armor must span several lines')
	const keystoreLeaves = leaves(JSON.parse(keychain)).filter(s => s.length >= 8 && s.toLowerCase() !== wallet.address.slice(2).toLowerCase())
	const needles = new Map()
	const add = (label, value) => { if (value && value.length >= 6) needles.set(label, value) }
	add('literal BEGIN PGP PRIVATE', 'BEGIN PGP PRIVATE')
	add('literal passwd', 'passwd')
	add('literal privateKey', 'privateKey')
	add('literal keychain', 'keychain')
	add('password value', passwd)
	add('wallet private key (hex)', wallet.privateKey.slice(2))
	add('keystore (whole JSON)', keychain)
	add('keystore (JSON-escaped)', JSON.stringify(keychain).slice(1, -1))
	add('PGP armor (whole)', privateKey)
	add('PGP armor (JSON-escaped)', JSON.stringify(privateKey).slice(1, -1))
	armorLines.forEach((l, i) => add(`PGP armor line ${i + 1}/${armorLines.length}`, l))
	keystoreLeaves.forEach((l, i) => add(`keystore field ${i + 1}`, l))
	return { setup, needles, address: wallet.address, passwd, wallet }
}

// Returns the labels of every secret found in `text` (also checks the ANSI-stripped and unescaped forms).
const findSecrets = (text, needles) => {
	const forms = [text, stripAnsi(text), stripAnsi(text).replace(/\\n/g, '\n'), stripAnsi(text).replace(/'\s*\+\s*\n\s*'/g, '')]
	const hits = []
	for (const [label, value] of needles) if (forms.some(f => f.includes(value))) hits.push(label)
	return hits
}

const runStart = ({ setup, sudoExit, marker, settleMs, timeoutMs }) => new Promise(resolve => {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), 'si-keylog-t-'))
	fs.mkdirSync(path.join(home, '.CoNET-SI'))
	fs.writeFileSync(path.join(home, '.CoNET-SI', 'nodeSetup.json'), JSON.stringify(setup))
	const bin = path.join(home, 'bin')
	fs.mkdirSync(bin)
	fs.writeFileSync(path.join(bin, 'sudo'), `#!/bin/sh\necho "stub sudo $1" >&2\nexit ${sudoExit}\n`)
	fs.chmodSync(path.join(bin, 'sudo'), 0o755)

	const child = spawn(process.execPath, [startJs], {
		cwd: root,
		detached: true,
		env: { ...process.env, HOME: home, PATH: `${bin}:${process.env.PATH}`, FORCE_COLOR: '0' },
	})
	let out = ''
	let markerSeen = false
	let exitCode = null
	let settleTimer = null
	let done = false
	const finish = () => {
		if (done) return
		done = true
		clearTimeout(hardTimer)
		clearTimeout(settleTimer)
		try { process.kill(-child.pid, 'SIGKILL') } catch {}
		let savedSetupText = ''
		try { savedSetupText = fs.readFileSync(path.join(home, '.CoNET-SI', 'nodeSetup.json'), 'utf8') } catch {}
		fs.rmSync(home, { recursive: true, force: true })
		resolve({ out, markerSeen, exitCode, savedSetupText })
	}
	const onData = (d) => {
		out += d.toString()
		if (!markerSeen && out.includes(marker)) {
			markerSeen = true
			settleTimer = setTimeout(finish, settleMs)
		}
	}
	child.stdout.on('data', onData)
	child.stderr.on('data', onData)
	child.on('exit', (code) => { exitCode = code; setTimeout(finish, 500) })
	const hardTimer = setTimeout(finish, timeoutMs)
})

let fake
test.before(async () => { fake = await makeFake() })

test('1. setupSummary(): no secret survives, even with the decrypted key objects attached', () => {
	const { setupSummary } = require(summaryJs)
	const setup = {
		...fake.setup,
		sslDate: Date.now(),
		pgpKeyObj: { privateKeyObj: { armor: () => fake.setup.pgpKey.privateKey, secretMarker: fake.passwd }, publicKeyObj: {} },
		someFutureField: fake.passwd,
	}
	const summary = setupSummary(setup)
	const rendered = [
		JSON.stringify(summary),
		inspect(summary),
		inspect(summary, false, null, true),
		inspect(summary, { depth: 8, breakLength: 40 }),
		String(summary),
	].join('\n')
	assert.deepEqual(findSecrets(rendered, fake.needles), [])
	assert.equal(summary.walletAddress.toLowerCase(), fake.address.toLowerCase())
	assert.equal(summary.walletStore, 'present')
	assert.equal(summary.routeKeyArmor, 'present')
	assert.equal(summary.unlockSecret, 'set')
	// Missing setup and a setup without password are handled without throwing or printing secrets.
	assert.equal(setupSummary(null).setup, 'missing')
	assert.equal(setupSummary({ ...fake.setup, passwd: undefined }).unlockSecret, 'missing')
})

test('2. certificate renewal path, certbot fails: key material absent, no worker is started', async () => {
	const r = await runStart({ setup: { ...fake.setup }, sudoExit: 1, marker: "Didn't init SSL Certificate", settleMs: 4000, timeoutMs: 30000 })
	assert.ok(r.markerSeen, 'renewal path not reached')
	assert.deepEqual(findSecrets(r.out, fake.needles), [])
	// Existing behaviour (unchanged by this fix): a failed reissue rejects start() with no catch; the
	// uncaughtException handler in server.ts swallows it, so the master stays up without forking a worker.
	assert.ok(r.out.includes('Caught exception'), 'expected the swallowed unhandled rejection after a failed reissue')
	assert.ok(!r.out.includes(`Wallet address: ${fake.address}`), 'worker must not start after a failed reissue')
})

test('3. certificate renewal path, certbot succeeds: worker starts, saved setup intact, no key material in output', async () => {
	const r = await runStart({ setup: { ...fake.setup }, sudoExit: 0, marker: `Wallet address: ${fake.address}`, settleMs: 5000, timeoutMs: 60000 })
	assert.ok(r.markerSeen, 'worker did not start after the renewal path')
	assert.deepEqual(findSecrets(r.out, fake.needles), [])
	assert.ok(r.out.includes("Didn't init SSL Certificate"), 'renewal path must have run')
	const saved = JSON.parse(r.savedSetupText)
	assert.ok(typeof saved.sslDate === 'number', 'sslDate must be saved after a successful reissue')
	assert.equal(saved.passwd, fake.passwd, 'the setup file itself must keep its content')
})

test('4. normal start path: worker loads the keys, no key material in output', async () => {
	const r = await runStart({ setup: { ...fake.setup, sslDate: Date.now() }, sudoExit: 1, marker: `Wallet address: ${fake.address}`, settleMs: 6000, timeoutMs: 60000 })
	assert.ok(r.markerSeen, 'worker did not start')
	assert.deepEqual(findSecrets(r.out, fake.needles), [])
})

test('5. self-test: the matcher flags a raw dump of the fake setup (inspect and console.log forms)', () => {
	const rawInspect = inspect(fake.setup, false, 3, true)
	const rawJson = JSON.stringify(fake.setup)
	const rawArmor = JSON.stringify(fake.setup.pgpKey.privateKey)
	for (const raw of [rawInspect, rawJson, rawArmor, `gpg --passphrase "${fake.passwd}"`]) {
		assert.ok(findSecrets(raw, fake.needles).length > 0, 'matcher missed a secret: ' + raw.slice(0, 30))
	}
	// The multi-line armor is caught line by line even when only one line is printed.
	const oneLine = fake.setup.pgpKey.privateKey.split('\n').filter(l => l.length >= 20 && !l.startsWith('-----'))[1]
	assert.ok(findSecrets(`x ${oneLine} y`, fake.needles).length > 0)
	assert.deepEqual(findSecrets('Wallet address: 0x0000000000000000000000000000000000000001 started', fake.needles), [])
})
