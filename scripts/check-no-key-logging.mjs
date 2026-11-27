#!/usr/bin/env node
/**
 * Checks that the node never writes key material to its log.
 *
 * Runs the built `dist/start.js` twice with a throw-away HOME that holds a fake node setup
 * (PGP key, wallet keystore and password all generated here, never real ones):
 *   1. certificate-renewal path: no sslDate, so start.ts renews the certificate first
 *   2. normal start path: fresh sslDate, so the worker starts and loads the keys
 * `sudo` is replaced by a stub that fails, so certbot / systemctl / reboot never run.
 * The worker also talks to the public CoNET RPC while it is up; that does not matter here.
 *
 * Fails if the captured stdout/stderr contains `BEGIN PGP PRIVATE`, `passwd`, `privateKey`,
 * `keychain`, or any of the fake secret values.
 *
 * Usage: npm run build && node scripts/check-no-key-logging.mjs [--show]
 *   --show  also print the captured output (fake values only)
 */
import { spawn } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'
import { randomBytes } from 'node:crypto'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const require = createRequire(import.meta.url)
const { generateKey } = require(join(root, 'node_modules/openpgp'))
const { Wallet } = require(join(root, 'node_modules/ethers'))

const startJs = join(root, 'dist/start.js')
if (!existsSync(startJs)) {
	console.error('dist/start.js missing; run `npm run build` first')
	process.exit(2)
}

const makeFakeSetup = async () => {
	const passwd = `fake-test-pass-${randomBytes(8).toString('hex')}`
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
		pgpKey: { privateKey, publicKey, keyID: '' },
		DL_registeredData: '',
		cpus: 1,
		passwd,
		platform_verison: 'test',
		dl_publicKeyArmored: '',
		restartBlockNumber: 0,
	}
	const armorLines = privateKey.split('\n').filter(l => l.length > 40)
	const needles = [
		['literal BEGIN PGP PRIVATE', 'BEGIN PGP PRIVATE'],
		['literal passwd', 'passwd'],
		['literal privateKey', 'privateKey'],
		['literal keychain', 'keychain'],
		['fake password value', passwd],
		['fake wallet private key', wallet.privateKey.slice(2)],
		['fake keystore ciphertext', JSON.parse(keychain).Crypto?.ciphertext ?? JSON.parse(keychain).crypto?.ciphertext],
		['fake PGP private armor body', armorLines[Math.floor(armorLines.length / 2)]],
	].filter(([, v]) => v)
	return { setup, needles, address: wallet.address }
}

const runCase = ({ name, setup, marker, settleMs, timeoutMs }) => new Promise(resolve => {
	const home = mkdtempSync(join(tmpdir(), 'si-keylog-'))
	mkdirSync(join(home, '.CoNET-SI'))
	writeFileSync(join(home, '.CoNET-SI', 'nodeSetup.json'), JSON.stringify(setup))
	const bin = join(home, 'bin')
	mkdirSync(bin)
	writeFileSync(join(bin, 'sudo'), '#!/bin/sh\necho "stub sudo refused" >&2\nexit 1\n')
	chmodSync(join(bin, 'sudo'), 0o755)

	const child = spawn(process.execPath, [startJs], {
		cwd: root,
		detached: true,
		env: { ...process.env, HOME: home, PATH: `${bin}:${process.env.PATH}`, FORCE_COLOR: '0' },
	})
	let out = ''
	let markerSeen = false
	let settleTimer = null
	const finish = () => {
		clearTimeout(hardTimer)
		clearTimeout(settleTimer)
		try { process.kill(-child.pid, 'SIGKILL') } catch {}
		rmSync(home, { recursive: true, force: true })
		resolve({ name, out, markerSeen })
	}
	const onData = d => {
		out += d.toString()
		if (!markerSeen && out.includes(marker)) {
			markerSeen = true
			settleTimer = setTimeout(finish, settleMs)
		}
	}
	child.stdout.on('data', onData)
	child.stderr.on('data', onData)
	child.on('exit', () => setTimeout(finish, 500))
	const hardTimer = setTimeout(finish, timeoutMs)
})

const { setup, needles, address } = await makeFakeSetup()
const cases = [
	{
		name: 'certificate renewal path (start.ts sslCertificate)',
		setup: { ...setup },
		marker: "Didn't init SSL Certificate",
		settleMs: 4_000,
		timeoutMs: 30_000,
	},
	{
		name: 'normal start path (worker initSetupData)',
		setup: { ...setup, sslDate: Date.now() },
		marker: `Wallet address: ${address}`,
		settleMs: 6_000,
		timeoutMs: 60_000,
	},
]

let failed = false
for (const c of cases) {
	const r = await runCase(c)
	const lines = r.out.split('\n')
	if (process.argv.includes('--show')) console.log(`----- ${c.name} -----\n${r.out}\n-----`)
	const hits = []
	for (const [label, value] of needles) {
		const at = lines.findIndex(l => l.includes(value))
		if (at >= 0) hits.push(`${label} (output line ${at + 1})`)
	}
	if (!r.markerSeen) {
		failed = true
		console.log(`FAIL ${c.name}: path not reached (marker "${c.marker}" not in output, ${lines.length} lines)`)
		console.log(r.out.split('\n').slice(-15).map(l => '    ' + l.slice(0, 160)).join('\n'))
	} else if (hits.length) {
		failed = true
		console.log(`FAIL ${c.name}: ${hits.length} leak(s): ${hits.join('; ')}`)
	} else {
		console.log(`PASS ${c.name}: ${lines.length} lines, no key material`)
	}
}
process.exit(failed ? 1 : 0)
