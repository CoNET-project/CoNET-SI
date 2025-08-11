import Cluster from 'node:cluster'
import {cpus} from 'node:os'

import conet_si_server from './endpoint/server'
import {postOpenpgpRouteSocket, IclientPool, generateWalletAddress, getPublicKeyArmoredKeyID, getSetup, makeOpenpgpObj, saveSetup, testCertificateFiles} from './util/localNodeCommand'
import {logger} from './util/logger'
import Colors, { inverse } from 'colors/safe'
import {exec} from 'node:child_process'
import {inspect} from 'node:util'
import {startExpressServer, stopServer} from './endpoint/sslManager'

const sslExpiration = 1000 * 60 * 60 * 24 * 30

if (Cluster.isPrimary) {

	let domain = 0
	const startNode = () => {
		
		const worker = Math.floor(cpus().length)
		logger(Colors.magenta(`startNode worker<2 = ${worker<2}`))
		// for (let i = 0; i < worker; i ++) {
			Cluster.fork()
		
		
		
	}

	const getDomain = () => {
		switch (domain) {
			case 3: {
				return 'theconetian.com'
			}
			case 1: {
				return 'openpgp.online'
			}
			case 2: {
				return 'conetlabs.org'
			}
			case 0:
			default: {
				return 'conet.network'
			}
		}
	}

	const _sslCertificate = (keyid: string) => new Promise((resolve, reject) => {
		
		const cmd = `sudo certbot certonly -v --noninteractive --agree-tos --cert-name slickstack --register-unsafely-without-email --webroot -w ${__dirname}/endpoint -d ${keyid}.${getDomain()}`
		return exec(cmd, (error, stdout, stderr) => {
			if (error) {
				logger(Colors.red(error.message))
				return reject (error)
			}

			if (stdout) {
				logger(Colors.blue(stdout))
			}
			if (stderr) {
				logger(Colors.magenta(stderr))
				
			}
			const cmd1 = `sudo chown peter:peter -R /etc/letsencrypt/`
			return exec(cmd1, () => {
				resolve (true)
			})
			
		})
	})

	
	const sslCertificate = async (publicKeyID: string, initData: ICoNET_NodeSetup) => {
		if (initData.sslDate) {
			const now = new Date().getTime()
			if (now - initData.sslDate < sslExpiration) {
				return startNode()
			}

		}
		logger(Colors.magenta(`Didn't init SSL Certificate! Try `))
		logger(inspect(initData, false, 3, true))
		startExpressServer()
		await _sslCertificate(publicKeyID)
		await testCertificateFiles()
		await stopServer()
		initData.sslDate = new Date().getTime()
		await saveSetup(initData, false)
		startNode()
	}

	const start = async () => {

		const initData: ICoNET_NodeSetup|null  = await getSetup ()
		if ( !initData?.keychain || initData?.passwd === undefined) {
			throw new Error (`Error: CONET Layer Minus Node have no setup data!\nPlease restart CoNET-SI with command: node dist/cli start!`)
		}
		try {
			initData.pgpKeyObj = await makeOpenpgpObj(initData.pgpKey.privateKey, initData.pgpKey.publicKey, initData.passwd)
		} catch (ex) {
			throw new Error (`Error: CONET Layer Minus Node have no setup data!\nPlease restart CoNET-SI with command: node dist/cli start!`)
		}

		const publicKeyID = initData.pgpKeyObj.publicKeyObj.getKeyIDs()[1].toHex().toUpperCase()

		
		return await sslCertificate(publicKeyID, initData)
	
	}


	const [,,...args] = process.argv
	if (args[0] ) {
		domain = parseInt(args[0])||0
	}

	start()
	
} else {
	new conet_si_server()
}
