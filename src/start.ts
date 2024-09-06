import Cluster from 'node:cluster'
import {cpus} from 'node:os'

import conet_si_server from './endpoint/server'
import {postOpenpgpRouteSocket, IclientPool, generateWalletAddress, getPublicKeyArmoredKeyID, getSetup, loadWalletAddress, makeOpenpgpObj, saveSetup, register_to_DL} from './util/localNodeCommand'
import {logger} from './util/logger'
import Colors from 'colors/safe'
import {exec} from 'node:child_process'
import {access, constants} from 'node:fs'
import {startExpressServer} from './endpoint/sslManager'

process.on ('uncaughtException', (err) => {
	console.error(err.stack)
	console.log("CONET node catch uncaughtException!!!\nNode NOT Exiting...")
})

const CertificatePATH = ['/etc/letsencrypt/live/slickstack/fullchain.pem','/etc/letsencrypt/live/slickstack/privkey.pem']

if (Cluster.isPrimary) {

	const _sslCertificate = (keyid: string) => new Promise((resolve, reject) => {
		const cmd = `sudo certbot certonly -v --noninteractive --agree-tos --cert-name slickstack --register-unsafely-without-email --webroot -w ${__dirname}/endpoint -d ${keyid}.conet.network`
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
		
	const testCertificateFiles = async () => {
		await Promise.all([
			//	@ts-ignore
			access(CertificatePATH[0], constants.R_OK),
			//	@ts-ignore
			access(CertificatePATH[1], constants.R_OK),

		])
	}

	const sslCertificate = async (publicKeyID: string) => new Promise(async (resolve, reject) => {
		logger(Colors.magenta(`Didn't init SSL Certificate! Try `))
		startExpressServer()
		//await _sslCertificate(publicKeyID)
		await testCertificateFiles()
		
	})
		
	

	const start = async () => {

		const initData:ICoNET_NodeSetup|null  = await getSetup ()
		if ( !initData?.keychain || initData?.passwd === undefined) {
			throw new Error (`Error: CONET Layer Minus Node have no setup data!\nPlease restart CoNET-SI with command: node dist/cli start!`)
		}
		try {
			initData.pgpKeyObj = await makeOpenpgpObj(initData.pgpKey.privateKey, initData.pgpKey.publicKey, initData.passwd)
		} catch (ex) {
			throw new Error (`Error: CONET Layer Minus Node have no setup data!\nPlease restart CoNET-SI with command: node dist/cli start!`)
		}
		const publicKeyID = initData.pgpKeyObj.publicKeyObj.getKeyIDs()[1].toHex().toUpperCase()

		if (!initData.sslDate) {
			await sslCertificate(publicKeyID)
		}
		
	}

	const startNode = () => {
		const worker = Math.floor(cpus().length/2)
		if (worker<2) {
			new conet_si_server()
		} else {
			for (let i = 0; i < worker; i ++) {
				Cluster.fork()
			}
		}
	}

	start()
	
} else {
	new conet_si_server()
}
