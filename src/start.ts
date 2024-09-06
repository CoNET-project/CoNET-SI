import Cluster from 'node:cluster'
import {cpus} from 'node:os'
import conet_si_server from './endpoint/server'
import {postOpenpgpRouteSocket, IclientPool, generateWalletAddress, getPublicKeyArmoredKeyID, getSetup, loadWalletAddress, makeOpenpgpObj, saveSetup, register_to_DL} from './util/localNodeCommand'
import {logger} from './util/logger'
import Colors from 'colors/safe'
import {exec} from 'node:child_process'
import {fstat} from 'node:fs'

process.on ('uncaughtException', (err) => {
	console.error(err.stack)
	console.log("CONET node catch uncaughtException!!!\nNode NOT Exiting...")
})


if (Cluster.isPrimary) {


	const sslCertificate = (keyid: string) => {
		const cmd = `sudo certbot certonly -v --noninteractive --agree-tos --cert-name slickstack --register-unsafely-without-email --webroot -w ${__dirname} -d ${keyid}.conet.network`
		exec(cmd, (error, stdout, stderr) => {
			if (error) {
				logger(Colors.red(error.message))
			}
			if (stdout) {
				logger(Colors.blue(stdout))
			}
			if (stderr) {
				logger(Colors.magenta(stderr))
			}
		})
	}

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
			logger(Colors.magenta(`Didn't init SSL Certificate`))
			sslCertificate(publicKeyID)
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
