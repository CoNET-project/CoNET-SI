
import { stat, mkdir, writeFile } from 'node:fs'
import { homedir, networkInterfaces, cpus } from 'node:os'
import { join } from 'node:path'
import { Writable } from 'node:stream'
import { get, request, RequestOptions } from 'node:https'
import { deflate, unzip } from 'node:zlib'
import { inspect } from 'node:util'
import { exec } from 'node:child_process'
import { createConnection } from 'node:net'
import type { NetConnectOpts } from 'node:net'
import { series } from 'async'
import { createHash, webcrypto } from 'node:crypto'
import Accounts from 'web3-eth-accounts'
import type { WalletBase } from 'web3-core'
import { createInterface } from 'readline'

import { publicKeyByPrivateKey, encryptWithPublicKey, cipher, hash, hex, publicKey, createIdentity, recover } from 'eth-crypto'

//	@ts-ignore
import {sign} from 'eth-crypto'

import { Buffer } from 'buffer'
import { generateKey, readKey, readPrivateKey, decryptKey, createCleartextMessage, sign as pgpSign, readMessage, decrypt, encrypt, createMessage, enums } from "openpgp"
import type { KeyID as typeOpenPGPKeyID } from 'openpgp'
import Colors from 'colors/safe'
import { getCoNETCashBalance, regiestNewCustomer } from './dl'
import type { GenerateKeyOptions, Key, PrivateKey, Message, MaybeStream, Data, DecryptMessageResult, WebStream, NodeStream } from 'openpgp'

import type { Response, Request } from 'express'


type IdecryptedObjText = DecryptMessageResult & {
	data: string
}

type IdecryptedObj = DecryptMessageResult & {
	data: string|WebStream<string> | NodeStream<string>
}

//import hexdump from 'hexdump-nodejs'

export const logger = ( ...argv: any ) => {
    const date = new Date ()
    let dateStrang = `[${ date.getHours() }:${ date.getMinutes() }:${ date.getSeconds() }:${ date.getMilliseconds ()}]`
    return console.log ( Colors.yellow( dateStrang ), ...argv )
}

const otherRespon = ( body: string| Buffer, _status: number ) => {
	const Ranges = ( _status === 200 ) ? 'Accept-Ranges: bytes\r\n' : ''
	const Content = ( _status === 200 ) ? `Content-Type: text/html; charset=utf-8\r\n` : 'Content-Type: text/html\r\n'
	const headers = `Server: nginx/1.6.2\r\n`
					+ `Date: ${ new Date ().toUTCString()}\r\n`
					+ Content
					+ `Content-Length: ${ body.length }\r\n`
					+ `Connection: keep-alive\r\n`
					+ `Vary: Accept-Encoding\r\n`
					//+ `Transfer-Encoding: chunked\r\n`
					+ '\r\n'

	const status = _status === 200 ? 'HTTP/1.1 200 OK\r\n' : 'HTTP/1.1 404 Not Found\r\n'
	return status + headers + body
}

export const return404 = () => {
	const kkk = '<html>\r\n<head><title>404 Not Found</title></head>\r\n<body bgcolor="white">\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx/1.6.2</center>\r\n</body>\r\n</html>\r\n'
	return otherRespon ( Buffer.from ( kkk ), 404 )
}

const jsonResponse = ( body: string ) => {
	const headers = `Server: nginx/1.6.2\r\n`
		+ `Date: ${ new Date ().toUTCString()}\r\n`
		+ `Content-Type: application/json; charset=utf-8\r\n`
		+ `Content-Length: ${ body.length }\r\n`
		+ `Connection: keep-alive\r\n`
		+ `Vary: Accept-Encoding\r\n`
		//+ `Transfer-Encoding: chunked\r\n`
		+ '\r\n'
	const status = 'HTTP/1.1 200 OK\r\n'
	return status + headers + body
}

export const returnHome = () => {
	const kkk = 
`<!DOCTYPE html>
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
	return kkk
}

export const rfc1918 = /(^0\.)|(^10\.)|(^100\.6[4-9]\.)|(^100\.[7-9]\d\.)|(^100\.1[0-1]\d\.)|(^100\.12[0-7]\.)|(^127\.)|(^169\.254\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.0\.0\.)|(^192\.0\.2\.)|(^192\.88\.99\.)|(^192\.168\.)|(^198\.1[8-9]\.)|(^198\.51\.100\.)|(^203.0\.113\.)|(^22[4-9]\.)|(^23[0-9]\.)|(^24[0-9]\.)|(^25[0-5]\.)/

export const setupPath = '.CoNET-SI'
const homeDir = homedir ()
const setupFileDir = join ( homeDir, setupPath )
const setupFile = join ( setupFileDir, 'nodeSetup.json')
const CoNetCashDataPath = join (setupFileDir,'.CoNETCashData')
const CoNetCashClientCachePath = join (setupFileDir, '.Cache')
const publicRouteURL = `https://s3.us-east-1.wasabisys.com/conet-mvp/router/`

export const getSetup:() => Promise<ICoNET_NodeSetup|null>  = ( ) => {
	
	return new Promise (resolve => {
		return stat( setupFileDir, err => {
			if ( err ) {
				logger (`checkSetupFile: have no .CoNET-SI directory`)
				return mkdir ( setupFileDir, err => {
					return resolve (null)
				})
			}
			let nodeSetup: ICoNET_NodeSetup
			try {
				nodeSetup = require (setupFile)
			} catch (ex) {
				return resolve (null)
			}
			return resolve ( nodeSetup )
		})
	})
	
}

export const getServerIPV4Address = ( includeLocal: boolean ) => {
	const nets = networkInterfaces()
	const results = []
	if (!nets) {
		return null
	}
	for ( const name of Object.keys( nets )) {
		//	@ts-ignore
		for (const net of nets[ name ]) {
			if ( net.family === 'IPv4' && !net.internal ) {
				// if (!results[ name ]) {
				// 	results[ name ] = []
				// }
				if (!includeLocal ) {
					if ( rfc1918.test (net.address)) {
						logger (`${net.address} is local`)
						continue
					}
				}
				results.push( net.address )
			}
		}
	}
	return results
}

export const generateWalletAddress = ( password: string ) => {

	//	@ts-ignore
	const accountw: Accounts.Accounts = new Accounts()

	const acc = accountw.wallet.create(1)
	const uu1 = acc.encrypt ( password )

	return (uu1)
}

export const generatePgpKey = async (walletAddr: string, passwd: string ) => {
	const option: GenerateKeyOptions = {
        type: 'ecc',
		passphrase: passwd,
		userIDs: [{
			name: walletAddr
		}],
		curve: 'curve25519',
        format: 'armored',
	}


	const { privateKey, publicKey } = await generateKey  (
		// @ts-ignore
		option)

	const keyObj = await readKey ({armoredKey: publicKey})
	const keyID = keyObj.getKeyIDs()[1].toHex().toUpperCase ()
	return ({privateKey, publicKey, keyID})
}

export const loadWalletAddress = ( walletBase: any, password: string ) => {

	//	@ts-ignore
	const account = <Accounts.Accounts> new Accounts()

	const uu = <WalletBase & {publickey: string} []> account.wallet.decrypt ( walletBase, password )

	uu[0].publickey = publicKeyByPrivateKey (uu[0].privateKey)
	return uu
}

export const makeOpenpgpObj = async ( privateKey: string, publicKey: string, passphrase: string ) => {
	const publicKeyObj = await readKey ({ armoredKey: publicKey })
	const privateKeyObj = await decryptKey ({ privateKey: await readPrivateKey ({armoredKey: privateKey}), passphrase })
	const ret: pgpObj = {
		publicKeyObj,
		privateKeyObj
	}
	return (ret)
}

export const saveSetup = ( setup: ICoNET_NodeSetup, debug: boolean ) => {

	const setupFile = join ( setupFileDir, 'nodeSetup.json')
	const setupInfo: ICoNET_NodeSetup = {
		keychain: setup.keychain,
		ipV4: setup.ipV4,
		ipV6: '',
		ipV4Port: setup.ipV4Port,
		ipV6Port: setup.ipV6Port,
		storage_price: setup.storage_price,
		outbound_price: setup.outbound_price,
		pgpKey: setup.pgpKey,
		DL_registeredData: setup.DL_registeredData,
		cpus: cpus().length,
		passwd: setup.passwd,
		platform_verison: setup.platform_verison,
		dl_publicKeyArmored: setup.dl_publicKeyArmored
	}

	return new Promise(resolve => {

		return writeFile (setupFile, JSON.stringify (setupInfo), 'utf-8', err => {
			if ( err ) {
				logger (`saveSetup [${setupFile}] Error!`, err )
				resolve (false)
			}
			logger (`saveSetup [${setupFile}] Success!` )
			return resolve (true)
		})
	})

}

export const waitKeyInput: (query: string, password: boolean ) => Promise<string> 
	= ( query: string, password = false ) => {

	const mutableStdout = <Writable & {muted: boolean} > new Writable ({
		write: ( chunk, encoding, next ) => {
			if (! mutableStdout.muted ) {
				process.stdout.write (chunk, encoding)
			}
			return next()
		}
	})
	
	const rl = createInterface ({
		input: process.stdin,
        output: mutableStdout,
		terminal: true
	})

	return new Promise ( resolve => {
		rl.question ( Colors.green( query ), ans => {
			rl.close()
			return resolve(ans)
		})
		return mutableStdout.muted = password
	})
}

const conetDLServer = 'openpgp.online'
const conetDLServerPOST = 443
const conetDLServerTimeout = 1000 * 60

export const splitIpAddr = (ipaddress: string ) => {
	if (!ipaddress?.length) {
		logger (Colors.red(`splitIpAddr ipaddress have no ipaddress?.length`), inspect( ipaddress, false, 3, true ))
		return ''
	}
	const _ret = ipaddress.split (':')
	return _ret[_ret.length - 1]
}


export const requestUrl = (option: RequestOptions, postData: string) => {

	return new Promise((resolve) => {
		const req = request (option, res => {
			clearTimeout (timeout)
			logger (Colors.blue(`Connect to DL Server [${option.path}]`))

			if (res.statusCode !== 200 ) {

				logger (Colors.red(`DL Server response !200 code [${ res.statusCode }]`))
				return resolve (null)
			}
			let ret = ''
			res.setEncoding('utf8')

			res.on('data', chunk => {
				ret += chunk
			})

			res.once ('end', () => {
				let retJson = null
				try {
					retJson = JSON.parse (ret)
				} catch (ex) {
					logger (Colors.red(`DL Server response no JSON error! [${ ret }]`))
					return resolve (null)
				}
				return resolve (retJson)
			})
		})

		req.on ('error', err => {
			resolve (null)
			return logger (`register_to_DL postToServer [${ inspect(option, false, 3, true) }] error`, err )
		})

		if ( postData ) {
			req.write(postData)
		}



		const timeout = setTimeout (() => {
			logger (Colors.red(`requestUrl [${option.method} ${ option.hostname }:${option.port}${option.path}] on TIMEOUT Error!`))
			return resolve (null)
		}, conetDLServerTimeout)
		
		return req.end()
	})
	
}

const signCleartext = async ( signingKeys: PrivateKey, _message: string ) => {
	const message = await createCleartextMessage ({text: _message})
	return (await pgpSign ({ message, signingKeys }))
}

export const proxyRequest = async (clientReq: Request, clientRes: Response, webUrl: string ) => {

	return get(webUrl, res => {
		if (/\.js$/.test(webUrl)) {
			clientRes.setHeader('Content-Type','text/javascript')

		}
		res.pipe (clientRes).once ('close', () => {
			if (clientRes.writable && typeof clientRes.end === 'function') {
				logger (Colors.blue (`Close [${splitIpAddr ( clientReq.ip )}] connecting.`))
				clientRes.end()
			}
		})
		
	}).once ('error', error => {
		logger (Colors.red (`proxyRequest get [${ webUrl }] Error`), error )
	})
}

const getDLPublicKey = async () => {
	const option: RequestOptions = {
		hostname: conetDLServer,
		port: conetDLServerPOST,
		path: '/api/publishGPGKeyArmored',
		method: 'GET',
		headers: {
			'Content-Type': 'application/json',
			'Content-Length': 0
		},
		rejectUnauthorized: false
	}
	const response: any = await requestUrl (option, '')
	if (!response?.publishGPGKey) {
		return null
	}

	return response.publishGPGKey
}

export const register_to_DL = async ( nodeInit: ICoNET_NodeSetup ) => {
	if (!nodeInit) {
		return false
	}

	const wallet = nodeInit.keyObj[0]


	if ( !nodeInit.dl_publicKeyArmored) {
		nodeInit.dl_publicKeyArmored = await getDLPublicKey()
	}

	if ( !nodeInit.dl_publicKeyArmored ) {
		return null
	}

	const data: ICoNET_DL_POST_register_SI = {
		ipV4Port: nodeInit.ipV4Port,
		ipV4: nodeInit.ipV4,
		storage_price:  nodeInit.storage_price,
		outbound_price: nodeInit.outbound_price,
		walletAddr: wallet.address,
		cpus: cpus().length,
		platform_verison: nodeInit.platform_verison,
		nft_tokenid: createHash('sha256').update(nodeInit.ipV4).digest('hex'),
		armoredPublicKey: nodeInit.pgpKey.publicKey,
		//	@ts-ignore
		walletAddrSign: sign( wallet.privateKey, hash.keccak256(wallet.address))
	}


	const payload = {
		pgpMessage: await EncryptePGPMessage (data, nodeInit.dl_publicKeyArmored, nodeInit.pgpKeyObj?.privateKeyObj)
	}

	const postJSON = JSON.stringify(payload)

	const option: RequestOptions = {
		hostname: conetDLServer,
		port: conetDLServerPOST,
		path: '/api/conet-si-node-register',
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Content-Length': Buffer.byteLength( postJSON )
		},
		rejectUnauthorized: false
	}

	logger (`register_to_DL [${ inspect(option, false, 3, true )}] connect to DL server`)

	const response: any = await requestUrl (option, postJSON)

	logger (`register_to_DL response is\n`, response)

	return response
}

const healthTimeout = 1000 * 60 * 5

export const si_healthLoop = async ( nodeInit: ICoNET_NodeSetup ) => {
	const wallet = nodeInit.keyObj[0]

	const _payload: ICoNET_DL_POST_health_SI = {
		nft_tokenid: createHash('sha256').update(nodeInit.ipV4).digest('hex'),
		armoredPublicKey: nodeInit.pgpKey.publicKey,
		platform_verison: nodeInit.platform_verison,
		walletAddr: wallet.address,
		//	@ts-ignore
		walletAddrSign: sign( wallet.privateKey, hash.keccak256(wallet.address))
	}
	logger (_payload)
	const payload = {
		pgpMessage:  await EncryptePGPMessage (_payload, nodeInit.dl_publicKeyArmored, nodeInit.pgpKeyObj?.privateKeyObj)
	}

	const postJSON = JSON.stringify(payload)

	const option: RequestOptions = {
		hostname: conetDLServer,
		port: conetDLServerPOST,
		path: '/api/si-health',
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Content-Length': Buffer.byteLength( postJSON )
		},
		rejectUnauthorized: false
	}

	const _si_healthLoop = async () => {
		const response: any = await requestUrl (option, postJSON)
		logger (`si_health response is\n`, response)
	
		if ( response === null ) {
			logger (Colors.red(`si_health DL return 404 try to regiest again!`))
			await register_to_DL (nodeInit)
		}

		setTimeout( async () => {
			_si_healthLoop ()
		},  healthTimeout )
	}
		
	_si_healthLoop ()
}

export const regiestPrivateKey = ( privateKey: string, password: string ) => {

	return new Promise (resolve => {
		if ( !privateKey || privateKey.length < 50 ) {
			logger (`regiestPrivateKey Error! !privateKey[${privateKey}] || [${ privateKey.length }]privateKey.length < 50 `)
			return resolve (false)
		}
		const cmd = `echo -n "${ privateKey }" | gpg ${ password ? '--pinentry-mode loopback --batch --passphrase ' + '"' + password + '"' : ''} --import`
		
		return  exec ( cmd, ( err, data, data1: string ) => {
			if ( err  ) {
				logger (Colors.red(`regiestPrivateKey exec command ERROR!\n`), Colors.grey (cmd))
				return resolve (false)
			}
			logger (Colors.green(`regiestPrivateKey SUCCESS`))
			return resolve ( true )
		})
	})

}

export const startPackageSelfVersionCheckAndUpgrade = async (packageName: string ) => {
	

	const execCommand = (command: string ) => {

		return new Promise ( resolve => {
			let u = ''
			let stderr: Error|null = null

			logger (Colors.magenta(`execCommand doing [${ command }]`))
			const running = exec ( command )

			if ( running.stdout ) {
				running.stdout.on ('data', data => {
					u += data.toString()
				})
			}

			if (running.stderr) {
				running.stderr.once ('error', err => {
					stderr = err
				})
			}

			running.once ('exit', () => {
				if ( stderr ) {
					return resolve (null)
				}
				if ( u.length ) {
					logger (Colors.blue(`execCommand stdout\n`), u)
					return resolve (true)
				}
				return resolve (false)
			})
		})
	}

	const cmd1 = await execCommand (`npm outdated -g | grep ${packageName}`)
	if ( cmd1 === null ) {
		logger (Colors.red(`execCommand npm outdated -g | grep ${packageName} had ERROR!`))
		return (null)
	}
	if ( cmd1 === false ) {
		logger (Colors.blue(`startPackageSelfVersionCheckAndUpgrade ${packageName} already has updated!`))
		return (false)
	}
	logger (`startPackageSelfVersionCheckAndUpgrade doing upgrade now!`)
	const cmd2 = await execCommand  (`sudo npm cache clean --force && sudo npm i ${packageName} -g`)
	if ( cmd2 === null ) {
		logger (Colors.red(`execCommand [sudo npm cache clean --force && sudo npm i ${packageName} -g] had ERROR!`))
		return (null)
	}
	logger (Colors.blue(`startPackageSelfVersionCheckAndUpgrade ${packageName} have new version and upgrade success!`))
	return (true)
}

export const getPublicKeyArmoredKeyID = async (publicKeyArmored: string) => {
	const keyObj = await readKey ({armoredKey: publicKeyArmored})
	return keyObj.getKeyIDs()[1].toHex().toUpperCase()
}

const EncryptePGPMessage = async (message: string|any, publicKeyObj: any, PrivateKeyObj: any) => {
	return await encrypt ({
		message: typeof message === 'string' ? (await createMessage ({text: message})): (await createMessage ({text: Buffer.from(JSON.stringify(message)).toString('base64')})),
		encryptionKeys: typeof publicKeyObj === 'string' ? await readKey ({armoredKey: publicKeyObj}): publicKeyObj,
		signingKeys: PrivateKeyObj,
		config: { preferredCompressionAlgorithm: enums.compression.zlib }
	})
}

const decryptMessage = async (encryptedText: string|Message<MaybeStream<Data>>, privateKeyObj: PrivateKey|string, passed:string ) => {
	let decryptionKeys = privateKeyObj

	if ( typeof decryptionKeys === 'string') {
		const privateKey = await readPrivateKey ({armoredKey: decryptionKeys})
		if (!privateKey.isDecrypted()) {
			decryptionKeys = await decryptKey({
				privateKey,
				passphrase: passed
			})
		} else {
			decryptionKeys = privateKey
		}
	}
	let message = encryptedText
	if ( typeof encryptedText === 'string') {
		message = await readMessage({armoredMessage: encryptedText})
	}

	const decrypted = await decrypt ({
		//	@ts-ignore
		message,
		decryptionKeys
	})

	return decrypted
}

export const initCoNetCashDataPath = () => {
	return new Promise ( resolve => {
		return stat (CoNetCashDataPath, err => {
			if (err) {
				return mkdir (CoNetCashDataPath, err => {
					return resolve(true)
				})
			}
			return resolve(true)
		})
	})
}

const saveCoNETCashData = async (publicGPGKeyID: string, jsonData: SI_Client_CoNETCashData) => {
	const setupFile = join ( CoNetCashDataPath, `${publicGPGKeyID}.json` )
	await initCoNetCashDataPath ()
	return new Promise ( resolve => {
		logger (`saveCoNETCashData ${setupFile}`)
		return writeFile (setupFile, JSON.stringify (jsonData), 'utf-8', err => {
			
			if (err) {
				logger (Colors.red(`saveCoNETCashData Error`), err)
				return resolve (false)
			}
			return resolve (true)
		})
	})
}

const getCoNETCashData = async (publicGPGKeyID: string) => {

	const setupFile = join ( CoNetCashDataPath, `${publicGPGKeyID}.json` )
	
	let data: SI_Client_CoNETCashData
	try {
		data = require (setupFile)
	} catch (ex) {
		logger (Colors.red(`getCoNETCashData [${ setupFile }] had error!`))
		return null
	}
	return data
}

const checkAndMakeDir = (dirname: string) => {
	return new Promise (_resolve => {
		return stat(dirname, err => {
			if (err) {
				return mkdir (dirname, err => {
					return _resolve(null)
				})
			}
			return _resolve(null)
		})
	})
}

const saveClientCache = (publicGPGKeyID: string, encryptedText: string, timeNumber: number ) => {
	return new Promise( async resolve => {
		const ClientFolder = join (CoNetCashClientCachePath, publicGPGKeyID)
		const fileName = join ()
		await checkAndMakeDir (CoNetCashClientCachePath)
		await checkAndMakeDir (ClientFolder)
		
	})
}

const getRouterFromKeyID = (keyID: string) => {
	return new Promise (resolve => {
		const url = `${publicRouteURL}${keyID}`
		return get(url, res => {
			if( res.statusCode === 404) {
				logger (Colors.grey(`getRouterFromKeyID [${ url }] return 404 not found `))
				res.emit ('end')
				return resolve (false)
			}
			if (res.statusCode !== 200) {
				res.emit ('end')
				return (null)
			}
			let ret = ''
			res.on ('data', _data => {
				ret += _data
			})
			res.once ('end', () => {
				logger (`res.once ('end') code=[${res.statusCode}]`)
				if (res.statusCode === 200) {
					let retJson: ICoNET_Router
					try {
						retJson = JSON.parse(ret)
					} catch (ex) {
						return resolve (false)
					}
					return resolve (retJson)
				}
			})

		}).once ('error', error => {
			logger (Colors.red (`getRouterFromKeyID connest to [${ url }] Error`), error )
			return resolve (null)
		})
	})
}

const routerPost = ( url: string, clientReq: Request, clientRes: Response, data: string) => {
	const option: RequestOptions = {
		hostname: url,
		path: '/post',
		port: 443,
		method: 'POST'
	}
	logger (Colors.blue(`routerPost connect to [https://${ url }/post]`))
	const req = request (option)

		// if ( res.statusCode === undefined ) {
		// 	logger (`routerPost to host [${ url }] res.statusCode === undefined Error! STOP client connection!`)
		// 	return clientRes.sendStatus(503).end()
		// }

		// clientRes.sendStatus (res.statusCode)
		// for (let i = 0; i < res.rawHeaders.length; i += 2) {
		// 	clientRes.setHeader(`"${res.rawHeaders[i]}"`, `"${res.rawHeaders[i+1]}"`)
		// }
		// res.pipe (clientRes)
		
	.once ('error', err => {
		logger (`routerPost req once ('error')`, err )
	})
	req.socket?.pipe (clientRes).once('close', () => {
		logger (Colors.blue (`routerPost [${ url }] once end, close clientRes`))
		clientRes.end()
	})

	req.write (data+'\r\n\r\n')
}

const socketPost = (ipAddr: string, port: number, clientRes: Response, data: string) => {
	const postData = JSON.stringify({data})

	const rawHttpRequest = `POST /post HTTP/1.1\r\nHost: ${ipAddr}\r\nAccept: */*\r\nConnection: keep-alive\r\ncontent-type: application/json\r\nContent-Length: ${ postData.length }\r\n\r\n${ postData }\r\n\r\n`

	const url = `[${ipAddr}:${port}]`
	let u = ''
	const conn = createConnection ( port, ipAddr, () => {

		logger (Colors.blue (`Connecting to Router ${ url } success !`))

		conn.setNoDelay(true)
		conn.pipe (clientRes)
		conn.write (rawHttpRequest)

	}).once ('end', () => {
		logger (Colors.green(`socketPost to router node ${url} once END event`), Colors.grey(u))
		clientRes.end()
	}).once ('error', err => {
		logger (Colors.red(`socketPost router node ${ url } on error STOP connect \n`), err )
		if (clientRes.writable) {
			clientRes.end()
		}
	})
	
	
}

const forwardConnectTimeOut = 30*1000

const forwardEncryptedText = async (clientReq: Request, clientRes: Response, encryptedText: string, gpgPublicKeyID: string, onlineClientPool: IclientPool[], outbound_price: number, storage_price: number, selfIpv4: string ) => {
	
	const client = await getCoNETCashData (gpgPublicKeyID)

	//			is the keyID client in node
	if ( client ) {

		return customerData (clientReq, clientRes, encryptedText, gpgPublicKeyID, client, onlineClientPool, outbound_price,storage_price)
	}

	//			forward encrypted text
	const _route = await getRouterFromKeyID (gpgPublicKeyID)
	if ( !_route ) {
		logger (`forwardEncryptedText can not find router [${ gpgPublicKeyID }]`)
		return clientRes.status(404).end ()
	}

	

	const router1: ICoNET_Router = _route

	if ( router1.ipv4 === selfIpv4 ) {
		logger (Colors.red(`forwardEncryptedText customer used old GPG Public key`))
		return clientRes.status(404).end ()
	}

	if (!router1.ipv4 ) {
		logger (`forwardEncryptedText got ICoNET_Router but have not ip address router1 =[${ inspect(router1, false, 3, true) }]`)
		return clientRes.status(404).end ()
	}

	const url = `${ gpgPublicKeyID }.openpgp.online`

	return socketPost( router1.ipv4, 80, clientRes, encryptedText)

}

export type IclientPool = {
	clientReq: Request
	clientRes: Response
	gpgPublicKeyID: string
	forwardNumber: number
}
const ByteToMByte = 0.000001

const customerData =  async (clientReq: Request, clientRes: Response, encryptedText: string, customerKeyID: string, client: SI_Client_CoNETCashData, onlineClientPool: IclientPool[], outbound_price: number, storage_price: number ) => {
	
	const clientConnectingIndex = onlineClientPool.findIndex(n => n.gpgPublicKeyID === customerKeyID)
	const length = encryptedText.length/ByteToMByte
	//			have no connect
	if ( clientConnectingIndex < 0) {
		logger (Colors.blue (`Encrypted Message develived to a offline customer [${ customerKeyID }] length [${ length }]Mbyte, store it to cache`))
		
		const use_history: use_history = {
			type: 'storage',
			data_length: length,
			price: storage_price,
			fee: 0,
			date: new Date().getTime()
		}
		if ( client.walletKeyArray[0].unpaid?.length ) {
			client.walletKeyArray[0].unpaid.unshift(use_history)
		} else {
			client.walletKeyArray[0].unpaid = [use_history]
		}

		clientRes.end ()
		await saveClientCache (customerKeyID, encryptedText, use_history.date)
		return await saveCoNETCashData (customerKeyID, client)
	}

	const connect = onlineClientPool[clientConnectingIndex]
	//		Forward data to a online client
	const use_history: use_history = {
		type: 'outbound',
		data_length: length,
		price: outbound_price,
		fee: outbound_price * length * connect.forwardNumber,
		date: new Date().getTime()
	}

	if ( client.walletKeyArray[0].unpaid?.length ) {
		client.walletKeyArray[0].unpaid.unshift(use_history)
	} else {
		client.walletKeyArray[0].unpaid = [use_history]
	}

	logger (Colors.blue(`customerData forward to a online client forwardNumber length [${ use_history.data_length }] [${connect.forwardNumber}] [${ splitIpAddr(clientReq.ip)}] cost=[${ use_history.fee }]`))
	
	return connect.clientRes.write(`data: ${encryptedText}\n\n`)
}

const encryptWebCrypt = async (keyJSON: webcrypto.JsonWebKey, _iv: string, command: SICommandObj ) => {

	const key = await webcrypto.subtle.importKey('jwk', keyJSON, {name: 'AES-CBC', length: 256, hash: 'SHA-512'}, true, ['encrypt', 'decrypt'])
	const iv = Buffer.from (_iv,'base64')
	const dec = new TextEncoder()
	const data = dec.encode(JSON.stringify(command))
	const encryptText = await crypto.subtle.encrypt({
		name: 'AES-CBC',
		iv,
	  	}, key, data)
	return (Buffer.from(encryptText).toString('base64'))
}

const localNodeCommand = async (clientReq: Request, clientRes: Response, decryptedObj: IdecryptedObjText, encryptedByPublicKeyID: string, onlineClientPool: IclientPool[], outbound_price: number, storage_price: number ) => {

	//			Forward encrypted text have not STOP in ths node so it allow have no signature
	if (!decryptedObj.signatures?.length) {

		logger (Colors.red(`localNodeCommand Have no signatures ERROR!\n`))
		return clientRes.status(400).end ()
	}

	let command: SICommandObj

	try {
		command = JSON.parse ( Buffer.from ( decryptedObj.data, 'base64').toString())
	} catch (ex) {
		logger (Colors.red(`postOpenpgpRoute localNodeCommand decrypted Obj JSON ERROR!\n`), Colors.grey (clientReq.body.data), '\n')
		return clientRes.status(400).end ()
	}

	//				have no publicKeyArmored included
	if ( typeof command?.publicKeyArmored !== 'string' || !command.publicKeyArmored.length || !decryptedObj.signatures.length ) {
		logger (Colors.red(`postOpenpgpRoute localNodeCommand decrypted Obj SICommandObj have no signatures key information ERROR!\n`), inspect(command, false, 3, true))
		return clientRes.status(400).end ()
	}
	//			Check signatures, publicGpgKey match
	const _clientKeyID = decryptedObj.signatures[0].keyID.toHex().toUpperCase ()
	
	if ( ! checkSignMatchPublicKeyArmored ( _clientKeyID, command.publicKeyArmored )) {
		logger (Colors.red(`postOpenpgpRoute localNodeCommand SICommandObj signatures key [${_clientKeyID}] different getPublicKeyArmoredKeyID ERROR!\n`), inspect(command, false, 3, true))
		return clientRes.status(400).end ()
	}

	if ( !command?.iv?.length || !command?.Securitykey?.length ) {
		logger (Colors.red(`postOpenpgpRoute localNodeCommand command format ERROR!\n`), inspect(command, false, 3, true ), '\n')
		return clientRes.status(400).end ()
	}

	logger (Colors.blue(`postOpenpgpRoute get request from customer [${ _clientKeyID }]`), inspect (command, false, 3, true))

	switch (command.command) {
		case 'getCoNETCashAccount': {
			const acc =  createIdentity ()
			const data: eth_crypto_key_obj = {
				privateKey: acc.privateKey,
				publicKey: acc.publicKey,
				address: acc.address,
				balance: 0,
				amount: 0
			}

			let historyData: SI_Client_CoNETCashData|null = await getCoNETCashData(_clientKeyID)

			if (! historyData) {
				logger (Colors.blue (`Client [${_clientKeyID}] is firest time user`))
				historyData =  {walletKeyArray: [data], publicKeyArmored: command.publicKeyArmored}
			} else {
				historyData.walletKeyArray.unshift (data)
			}

			logger (inspect(historyData, false, 3, true))

			command.responseError = null
			command.responseData = [data.address]
			let keyJSON
			try {
				keyJSON = JSON.parse(command.Securitykey)
			} catch (ex) {
				logger (Colors.red(`localNodeCommand getCoNETCashAccount JSON.parse Securitykey Error! [${inspect(command, false, 3, true)}]`))
				clientRes.status(400).end ()
				return clientRes.socket?.end().destroy()
			}

			command.responseError = null
			command.publicKeyArmored = ''
			command.responseData = [data.address]
			const response = await encryptWebCrypt (keyJSON, command.iv, command)

			logger (Colors.blue(`getCoNETCashAccount [${ _clientKeyID }] success!`), inspect(response, false, 3, true))

			clientRes.json({data: response}).end()
			clientRes.socket?.end().destroy()

			return await saveCoNETCashData (_clientKeyID, historyData)
		}

		case 'regiestRecipient': {
			const authorizeID = command.requestData[0]

			if (!authorizeID?.id) {
				logger (Colors.red(`localNodeCommand regiestRecipient have no authorizeID! [${inspect(command, false, 3, true)}]`))
				clientRes.status(400).end ()
				return clientRes.socket?.end().destroy()
			}

			
			const _balance = await getCoNETCashBalance( authorizeID.id )

			const balance = <CoNETCashBalanceResponse> _balance

			logger (Colors.blue (`getCoNETCashBalance result`), inspect(balance, false, 3, true))

			if (!balance.balance) {
				logger (Colors.red(`localNodeCommand regiestRecipient authorizeID ERROR! [${inspect(command, false, 3, true)}]`))
				clientRes.status(400).end ()
				return clientRes.socket?.end().destroy()
			}

			let historyData: SI_Client_CoNETCashData|null = await getCoNETCashData(_clientKeyID)

			if (! historyData) {
				logger (Colors.red(`localNodeCommand regiestRecipient have no historyData! [${inspect(command, false, 3, true)}]`))
				logger (Colors.red(`_clientKeyID = [${ _clientKeyID }]`))
				clientRes.status(400).end ()
				return clientRes.socket?.end().destroy()
			}

			const index = historyData.walletKeyArray.findIndex (n => n.address.toLowerCase() === balance.owner.toLowerCase())

			if (index < 0 || balance.balance < 1 ) {
				logger (Colors.red(`localNodeCommand regiestRecipient have no my wallet address! [${inspect(balance, false, 3, true)}] [${inspect(historyData.walletKeyArray, false, 3, true)}]`))
				clientRes.status(400).end ()
				return clientRes.socket?.end().destroy()
			}

			const {profile, profileHash, sign} = command.requestData[1]

			if ( !profile||!profileHash|| !sign) {
				logger (Colors.red(`localNodeCommand regiestRecipient profile||!profileHash|| !sign command.requestData = [${ inspect( command.requestData )}]`))
				clientRes.status(400).end ()
				return clientRes.socket?.end().destroy()
			}
			
			const _txObjHash = hash.keccak256(profile)

			if ( _txObjHash !== profileHash ) {
				logger (Colors.red(`localNodeCommand regiestRecipient profileObj Hash !== profileHash Error! [${inspect(balance, false, 3, true)}] [${inspect(historyData.walletKeyArray, false, 3, true)}]`))
				clientRes.status(400).end ()
				return clientRes.socket?.end().destroy()
			}

			let signAddr = ''

			try {
				signAddr = recover(sign, _txObjHash).toUpperCase()
			} catch (ex) {
				logger (Colors.red(`localNodeCommand regiestRecipient recover Error`), ex)
				clientRes.status(400).end ()
				return clientRes.socket?.end().destroy()
				
			}

			if (!command.publicKeyArmored) {
				logger (Colors.red(`localNodeCommand regiestRecipient have no publicKeyArmored Error`))
				clientRes.status(400).end ()
				return clientRes.socket?.end().destroy()
			}
			command.publicKeyArmored = ''
			command.responseError = null
			command.responseData = ['']
			let keyJSON
			try {
				keyJSON = JSON.parse(command.Securitykey)
			} catch (ex) {
				logger (Colors.red(`localNodeCommand getCoNETCashAccount JSON.parse Securitykey Error! [${inspect(command, false, 3, true)}]`))
				clientRes.status(400).end ()
				return clientRes.socket?.end().destroy()
			}
			
			const response = await encryptWebCrypt (keyJSON, command.iv, command)
			clientRes.json({data: response}).end ()
			clientRes.socket?.end().destroy()

			return regiestNewCustomer ( profile, signAddr, _clientKeyID, _clientKeyID )
		}

		default : {
			logger (Colors.red(`postOpenpgpRoute invalid command [${inspect(command, false, 3, true)}]`))
			return clientRes.status(400).end ()
		}
	}

}

export const postOpenpgpRoute = async (clientReq: Request, clientRes: Response, pgpData: string, privateKeyArmored: string, password: string, outbound_price: number, storage_price: number, selfIpv4: string,  onlineClientPool: IclientPool[], preDecryptedObj: IdecryptedObjText | null, encryptedByPublicKeyID: string = '' ) => {

	let messObj
	
	try {
		messObj = await readMessage ({armoredMessage: pgpData})
	} catch (ex) {

		//			pgpData looks laready decrypted to clear text
		if (preDecryptedObj) {
			return localNodeCommand (clientReq, clientRes, preDecryptedObj, encryptedByPublicKeyID, onlineClientPool, outbound_price, storage_price )
		}

		logger (Colors.red(`postOpenpgpRoute body has not PGP message Error !\n`), Colors.grey (pgpData), '\n')
		return clientRes.status(400).end ()
	}

	const encrypKeyID: typeOpenPGPKeyID[] = messObj.getEncryptionKeyIDs()

	if (!encrypKeyID?.length) {
		logger (Colors.red(`postOpenpgpRoute readMessage has no keys ERROR end connecting!\n`), Colors.grey (clientReq.body.data), '\n')
		return clientRes.status(400).end ()
	}

	const customerKeyID = encrypKeyID[0].toHex().toUpperCase()

	let decryptedObj

	try {
		decryptedObj = await decryptMessage ( messObj, privateKeyArmored, password )
	} catch (ex) {
		logger (Colors.blue(`customerKeyID [${customerKeyID}] decryptMessage ERROR, goto forwardEncryptedText!`), ex)
		return await forwardEncryptedText(clientReq, clientRes, pgpData, customerKeyID, onlineClientPool,outbound_price, storage_price, selfIpv4 )
	}

	if ( typeof decryptedObj.data !== 'string') {
		logger (Colors.red(`postOpenpgpRoute decryptMessage data has not string format ERROR\n`), inspect(decryptedObj, false, 3, true), '\n')
		return clientRes.status(400).end ()
	}

	//		already once russian doll
	if ( preDecryptedObj && encryptedByPublicKeyID) {
		logger (Colors.red(`postOpenpgpRoute had many russian doll ERROR\n`), inspect(decryptedObj, false, 3, true), '\n')
		return clientRes.status(400).end ()
	}


	const _preDecryptedObj = <IdecryptedObjText> decryptedObj
	
	if (!/^-----BEGIN PGP MESSAGE-----\n/.test (_preDecryptedObj.data)) {
		return localNodeCommand (clientReq, clientRes, _preDecryptedObj, encryptedByPublicKeyID, onlineClientPool, outbound_price, storage_price )
	}

	postOpenpgpRoute (clientReq, clientRes, decryptedObj.data,privateKeyArmored, password, outbound_price, storage_price, selfIpv4, onlineClientPool, _preDecryptedObj, customerKeyID )


}

export const checkSignMatchPublicKeyArmored = async (upperCaseSignGPGKeyID: string, publicKeyArmored: string) => {
	let clientKeyID11
	try {
		clientKeyID11 = await readKey ({armoredKey: publicKeyArmored})
	} catch (ex) {
		return false
	}
	const index = clientKeyID11.getKeyIDs().findIndex(n => n.toHex().toUpperCase() === upperCaseSignGPGKeyID)
	return (index >= 0)
	
}

export const decryptPgpMessage = async ( pgpMessage: string, pgpPrivateObj: PrivateKey ) => {

	let message
	let clearObj: DecryptMessageResult
	try {
		message = await readMessage ({armoredMessage: pgpMessage})
		clearObj = await decrypt ({ message, decryptionKeys: pgpPrivateObj })
	} catch (ex) {
		logger (Colors.red(`decryptPgpMessage Error!`), Colors.gray(pgpMessage))
		return null
	}
	
	if (typeof clearObj.data !== 'string' ) {
		logger (Colors.red(`decryptPgpMessage clearObj.data !== 'string' Error!`))
		return null
	}

	if (!clearObj.signatures.length ) {
		logger (Colors.red(`decryptPgpMessage have no signatures Error!`))
		return null
	}
	
	let obj: IPGP_DecryptedInfo
	try {
		obj = JSON.parse(Buffer.from(clearObj.data, 'base64').toString())
	} catch (ex) {
		logger (Colors.red(`decryptPgpMessage JSON.parse clearObj Error!`))
		return null
	}
	if (!obj.publicKeyArmored) {
		logger (Colors.red(`decryptPgpMessage decrypted OBJ have no publicKeyArmored Error!`))
		return null
	}

	const publickeyObj = await readKey ({armoredKey: obj.publicKeyArmored})
	const keyID = publickeyObj.getKeyIDs().map (n => n.toHex().toUpperCase())

	logger (keyID)
	
}
/**
 * 
												TEST 
 */


/**
 * 
 * 		TEST 
 * 
*/

/** */