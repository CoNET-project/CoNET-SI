
import { stat, mkdir, writeFile, linkSync } from 'node:fs'
import { homedir, networkInterfaces, cpus } from 'node:os'
import { join } from 'node:path'
import { Writable } from 'node:stream'
import { get, request as requestHttps, RequestOptions } from 'node:https'
import { request as requestHttp} from 'node:http'
import { deflate, unzip } from 'node:zlib'
import { inspect } from 'node:util'
import { exec } from 'node:child_process'
import { createConnection } from 'node:net'
import type { NetConnectOpts } from 'node:net'
import { series } from 'async'
import { createHash, webcrypto } from 'node:crypto'
import {Wallet} from 'ethers'
import type {HDNodeWallet} from 'ethers'
import { createInterface } from 'readline'
import {Transform} from 'node:stream'

import { publicKeyByPrivateKey, encryptWithPublicKey, cipher, hash, hex, publicKey, createIdentity, recover, util, sign } from 'eth-crypto'

import { Buffer } from 'buffer'
import { generateKey, readKey, readPrivateKey, decryptKey, createCleartextMessage, sign as pgpSign, readMessage, decrypt, encrypt, createMessage, enums } from "openpgp"
import type { KeyID as typeOpenPGPKeyID } from 'openpgp'
import Colors from 'colors/safe'
import { getCoNETCashBalance, regiestNewCustomer } from './dl'
import type { GenerateKeyOptions, Key, PrivateKey, Message, MaybeStream, Data, DecryptMessageResult, WebStream, NodeStream } from 'openpgp'
import type {IncomingMessage} from 'node:http'

import type { Response, Request } from 'express'
const KB = 1000
const MB = 1000 * KB

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
		const _nets = nets[ name ]
		if (!_nets?.length) {
			continue
		}
		for (const net of _nets) {
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

export const generateWalletAddress = async ( password: string ) => {
	const accountw = Wallet.createRandom()
	const acc = await accountw.encrypt (password)
	return (acc)
}

export const generatePgpKey = async (walletAddr: string, passwd: string ) => {
	const option: GenerateKeyOptions = {
        type: 'ecc',
		passphrase: passwd,
		userIDs: [{
			name: walletAddr
		}],
		curve: 'curve25519',
        format: "armored"
		
	}


	const { privateKey, publicKey } = await generateKey  (
		//@ts-ignore
		option)

	const keyObj = await readKey ({armoredKey: publicKey})
	const keyID = keyObj.getKeyIDs()[1].toHex().toUpperCase ()
	return ({privateKey, publicKey, keyID})
}

export const loadWalletAddress = async ( walletBase: string, password: string ) => {
	logger (inspect(walletBase, false, 3, true))
	if (typeof walletBase === 'object') {
		walletBase = JSON.stringify(walletBase)
	}
	const account = await Wallet.fromEncryptedJson (walletBase, password)
	logger (inspect(account, false, 3, true))
	return account
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

export const waitKeyInput: (query: string, password: boolean ) => Promise<string> = 
	( query: string, password = false ) => {

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


export const requestHttpsUrl = (option: RequestOptions, postData: string) => {

	return new Promise((resolve) => {
		const req = requestHttps (option, res => {
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

		req.on ('error', (err: Error) => {
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
		if ( res.statusCode != 200 ) {
			switch (res.statusCode) {
				case 301: {
					if (res.headers['location']?.length) {
						const newUrl = res.headers['location']
						logger (Colors.blue(`proxyRequest target server [${webUrl}] response a 301 Moved, resirect to [${newUrl}]`))
						
						proxyRequest (clientReq, clientRes, newUrl)
						return
					}
				}
				default: {
				}
			}
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
	const response: any = await requestHttpsUrl (option, '')
	if (!response?.publishGPGKey) {
		return null
	}

	return response.publishGPGKey
}

export const register_to_DL = async ( nodeInit: ICoNET_NodeSetup ) => {
	if (!nodeInit) {
		return false
	}

	const wallet = nodeInit.keyObj
	// logger ('********************************************************************************************************************************************')
	// logger (inspect(wallet, false, 3, true))
	// logger ('********************************************************************************************************************************************')
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

	const response: any = await requestHttpsUrl (option, postJSON)

	logger (`register_to_DL response is\n`, response)

	return response
}

const healthTimeout = 1000 * 60 * 5

export const si_healthLoop = async ( nodeInit: ICoNET_NodeSetup ) => {
	const wallet = nodeInit.keyObj

	const _payload: ICoNET_DL_POST_health_SI = {
		nft_tokenid: createHash('sha256').update(nodeInit.ipV4).digest('hex'),
		armoredPublicKey: nodeInit.pgpKey.publicKey,
		platform_verison: nodeInit.platform_verison,
		walletAddr: wallet.address,
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
		const response: any = await requestHttpsUrl (option, postJSON)
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
					if(err) {
						logger (Colors.red(`initCoNetCashDataPath Error`), err)
					}
					return resolve(true)
				})
			}
			return resolve(true)
		})
	})
}

const saveCoNETCashData = async (publicGPGKeyID: string, linkid: string, jsonData: SI_Client_CoNETCashData) => {
	const setupFile = join ( CoNetCashDataPath, `${publicGPGKeyID}.json` )
	const linkPath = join(CoNetCashDataPath, `${linkid}.json`)
	await initCoNetCashDataPath ()
	return new Promise ( resolve => {
		logger (`saveCoNETCashData ${setupFile}`)
		return writeFile (setupFile, JSON.stringify (jsonData), 'utf-8', err => {
			
			if (err) {
				logger (Colors.red(`saveCoNETCashData Error`), err)
				return resolve (false)
			}

			if (linkid) {
                try {
                    linkSync(setupFile, linkPath)
                }
                catch (ex) {
                    return resolve(true);
                }
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


const forwardCache: Map<string, ICoNET_Router> = new Map()

const getRouterFromKeyID : (keyid: string) => Promise<ICoNET_Router|false>= (keyID: string) => {
	return new Promise (resolve => {
		const node = forwardCache.get(keyID)
		if (node) {
			return resolve (node)
		}

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
					forwardCache.set (keyID, retJson)
					return resolve (retJson)
				}
			})

		}).once ('error', error => {
			logger (Colors.red (`getRouterFromKeyID connest to [${ url }] Error`), error )
			return resolve (false)
		})
	})
}

// const routerPost = ( url: string, clientReq: Request, clientRes: Response, data: string) => {
// 	const option: RequestOptions = {
// 		hostname: url,
// 		path: '/post',
// 		port: 443,
// 		method: 'POST'
// 	}
// 	logger (Colors.blue(`routerPost connect to [https://${ url }/post]`))
// 	const req = request (option)

// 		// if ( res.statusCode === undefined ) {
// 		// 	logger (`routerPost to host [${ url }] res.statusCode === undefined Error! STOP client connection!`)
// 		// 	return clientRes.sendStatus(503).end()
// 		// }

// 		// clientRes.sendStatus (res.statusCode)
// 		// for (let i = 0; i < res.rawHeaders.length; i += 2) {
// 		// 	clientRes.setHeader(`"${res.rawHeaders[i]}"`, `"${res.rawHeaders[i+1]}"`)
// 		// }
// 		// res.pipe (clientRes)
		
// 	.once ('error', err => {
// 		logger (`routerPost req once ('error')`, err )
// 	})
// 	req.socket?.pipe (clientRes).once('close', () => {
// 		logger (Colors.blue (`routerPost [${ url }] once end, close clientRes`))
// 		clientRes.end()
// 	})

// 	req.write (data+'\r\n\r\n')
// }

const socketPost = (ipAddr: string, port: number, clientRes: Response, data: string) => {

	const postData = JSON.stringify({data})
	const disConnect = () => {
		logger (Colors.blue(`socketPost doing disConnect`))
		clientRes.status(400).json().end()
		if (clientRes.socket && typeof clientRes.socket.destroy === 'function') {
			logger (Colors.red(`socketPost doing clientRes.socket.destroy()`))
			clientRes.socket.destroy()
		}
        
	}	
	const rawHttpRequest = `POST /post HTTP/1.1\r\nHost: ${ipAddr}\r\nAccept: */*\r\nConnection: keep-alive\r\ncontent-type: application/json\r\nContent-Length: ${ postData.length }\r\n\r\n${ postData }\r\n\r\n`

	const url = `[${ipAddr}:${port}]`
	let u = ''
	const conn = createConnection ( port, ipAddr, () => {

		logger (Colors.blue (`Connecting to Router ${ url } success !`))
		conn.once ('end', () => {
			logger(Colors.red(`socketPost conn.once ('end')`))
			if (clientRes.socket && typeof clientRes.socket.destroy === 'function') {
				logger (Colors.red(`socketPost doing clientRes.socket.destroy()`))
				clientRes.end()
				//clientRes.socket.destroy()
			}
		})
		conn.setNoDelay(true)
		conn.pipe (clientRes)
		conn.write (rawHttpRequest)

	}).once ('error', err => {
		logger (Colors.red(`socketPost router node ${ url } on error STOP connect \n`), err )
		disConnect()
	})
	
	
}

const forwardConnectTimeOut = 30*1000


const forwardEncryptedText = async (clientReq: Request, clientRes: Response, encryptedText: string, gpgPublicKeyID: string, onlineClientPool: IclientPool[], outbound_price: number, storage_price: number, selfIpv4: string ) => {
	


	//			forward encrypted text
	const _route = await getRouterFromKeyID (gpgPublicKeyID)
	if ( !_route ) {
		const client = await getCoNETCashData (gpgPublicKeyID)

		//			is the keyID client in node
		if ( client ) {
			return customerData (clientReq, clientRes, encryptedText, gpgPublicKeyID, client, onlineClientPool, outbound_price,storage_price)
		}
		
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
	forwardNumber: string
	locked: boolean
	command: SICommandObj
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
		return await saveCoNETCashData (customerKeyID, '', client)
	}

	const connect = onlineClientPool[clientConnectingIndex]
	//		Forward data to a online client
	const use_history: use_history = {
		type: 'outbound',
		data_length: length,
		price: outbound_price,
		fee: outbound_price * length * parseInt(connect.forwardNumber),
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

const encryptWebCrypt = async (keyJSON: webcrypto.JsonWebKey, _iv: string, command: string ) => {

	const key = await webcrypto.subtle.importKey('jwk', keyJSON, {name: 'AES-CBC', length: 256, hash: 'SHA-512'}, true, ['encrypt', 'decrypt'])
	const iv = Buffer.from (_iv,'base64')
	const dec = new TextEncoder()
	const data = dec.encode(command)
	const encryptText = await crypto.subtle.encrypt({
		name: 'AES-CBC',
		iv,
	  	}, key, data)
	return (Buffer.from(encryptText).toString('base64'))
}

const encryptWebCryptCommand = async (keyJSON:  webcrypto.JsonWebKey, _iv: string, command: SICommandObj) => {
    return encryptWebCrypt(keyJSON, _iv, JSON.stringify(command))
}

const writeServerSendEvent = (res: Response, sseId: string, data: string) => {
    const data1 = data ? `data: ${data}` : `date: ${new Date().toISOString()}`
    logger (`writeServerSendEvent ${data1}`)
    res.write(`id: ${sseId}\r\n`)
    res.write(data1)
}

const localNodeCommand = async (clientReq: Request, clientRes: Response, decryptedObj: IdecryptedObjText, command: SICommandObj,onlineClientPool:IclientPool[], outbound_price: number, storage_price: number ) => {
	const disConnect = () => {
		clientRes.status(400).json().end()
		if (typeof clientRes.socket?.destroy === 'function') {
			clientRes.socket.destroy()
		}
        
	}

	//				have no publicKeyArmored included
	if ( typeof command?.publicKeyArmored !== 'string' || !command.publicKeyArmored.length || !decryptedObj.signatures.length ) {
		logger (Colors.red(`postOpenpgpRoute localNodeCommand decrypted Obj SICommandObj have no signatures key information ERROR!\n`), inspect(command, false, 3, true))
		return disConnect()
	}
	//			Check signatures, publicGpgKey match
	const _clientKeyID = decryptedObj.signatures[0].keyID.toHex().toUpperCase ()
	
	if ( ! checkSignMatchPublicKeyArmored ( _clientKeyID, command.publicKeyArmored )) {
		logger (Colors.red(`postOpenpgpRoute localNodeCommand SICommandObj signatures key [${_clientKeyID}] different getPublicKeyArmoredKeyID ERROR!\n`), inspect(command, false, 3, true))
		return disConnect()
	}

	if ( !command?.Securitykey?.length ) {
		logger (Colors.red(`postOpenpgpRoute localNodeCommand command format ERROR!\n`), inspect(command, false, 3, true ), '\n')
		return disConnect()
	}

	logger (Colors.blue(`postOpenpgpRoute get request from customer [${ _clientKeyID }]`), inspect (command, false, 3, true))
	const _clientKeyID_linked = await getPublicKeyArmoredKeyID(command.publicKeyArmored)

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
				return disConnect()
			}

			command.responseError = null
			command.publicKeyArmored = ''
			command.responseData = [data.address]
			const response = await encryptWebCryptCommand (keyJSON, command.iv, command)

			logger (Colors.blue(`getCoNETCashAccount [${ _clientKeyID }] success!`), inspect(response, false, 3, true))

			clientRes.json({data: response}).end()
			clientRes.socket?.end().destroy()

			return await saveCoNETCashData (_clientKeyID, _clientKeyID_linked, historyData)
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
			
			const response = await encryptWebCryptCommand (keyJSON, command.iv, command)
			clientRes.json({data: response}).end ()
			clientRes.socket?.end().destroy()

			return regiestNewCustomer ( profile, signAddr, _clientKeyID, _clientKeyID )
		}


        case 'connecting': {
            const linked = onlineClientPool.findIndex(n => n.gpgPublicKeyID === _clientKeyID_linked);
            if (linked > -1) {
                logger(Colors.red(`localNodeCommand connecting from [${_clientKeyID_linked}] already has connecting Error! [${inspect(command, false, 3, true)}]`))
                return disConnect()
            }

            const { profile, profileHash, sign } = command.requestData[0]
            if (!profile || !profileHash || !sign) {
                logger(Colors.red(`localNodeCommand regiestRecipient profile||!profileHash|| !sign command.requestData = [${inspect(command.requestData, false, 3, true)}]`))
                return disConnect()
            }

            const _txObjHash = hash.keccak256(profile)
            if (_txObjHash !== profileHash) {
                logger(Colors.red(`localNodeCommand regiestRecipient profileObj Hash !== profileHash Error! ${inspect(command, false, 3, true)}`))
                return disConnect()
            }

            let signAddr = ''
            try {
                signAddr = recover(sign, _txObjHash).toUpperCase()
            }
            catch (ex) {
                logger(Colors.red(`localNodeCommand regiestRecipient recover Error`), ex)
                return disConnect()
            }

            if (!command.publicKeyArmored) {
                logger(Colors.red(`localNodeCommand regiestRecipient have no publicKeyArmored Error`))
                return disConnect()
            }

            command.publicKeyArmored = ''
            command.responseError = null
            command.responseData = ['']
            let keyJSON

            try {
                keyJSON = JSON.parse(command.Securitykey)
            }
            catch (ex) {
                logger(Colors.red(`localNodeCommand getCoNETCashAccount JSON.parse Securitykey Error! [${inspect(command, false, 3, true)}]`))
                return disConnect()
            }

            const response = await encryptWebCryptCommand(keyJSON, command.iv, command)
            const sseId = (new Date()).getTime().toString()
            //		When Client Close

            clientReq.socket.once ('end', () => {
                logger(Colors.green(`${sseId} Clisnt on End`))
                const inedx1 = onlineClientPool.findIndex(n => n.forwardNumber === sseId)
                if (inedx1 < 0) {
                    return logger(Colors.red(`${sseId} clientReq.socket.once ('end') but have not list in onlineClientPool`))
                }
                return onlineClientPool.splice(inedx1, 1)
            })

            clientRes.writeHead(200, {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive'
            })

            writeServerSendEvent(clientRes, sseId, response)

            return onlineClientPool.push({
                gpgPublicKeyID: _clientKeyID_linked,
                forwardNumber: sseId,
                clientReq: clientReq,
                clientRes: clientRes,
                locked: false,
                command: command
            })
        }

        case 'SaaS_Proxy': {
            const requestHeaders = command.requestData[1]
            const requestOrgnal = command.requestData[0]

            logger (Colors.blue(`SaaS_Proxy get Request\n`), inspect(requestOrgnal, false, 3, true))
            logger (Colors.blue(`SaaS_Proxy requestHeaders\n`), inspect(requestHeaders, false, 3, true))
            logger (`SaaS_Proxy clientReq headers\n`, clientReq.rawHeaders)

            const password = command.Securitykey
            // const _encrypt = new encrypteStream (keyJSON, command.iv, MB)
            //#endregion 
            if (!password) {
                logger (Colors.red(`SaaS_Proxy have no password error! [${inspect(command, false, 3, true)}]`))
                return disConnect()
            }
            return connectWithHttp(requestOrgnal, clientRes, password, requestHeaders)
        }

		default : {
			logger (Colors.red(`postOpenpgpRoute invalid command [${inspect(command, false, 3, true)}]`))
			return disConnect()
		}
	}

}

type RequestOrgnal = {
	href: string
	method: string
	port: number
	json: string
}

/**
 * Encrypts plaintext using AES-GCM with supplied password, for decryption with aesGcmDecrypt().
 *                                                                      (c) Chris Veness MIT Licence
 *
 * @param   {String} plaintext - Plaintext to be encrypted.
 * @param   {String} password - Password to use to encrypt plaintext.
 * @returns {String} Encrypted ciphertext.
 *
 * @example
 *   const ciphertext = await aesGcmEncrypt('my secret text', 'pw');
 *   aesGcmEncrypt('my secret text', 'pw').then(function(ciphertext) { console.log(ciphertext); });
 */
const aesGcmEncrypt = async (plaintext: string, password: string) => {
    const pwUtf8 = new TextEncoder().encode(password) // encode password as UTF-8
    const pwHash = await crypto.subtle.digest('SHA-256', pwUtf8) // hash the password
    const iv = crypto.getRandomValues(new Uint8Array(12)) // get 96-bit random iv
    const ivStr = Array.from(iv).map(b => String.fromCharCode(b)).join('') // iv as utf-8 string
    const alg = { name: 'AES-GCM', iv: iv } // specify algorithm to use
    const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['encrypt']) // generate key from pw
    const ptUint8 = new TextEncoder().encode(plaintext) // encode plaintext as UTF-8
    const ctBuffer = await crypto.subtle.encrypt(alg, key, ptUint8) // encrypt plaintext using key
    const ctArray = Array.from(new Uint8Array(ctBuffer)) // ciphertext as byte array
    const ctStr = ctArray.map(byte => String.fromCharCode(byte)).join('') // ciphertext as string
    const str = btoa(ivStr + ctStr)
    return str
}

class encrypteStreamGCM extends Transform {
    password
    length
    text = ''
    constructor(password: string, length: number, private clientRes: Response) {
        super()
        this.password = password
        this.length = length
    }

    async _transform(chunk: Buffer, encoding: string, callback: (err?: Error|null, chunk?: string) => void) {
        this.text += chunk.toString('binary')
        if (this.text.length < this.length) {
            // console.log(`this.text.length [${this.text.length}] < this.length [${this.length}], continue waiting`)
            return callback()
        }
        
        const req = await aesGcmEncrypt(this.text, this.password)
        this.text = ''
        const blockLength = req.length.toString(16)
		console.log(`_transform start encrypte block length =[${blockLength}]\n`)
        return callback(null,req + '\r\n\r\n')
		//return callback(null, blockLength + '\r\n' + req + '\r\n\r\n')
    }

    async _flush(callback: (err?: Error|null, chunk?: string) => void) {
        if (this.text.length) {
            
            const req = await aesGcmEncrypt(this.text, this.password)
            const blockLength = req.length.toString(16)
			console.log(`_transform _flush encrypte block length =[${blockLength}]\n`)
			callback(null, req + '\r\n\r\n')
			this.once ('finish', () => {
				logger (Colors.red(`encrypteStreamGCM on finish`))
				if (this.clientRes.socket) {
					logger (Colors.red(`encrypteStreamGCM listening clientRes.socket end`))
					this.clientRes.socket.end()
				}
				
			})
        }
    }
}

const connectWithHttp = (requestOrgnal1: RequestOrgnal, clientRes: Response, password: string, requestHeaders:  { [key: string]: string }, reDirectCount = 0) => {
    let requestOrgnalUrl: URL
	const disConnect = () => {
		clientRes.status(400).json().end()
        if (typeof clientRes.socket?.destroy === 'function') {
			clientRes.socket.destroy()
		}
	}
    try {
        requestOrgnalUrl = new URL(requestOrgnal1.href)
    }
    catch (ex) {
        logger (Colors.red(`connectWithHttp invalid requestOrgnal.href [${inspect(requestOrgnal1.href, false, 3, true)}] STOP Connecting!`))
        return clientRes.status(404).end()
    }
    const listenHttp = (_res: IncomingMessage) => {
		logger (Colors.blue(`listen1 start! for [${requestOrgnalUrl.href}]`))

        const processStream = async () => {
            const headerLine = []
            for (let i = 0; i < _res.rawHeaders.length; i += 2) {
                const kkk = _res.rawHeaders[i] + ': ' + _res.rawHeaders[i + 1]
                headerLine.push(kkk)
				
            }
			
			if (reDirectCount>0) {
				headerLine.push(`location: ${requestOrgnalUrl.origin}`)
			}
            /**
             * header("Access-Control-Allow-Origin: http://localhost:4200");
                header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
                header("Access-Control-Allow-Headers: Content-Type, Authorization");
             */
            clientRes.status(200)
			
            clientRes.setHeader('Access-Control-Allow-Origin', '*')
            // clientRes.setHeader('Access-Control-Allow-Origin','GET, POST, OPTIONS')
            // clientRes.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization')
            clientRes.setHeader('Content-Type', 'text/plain')
            const rawHeaders = headerLine.join('\r\n')

            logger (`connectWithHttp target Status code [${_res.statusCode}] message [${_res.statusMessage}]`)
            logger (`connectWithHttp target response header raw data = \n`, Colors.yellow(rawHeaders))
            const str = `HTTP/1.1 ${_res.statusCode} ${_res.statusMessage}\n` + rawHeaders + '\r\n\r\n' //		use \r\n\r\n different body
            logger (`encrypt header`)
			logger (Colors.gray(str))

            const utr = await aesGcmEncrypt(str, password)
            const blockStream = new encrypteStreamGCM(password, MB / 4, clientRes)
            const blockLength = utr.length.toString(16)
            //clientRes.write(blockLength + '\r\n' + utr + '\r\n\r\n')
			clientRes.write(utr + '\r\n')


            _res.pipe(blockStream).pipe(clientRes)
        }

        _res.on('error', err => {
            logger (Colors.red(`listenHttp url${requestOrgnalUrl.href} ERROR!`))
            logger (Colors.red(err.message))
            return disConnect ()
        })

        switch (_res.statusCode) {
            case 200: {
				
                logger (`connectWithHttp target server response 200 OK`)
                return processStream()
            }
            //		location
            case 307:
            case 302:
            case 301: {
				logger(Colors.red(`connectWithHttp get statusCode [${_res.statusCode}]!`))
                if (++reDirectCount > 5) {
                    logger (Colors.red(`connectWithHttp reDirect over [${reDirectCount}] time STOP reDirect`))
                    return processStream()
                }
                const reDirect = _res.headers.location
                if (!reDirect) {
                    return processStream()
                }
				_res.destroy()
                let reUrl
				
                try {
					reUrl = new URL(/http/i.test(reDirect) ? reDirect : requestOrgnalUrl.origin + reDirect)
                }
                catch (ex) {
                    return processStream()
                }
                const orgnalDomainRex = new RegExp(requestOrgnalUrl.origin, 'g')
                const uu = _res.headers['set-cookie']
                if (uu?.length) {
                    let cookieNew = []
                    for (let i of uu) {
                        const hh = i.split(';')
                        if (hh.length) {
                            logger (Colors.blue(`connectWithHttp set-cookie has DATA [${hh}]`))
                            for (let l of hh) {
                                const uu = l.split(/;|,/)[0]
                                if (uu) {
                                    cookieNew.push(uu);
                                    logger (Colors.blue(`connectWithHttp set-cookie requestHeaders['Cookie'] [${l}]`))
                                    logger (inspect(requestHeaders, false, 3, true))
                                }
                            }
                        }
                    }
                    requestHeaders['Cookie'] = cookieNew.join(';')
                }

                logger (Colors.blue(`connectWithHttp got redirection [${_res.statusCode}] response from [${requestOrgnalUrl.origin}] to new Location [${reUrl}] with cookies! reDirect[${reDirect}] `), inspect(requestHeaders, false, 3, true))
                requestOrgnal1.href = reUrl.href

                return connectWithHttp(requestOrgnal1, clientRes, password, requestHeaders, reDirectCount)
            }
            default: {
                return processStream()
            }
        }
    }


    const httpConnecting = () => {
        logger (Colors.blue(`connectWithHttp connecting reDirectCount = [${reDirectCount}]`), inspect(requestOrgnalUrl, false, 3, true))
        delete requestHeaders['referer']
        delete requestHeaders['host']
        const option = {
            host: requestOrgnalUrl.host,
            servername: requestOrgnalUrl.host,
            method: requestOrgnal1.method,
            port: requestOrgnalUrl.port,
            path: requestOrgnalUrl.pathname + requestOrgnalUrl.search,
            headers: {
                ...requestHeaders
            }
        }

        return /^http\:$/i.test(requestOrgnalUrl.protocol) ? requestHttp (option, listenHttp) : requestHttps(option, listenHttp)
    }
    const serverReq = httpConnecting()

    serverReq.on('error', (err: Error ) => {
        logger (Colors.red(`serverReq on Error url[${requestOrgnalUrl.href}]`), err)
        return disConnect ()
    })

    if (requestOrgnal1.json) {
        return serverReq.end(requestOrgnal1.json)
    }

    serverReq.end()
}

export const postOpenpgpRoute = async (clientReq: Request, clientRes: Response, pgpData: string, privateKeyArmored: string, password: string, outbound_price: number, storage_price: number, selfIpv4: string,  onlineClientPool: IclientPool[], preDecryptedObj: IdecryptedObjText | null, encryptedByPublicKeyID: string = '' ) => {

	const disConnect = () => {
		clientRes.status(400).json().end()
        clientRes.socket?.end().destroy()
	}

	let messObj
	
	try {
		messObj = await readMessage ({armoredMessage: pgpData})
	} catch (ex) {
		logger (Colors.red(`postOpenpgpRoute body has not PGP message Error !\n`), Colors.grey (pgpData), '\n')
		return disConnect()
	}

	const encrypKeyID: typeOpenPGPKeyID[] = messObj.getEncryptionKeyIDs()

	if (!encrypKeyID?.length) {
		logger (Colors.red(`postOpenpgpRoute readMessage has no keys ERROR end connecting!\n`), Colors.grey (clientReq.body.data), '\n')
		return disConnect()
	}

	const customerKeyID = encrypKeyID[0].toHex().toUpperCase()

	let decryptedObj

	try {
		decryptedObj = await decryptMessage ( messObj, privateKeyArmored, password )
	} catch (ex) {
		//logger (Colors.blue(`customerKeyID [${customerKeyID}] decryptMessage ERROR, goto forwardEncryptedText!`), ex)
		forwardEncryptedText(clientReq, clientRes, pgpData, customerKeyID, onlineClientPool,outbound_price, storage_price, selfIpv4 )
		return
	}

	if ( typeof decryptedObj.data !== 'string') {
		logger (Colors.red(`postOpenpgpRoute decryptMessage data has not string format ERROR\n`), inspect(decryptedObj, false, 3, true), '\n')
		return disConnect()
	}

	//		already once russian doll
	if ( preDecryptedObj && encryptedByPublicKeyID) {
		logger (Colors.red(`postOpenpgpRoute had many russian doll ERROR\n`), inspect(decryptedObj, false, 3, true), '\n')
		return disConnect()
	}


	const _preDecryptedObj = <IdecryptedObjText> decryptedObj
	let command;
    try {
        command = JSON.parse(Buffer.from(decryptedObj.data, 'base64').toString());
    }
    catch (ex) {
		logger (Colors.red(`postOpenpgpRoute localNodeCommand decrypted Obj JSON ERROR!\n`), Colors.grey(clientReq.body.data), '\n')
        return disConnect()
    }

	//				have no publicKeyArmored included
	const cmdStr = command
	command.algorithm = 'aes-256-cbc'

	if (/^-----BEGIN PGP MESSAGE-----\n/.test (cmdStr)) {
		postOpenpgpRoute (clientReq, clientRes, cmdStr, privateKeyArmored, password, outbound_price, storage_price, selfIpv4, onlineClientPool, _preDecryptedObj, customerKeyID )
		return
	}
	//			Forward encrypted text have not STOP in ths node so it allow have no signature
	if (!decryptedObj.signatures?.length) {
		logger (Colors.red(`localNodeCommand Have no signatures ERROR!\n`))
		return disConnect()
	}

	localNodeCommand(clientReq, clientRes, _preDecryptedObj, command, onlineClientPool, outbound_price, storage_price)

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
/**
 * 
												TEST 
 */
	// const oo = {
	// 	version: 3,
	// 	id: 'cb3a4d60-3796-4e17-98fc-4d2e15c148c1',
	// 	address: 'c489e1a86ccc14b3b0f6b31afc52521ea1ccad9c',
	// 	crypto: {
	// 	  ciphertext: '2be676dd9193bfc5d0e412bedd67bac42b3cccd75b093d8ab61a196f000ed642',
	// 	  cipherparams: [Object],
	// 	  cipher: 'aes-128-ctr',
	// 	  kdf: 'scrypt',
	// 	  kdfparams: [Object],
	// 	  mac: 'deaff79d3dddd6c5c591c4d9788ddad5f4677a3dbb6d21f11f7073748e482393'
	// 	}
	//   }
	// const start = async () => {
	// 	const passwd = 'erewfwref'
	// 	const kk = await generateWalletAddress(passwd)
	// 	const ss = await loadWalletAddress (kk, passwd)
	// 	logger (inspect(kk, false, 3, true))
	// 	logger (typeof ss)
	// 	logger (ss)
	// }
	// start()
	
/**
 * 
 * 		TEST 
 * 
*/

/** */