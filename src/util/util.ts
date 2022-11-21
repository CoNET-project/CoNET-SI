import Colors from 'colors/safe'
import { stat, mkdir, writeFile } from 'node:fs'
import { homedir, networkInterfaces } from 'node:os'
import { join } from 'node:path'
import { Writable } from 'node:stream'
import { request } from 'node:https'
import { deflate, unzip } from 'node:zlib'
import { inspect } from 'node:util'
import Accounts from 'web3-eth-accounts'
import { createInterface } from 'readline'
import type { RequestOptions } from 'https'
import { publicKeyByPrivateKey, encryptWithPublicKey, cipher, sign, hash, hex, publicKey } from 'eth-crypto'
import { Buffer } from 'buffer'
import { generateKey, readKey, readPrivateKey, decryptKey, createCleartextMessage, sign as pgpSign } from "openpgp"
import type { GenerateKeyOptions, Key, PrivateKey } from 'openpgp'

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
	return otherRespon ( kkk, 200 )
}

export const rfc1918 = /(^0\.)|(^10\.)|(^100\.6[4-9]\.)|(^100\.[7-9]\d\.)|(^100\.1[0-1]\d\.)|(^100\.12[0-7]\.)|(^127\.)|(^169\.254\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.0\.0\.)|(^192\.0\.2\.)|(^192\.88\.99\.)|(^192\.168\.)|(^198\.1[8-9]\.)|(^198\.51\.100\.)|(^203.0\.113\.)|(^22[4-9]\.)|(^23[0-9]\.)|(^24[0-9]\.)|(^25[0-5]\.)/

export const setupPath = '.CoNET-SI'

export const getSetup = ( debug: boolean ) => {
	const homeDir = homedir ()
	const setupFileDir = join ( homeDir, setupPath )
	const setupFile = join ( setupFileDir, 'nodeSetup.json')
	
	let nodeSetup: ICoNET_NodeSetup

	return {
		then( resolve:any ) {
			return stat( setupFileDir, err => {
				if ( err ) {
					logger (`checkSetupFile: have no .CoNET-SI directory`)
					return mkdir ( setupFileDir, err => {
						return resolve ()
					})
				}
				try {
					nodeSetup = require (setupFile)
				} catch (ex) {
					return resolve ()
				}
				return resolve ( nodeSetup )
			})
		}
	}
	
}

export const getServerIPV4Address = ( includeLocal: boolean ) => {
	const nets = networkInterfaces()
	const results = []
	for ( const name of Object.keys( nets )) {
		// @ts-ignore: Unreachable code error
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
	// @ts-ignore: Unreachable code error
	const accountw: Accounts.Accounts = new Accounts()
	const acc = accountw.wallet.create(1)
	return acc.encrypt ( password )
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
	// @ts-ignore: Unreachable code error
	const { privateKey, publicKey } = await generateKey (option)
	const keyObj = await readKey ({armoredKey: publicKey})
	const keyID = keyObj.getKeyID().toHex().toUpperCase ()
	return ({privateKey, publicKey, keyID})
}


export const loadWalletAddress = ( walletBase: any, password: string ) => {
	// @ts-ignore: Unreachable code error
	const account: Accounts.Accounts = new Accounts()

	const uu = account.wallet.decrypt ( walletBase, password )
	// @ts-ignore: Unreachable code error
	uu[0]['publickey'] = publicKeyByPrivateKey (uu[0].privateKey)
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
	const homeDir = homedir ()
	const setupFileDir = join ( homeDir, setupPath )
	const setupFile = join ( setupFileDir, 'nodeSetup.json')
	
	return new Promise(resolve => {
		logger (`saveSetup`, inspect(setup, false, 3, true))
		return writeFile (setupFile, JSON.stringify (setup), 'utf-8', err => {
			if ( err ) {
				logger (`saveSetup [${setupFile}] Error!`, err )
				resolve (false)
			}
			logger (`saveSetup [${setupFile}] Success!` )
			return resolve (true)
		})
	})

}

export const waitKeyInput = ( query: string, password = false ) => {

	const mutableStdout = new Writable({
		write: ( chunk, encoding, next ) => {
			// @ts-ignore: Unreachable code error
			if (!mutableStdout["muted"]) {
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

	return {
		then( resolve: any ) {
			rl.question ( Colors.green(query), ans => {
				rl.close()
				return resolve(ans)
			})
			// @ts-ignore: Unreachable code error
			return mutableStdout["muted"] = password
		}
	}
}

const conetDLServer = 'openpgp.online'
const conetDLServerPOST = 443
const conetDLServerTimeout = 1000 * 60


const requestUrl = (option: any, postData: string) => {

	return new Promise((resolve: any) => {
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
			logger (Colors.red(`requestUrl on TIMEOUT Error!`))
			return resolve (null)
		}, conetDLServerTimeout)
		
		return req.end()
	})
	
}

const compressText = ( input: string ) => {
	return {
		then ( resolve: any, inject: any ) {
			return deflate (input, (err, data ) => {
				if ( err ) {
					return inject (err)
				}
				return resolve(data.toString('base64'))
			})
		}
	}
}

const signCleartext = async ( signingKeys: PrivateKey, _message: string ) => {
	const message = await createCleartextMessage ({text: _message})
	return (await pgpSign ({ message, signingKeys }))
}



export const register_to_DL = async ( nodeInit: ICoNET_NodeSetup ) => {
	if (!nodeInit) {
		return false
	}
	const data: ICoNET_DL_POST_register_SI = {
		pgpPublicKey: await signCleartext (nodeInit.pgpKeyObj?.privateKeyObj, nodeInit.pgpKey.publicKey ),
		ipV4Port: nodeInit.ipV4Port,
		ipV4: nodeInit.ipV4,
		storage_price:  nodeInit.storage_price,
		outbound_price: nodeInit.outbound_price,
		wallet_CoNET: '0X' + nodeInit.keychain[0].address.toUpperCase()
	}

	const dataMessage = JSON.stringify (data)

	const signature = sign( nodeInit.keyObj[0].privateKey, hash.keccak256 (dataMessage))
	
	const payload = {
		message: dataMessage,
		signature
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

export const si_health = async ( nodeInit: ICoNET_NodeSetup ) => {
	const _payload = {
		nft_tokenid: nodeInit.DL_registeredData,
		publickey: nodeInit.pgpKey.keyID
	}

	const JSONString = JSON.stringify(_payload)

	const signature = sign( nodeInit.keyObj[0].privateKey, hash.keccak256 (JSONString))

	const payload = {
		message: JSONString,
		signature
	}

	logger (`si_health \n`, inspect(payload, false, 3, true ))

	const sendData = JSON.stringify (payload)

	const option: RequestOptions = {
		hostname: conetDLServer,
		port: conetDLServerPOST,
		path: '/api/si-health',
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Content-Length': Buffer.byteLength( sendData )
		},
		rejectUnauthorized: false
	}
	const response: any = await requestUrl (option, sendData)

	logger (`si_health response is\n`, response)

	setTimeout(() => {
		return si_health (nodeInit)
	},  healthTimeout)
}



/**
 * 
 * 		TEST 
 * 
*/

/*
const uuuu = async () => {
	const hhh = await generatePgpKey ('0X2DFEAED46E703F17FADF41C83207B772344F7719', '1')
	logger (`Success`, inspect (hhh, false, 3, true))
}
uuuu ()

/*
 getSetupFile (true, (err, data) => {
	if (err ) {
		return logger (err)
	}
	return logger ('success!')
 })

 /** */
/*
logger ( inspect(getServerIPV4Address (false), false, 3, true ))

 /** */

 /*
const kk =  generateWalletAddress ('11111')
const obj = loadWalletAddress (kk, '11111')
logger (inspect(obj, false, 3, true))
/*

const kk = loadWalletAddress ( uu,'' )

/** */
/*
const uu = async () => {
	const pass = await s3fsPasswd()
	if ( !pass) {
		return logger (Colors.red(`pass Error!`))
	}
	const kk = await saveRouter (pass, '0X2DFEAED46E703F17FADF41C83207B772344F7719', '74.208.24.74')
	logger (`success`, kk)
}

uu()
/*

const y = ulid()
const uu = Base32.decode (y, 'Crockford')
const ss = Buffer.from (uu)
logger (colors.grey( hexdump(ss)))
/** */