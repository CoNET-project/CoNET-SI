import Colors from 'colors/safe'
import { series } from 'async'
import { stat, mkdir, writeFile } from 'node:fs'
import { homedir, networkInterfaces } from 'node:os'
import { join } from 'node:path'
import { Writable } from 'node:stream'
import { request } from 'node:http'
import { deflate, unzip } from 'node:zlib'
import { inspect } from 'node:util'
import Accounts from 'web3-eth-accounts'
import { createInterface } from 'readline'
import { publicKeyByPrivateKey, encryptWithPublicKey, cipher, sign, hash, hex, publicKey } from 'eth-crypto'
import { Buffer } from 'buffer'
import { ulid } from 'ulid'
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

export const getSetup = ( debug: boolean ) => {
	const homeDir = homedir ()
	const setupFileDir = join ( homeDir, '.CoNET-SI' )
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

export const GenerateWalletAddress = ( password: string ) => {
	// @ts-ignore: Unreachable code error
	const accountw: Accounts.Accounts = new Accounts()
	const acc = accountw.wallet.create(2)
	return acc.encrypt ( password )
}

export const loadWalletAddress = ( walletBase: any, password: string ) => {
	// @ts-ignore: Unreachable code error
	const account: Accounts.Accounts = new Accounts()

	const uu = account.wallet.decrypt ( walletBase, password )
	// @ts-ignore: Unreachable code error
	uu[0]['publickey'] = publicKeyByPrivateKey (uu[0].privateKey)
	// @ts-ignore: Unreachable code error
	uu[1]['publickey'] = publicKeyByPrivateKey (uu[1].privateKey)
	return uu
}

export const saveSetup = ( setup: ICoNET_NodeSetup, debug: boolean ) => {
	const homeDir = homedir ()
	const setupFileDir = join ( homeDir, '.CoNET-SI' )
	const setupFile = join ( setupFileDir, 'nodeSetup.json')
	
	return {
		then ( resolve: any, reject: any ) {
			return writeFile (setupFile, JSON.stringify (setup), 'utf-8', err => {
				if ( err ) {
					throw err
				}
				return resolve ()
			})
		}
	}
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


const requestUrl = (option: any, postData: string) => {
	return {
		then (resolve: any, inject: any ){
			const req = request (option, res => {
				let ret = ''
				res.setEncoding('utf8')

				res.on('data', chunk => {
					ret += chunk
				})

				res.once ('end', () => {
					resolve (ret)
				})
			})

			req.on ('error', err => {
				inject (err)
				return logger (`register_to_DL postToServer [${ option.uri }] error`, err )
			})
			req.write(postData)
			return req.end()
		}
	}
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

export const register_to_DL = ( nodeInit: ICoNET_NodeSetup ) => {

	const DLNode = nodeInit.DL_nodes[0]
	const data: ICoNET_DL_POST_register_SI = {
		publicKey: nodeInit.keychain[0].publickey,
		ipV4Port: nodeInit.ipV4Port,
		ipV4: nodeInit.ipV4,
		storage_price:  nodeInit.storage_price,
		outbound_price: nodeInit.outbound_price,
		wallet_CoNET: nodeInit.keychain[0].address,
		wallet_CNTCash: nodeInit.keychain[1].address
	}

	const dataMessage = JSON.stringify (data)

	const process_sync = async () => {
		const signature = sign( nodeInit.keyObj[0].privateKey, hash.keccak256 (dataMessage))
		const payload = {
			message:dataMessage,
			signature
		}
		const encrypted = await encryptWithPublicKey(DLNode.public, JSON.stringify (payload))

			const hexString = cipher.stringify(encrypted)
			// @ts-ignore: Unreachable code error
			const compress = await compressText (hexString)

			//logger (Colors.gray(hexdump(Buffer.from (decompress, 'ucs-2'))))

		const postData = JSON.stringify({
			payload: compress
		})

		const option = {
			host: DLNode.ipAddr,
			port: DLNode.PORT,
			path: '/conet-si-node-register',
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Content-Length': Buffer.byteLength( postData )
			}
		}

		// @ts-ignore: Unreachable code error
		const response = await requestUrl (option, postData)
		logger (response)
	}
	
	process_sync()
}



/**
 * 
 * 		TEST 
 * 
 */
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
const uu =  GenerateWalletAddress ('')
logger (inspect (uu, false, 3, true ))
const kk = loadWalletAddress ( uu,'' )

/** */
/*
const y = ulid()
const uu = Base32.decode (y, 'Crockford')
const ss = Buffer.from (uu)
logger (colors.grey( hexdump(ss)))
/** */