import type { Socket } from 'node:net'
import {createConnection} from 'node:net'
import {distorySocket, response200Html} from './htmlResponse'
import {logger} from './logger'
import Colors from 'colors/safe'
import {inspect} from 'node:util'
import { generateKey, readKey, readPrivateKey, decryptKey, createCleartextMessage, sign as pgpSign, readMessage, decrypt, encrypt, createMessage, enums } from "openpgp"
import { publicKeyByPrivateKey, encryptWithPublicKey, cipher, hash, hex, publicKey, createIdentity, recover, util, sign } from 'eth-crypto'
import {join} from 'node:path'
import { homedir, networkInterfaces, cpus } from 'node:os'
import { createHash, webcrypto } from 'node:crypto'
import { stat, mkdir, writeFile, linkSync } from 'node:fs'
import { get, request as requestHttps, RequestOptions } from 'node:https'
import { request as requestHttp} from 'node:http'
import type {IncomingMessage} from 'node:http'
import {Transform} from 'node:stream'
import type { KeyID as typeOpenPGPKeyID } from 'openpgp'
import type { GenerateKeyOptions, Key, PrivateKey, Message, MaybeStream, Data, DecryptMessageResult, WebStream, NodeStream } from 'openpgp'
import { Wallet } from 'ethers'
import { exec } from 'node:child_process'
import { Writable } from 'node:stream'
import { createInterface } from 'readline'
import { TransformCallback } from 'stream'
export const setupPath = '.CoNET-SI'
import {checkPayment, getRoute } from './util'
import { ethers } from 'ethers'
import IP from 'ip'
import {resolve4} from 'node:dns'

const KB = 1000
const MB = 1000 * KB

const homeDir = homedir ()
const setupFileDir = join ( homeDir, setupPath )
const CoNetCashDataPath = join (setupFileDir,'.CoNETCashData')
const forwardCache: Map<string, ICoNET_Router> = new Map()

const ByteToMByte = 0.000001
const CoNetCashClientCachePath = join (setupFileDir, '.Cache')
const setupFile = join ( setupFileDir, 'nodeSetup.json')
const conetDLServer = 'api.openpgp.online'
const conetDLServerPOST = 4001
const conetDLServerTimeout = 1000 * 60
const healthTimeout = 1000 * 60 * 5
export const rfc1918 = /(^0\.)|(^10\.)|(^100\.6[4-9]\.)|(^100\.[7-9]\d\.)|(^100\.1[0-1]\d\.)|(^100\.12[0-7]\.)|(^127\.)|(^169\.254\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.0\.0\.)|(^192\.0\.2\.)|(^192\.88\.99\.)|(^192\.168\.)|(^198\.1[8-9]\.)|(^198\.51\.100\.)|(^203.0\.113\.)|(^22[4-9]\.)|(^23[0-9]\.)|(^24[0-9]\.)|(^25[0-5]\.)/

export const generateWalletAddress = async ( password: string ) => {
	const accountw = Wallet.createRandom()
	const acc = await accountw.encrypt (password)
	return (acc)
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

const EncryptePGPMessage = async (message: string|any, publicKeyObj: any, PrivateKeyObj: any) => {
	return await encrypt ({
		message: typeof message === 'string' ? (await createMessage ({text: message})): (await createMessage ({text: Buffer.from(JSON.stringify(message)).toString('base64')})),
		encryptionKeys: typeof publicKeyObj === 'string' ? await readKey ({armoredKey: publicKeyObj}): publicKeyObj,
		signingKeys: PrivateKeyObj,
		config: { preferredCompressionAlgorithm: enums.compression.zlib }
	})
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
			setTimeout (() => {
				resolve (null)
			}, 30000)
			
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

export const register_to_DL = async ( nodeInit: ICoNET_NodeSetup|null ) => {
	if (!nodeInit) {
		return false
	}

	const wallet = nodeInit.keyObj
	// logger ('********************************************************************************************************************************************')
	// logger (inspect(wallet, false, 3, true))
	// logger ('********************************************************************************************************************************************')

	nodeInit.dl_publicKeyArmored = await getDLPublicKey()


	if (nodeInit.dl_publicKeyArmored === null) {
		
		return logger (Colors.red(`register_to_DL got null return try late again!`))
	}

	logger (`dl_publicKeyArmored = `, nodeInit.dl_publicKeyArmored)
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


export const saveSetup = ( setup: ICoNET_NodeSetup|null, debug: boolean ) => {
	
	const setupFile = join ( setupFileDir, 'nodeSetup.json')
	

	return new Promise(resolve => {
		if (!setup) {
			resolve(false)
			return logger (Colors.red(`saveSetup setup: ICoNET_NodeSetup|null === NULL Error`))
		}
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


export const makeOpenpgpObj = async ( privateKey: string, publicKey: string, passphrase: string ) => {
	const publicKeyObj = await readKey ({ armoredKey: publicKey })
    let privateKeyObj = await readPrivateKey ({armoredKey: privateKey})
    if (!privateKeyObj.isDecrypted()) {
        privateKeyObj = await decryptKey ({ privateKey: privateKeyObj, passphrase })
    }
	const ret: pgpObj = {
		publicKeyObj,
		privateKeyObj
	}
	return (ret)
}


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

export const getPublicKeyArmoredKeyID = async (publicKeyArmored: string) => {
	const keyObj = await readKey ({armoredKey: publicKeyArmored})
	return keyObj.getKeyIDs()[1].toHex().toUpperCase()
}

export type IdecryptedObjText = DecryptMessageResult & {
	data: string
}

export type IclientPool = {
	clientSocket: Socket
	gpgPublicKeyID: string
	forwardNumber: string
	locked: boolean
	command: SICommandObj
}

const otherRequestForNet = ( data: string, host: string, port: number ) => {

	return 	`POST /post HTTP/1.1\r\n` +
			`Host: ${ host }${ port !== 80 ? ':'+ port : '' }\r\n` +
			`User-Agent:'Mozilla/5.0' }\r\n` +
			`Content-Type: application/json;charset=UTF-8\r\n` +
			`Connection: keep-alive\r\n` +
			`Content-Length: ${ data.length }\r\n\r\n` +
			data + '\r\n\r\n'
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

const encryptWebCrypt = async (keyJSON: webcrypto.JsonWebKey, _iv: string, command: string ) => {

	const key = await webcrypto.subtle.importKey('jwk', keyJSON, {name: 'AES-CBC', length: 256, hash: 'SHA-512'}, true, ['encrypt', 'decrypt'])
	const iv = Buffer.from (_iv,'base64')
	const dec = new TextEncoder()
	const data = dec.encode(command)
	const encryptText = await crypto.subtle.encrypt({
		name: 'AES-CBC',
		iv}, key, data)
	return (Buffer.from(encryptText).toString('base64'))
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


const encryptWebCryptCommand = async (keyJSON:  webcrypto.JsonWebKey, _iv: string, command: SICommandObj) => {
    return encryptWebCrypt(keyJSON, _iv, JSON.stringify(command))
}

class encrypteStreamGCM extends Transform {
    password
    length
    text = ''
    constructor(password: string, length: number, private clientRes: Socket) {
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
				this.clientRes.end()
				
			})
        }
    }
}

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

const connectWithHttp = (requestOrgnal1: RequestOrgnal, clientRes: Socket, password: string, requestHeaders:  { [key: string]: string }, reDirectCount = 0) => {
    let requestOrgnalUrl: URL

    try {
        requestOrgnalUrl = new URL(requestOrgnal1.href)
    }
    catch (ex) {
        logger (Colors.red(`connectWithHttp invalid requestOrgnal.href [${inspect(requestOrgnal1.href, false, 3, true)}] STOP Connecting!`))
        return distorySocket(clientRes)
    }

    const listenHttp = (_res: IncomingMessage) => {
		logger (Colors.blue(`listen1 start! for [${requestOrgnalUrl.href}]`))

        const processStream = async () => {
            const headerLine = []
            for (let i = 0; i < _res.rawHeaders.length; i += 2) {
                const kkk = _res.rawHeaders[i] + ': ' + _res.rawHeaders[i + 1]
                headerLine.push(kkk)
            }
			
			if (reDirectCount > 0) {
				headerLine.push(`location: ${requestOrgnalUrl.origin}`)
			}
            /**
             * header("Access-Control-Allow-Origin: http://localhost:4200");
                header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
                header("Access-Control-Allow-Headers: Content-Type, Authorization");
             */
            // @ts-ignore
            const responseData = `HTTP/1.1 200 OK\r\nDate: ${ new Date ().toGMTString()}\r\nContent-Type: text/plain\r\nAccess-Control-Allow-Origin: *\r\nConnection: keep-alive\r\nVary: Accept-Encoding\r\n\r\n`

            // clientRes.setHeader('Access-Control-Allow-Origin','GET, POST, OPTIONS')
            // clientRes.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization')
            
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

        _res.once('error', err => {
            logger (Colors.red(`listenHttp url${requestOrgnalUrl.href} ERROR!`))
            logger (Colors.red(err.message))
            _res.destroy()
            return clientRes.end()
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

    serverReq.once('error', (err: Error ) => {
        logger (Colors.red(`serverReq on Error url[${requestOrgnalUrl.href}]`), err)
        return serverReq._destroy(null, () => {
            logger (Colors.magenta(`serverReq on Error url[${requestOrgnalUrl.href}] destroyed`), err)
        })
    })

    if (requestOrgnal1.json) {
        return serverReq.end(requestOrgnal1.json)
    }

    serverReq.end()
}


export const localNodeCommandSocket = async (socket: Socket, headers: string[], command: SICommandObj) => {



	switch (command.command) {

		case 'SaaS_Sock5': {
			
			const prosyData = command.requestData[0]
			return socks5Connect(prosyData, socket)
		}

        case 'SaaS_Proxy': {
            const requestHeaders = command.requestData[1]
            const requestOrgnal = command.requestData[0]

            logger (Colors.blue(`SaaS_Proxy get Request\n`), inspect(requestOrgnal, false, 3, true))
            logger (Colors.blue(`SaaS_Proxy requestHeaders\n`), inspect(requestHeaders, false, 3, true))
            logger (`SaaS_Proxy clientReq headers\n`, headers)

            const password = command.Securitykey
            // const _encrypt = new encrypteStream (keyJSON, command.iv, MB)
            //#endregion 
            if (!password) {
                logger (Colors.red(`SaaS_Proxy have no password error! [${inspect(command, false, 3, true)}]`))
                return distorySocket(socket)
            }

            return connectWithHttp(requestOrgnal, socket, password, requestHeaders)
        }

		default : {
			logger (Colors.red(`postOpenpgpRoute invalid command [${inspect(command, false, 3, true)}]`))
			return distorySocket(socket)
		}
	}

}

class BandwidthCount extends Transform {
	private count = 0
	constructor(){
		super()
	}
	public _transform(chunk: Buffer, encoding: BufferEncoding, callback: TransformCallback): void {
		this.count += chunk.length
		callback ()
	}
	public _final(callback: (error?: Error | null | undefined) => void): void {
		callback
	}
}

const getHostIpv4: (host: string) => Promise<string> = (host: string) => new Promise(resolve => {
	return resolve4(host, (err, ipv4s) => {
		if (err||!ipv4s?.length) {
			return resolve ('')
		}

		return resolve(ipv4s[0])
	})
})

const socks5Connect = async (prosyData: VE_IPptpStream, resoestSocket: Socket) => {

    logger (Colors.blue (`socks5Connect connect to [${prosyData.host}:${prosyData.port}]`))
	const port = prosyData.port
	let host = prosyData.host
	if (!host) {
		return distorySocket(resoestSocket)
	}

	try {
		const ipStyle = IP.isPublic(host)
		if (!ipStyle) {
			return distorySocket(resoestSocket)
		}
	} catch (ex){
		host = await getHostIpv4(host)
	}
	

	if ( port < 1 || port > 65535  || !prosyData.uuid || !host) {
		return distorySocket(resoestSocket)
	}

	try {
		const socket = createConnection ( port, host, () => {

			socket.pipe(resoestSocket).pipe(socket).on('error', err => {
				logger(Colors.red(`socks5Connect pipe on Error`), err)
			})
	
			const data = Buffer.from(prosyData.buffer, 'base64')
			socket.write (data)
			resoestSocket.resume()
		})
	
		socket.on ( 'end', () => {
			logger (Colors.red(`socks5Connect host [${host}:${port}] on END!`))
			resoestSocket.end().destroy()
		})
	
		socket.on ( 'error', err => {
			logger (Colors.red(`socks5Connect [${host}:${port}] on Error! [${err.message}]`))
	
		})
	
		resoestSocket.on('error', err => {
			logger (Colors.red(`socks5Connect host [${host}:${port}] resoestSocket ON Err [${err.message}]`))
		})
	} catch (ex) {
		logger(`createConnection On catch`, ex)
		resoestSocket.end().destroy()
	}

}

const decryptMessage = async (encryptedText: Message<string>, decryptionKeys: any ) => {
	
	const decrypted = await decrypt ({
		message: encryptedText,
		decryptionKeys
	})

	return decrypted
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



const customerDataSocket =  async (socket: Socket, encryptedText: string, customerKeyID: string, client: SI_Client_CoNETCashData, onlineClientPool: IclientPool[], outbound_price: number, storage_price: number ) => {
	
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

		response200Html(socket, JSON.stringify({}))
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

	
	return connect.clientSocket.write(`data: ${encryptedText}\n\n`)
}

export const postOpenpgpRouteSocket = async (socket: Socket, headers: string[],  pgpData: string, pgpPrivateObj: any, pgpPublicKeyID: string) => {

	logger (Colors.red(`postOpenpgpRoute clientReq headers = `), inspect(headers, false, 3, true ), Colors.grey (`Body length = [$${pgpData?.length}]`))

	let messObj
	
	try {
		messObj = await readMessage ({armoredMessage: pgpData})
	} catch (ex) {
		logger (Colors.red(`postOpenpgpRoute body has not PGP message Error !\n`))
		return distorySocket(socket)
	}

	const encrypKeyID: typeOpenPGPKeyID[] = messObj.getEncryptionKeyIDs()

	if (!encrypKeyID?.length) {
		logger (Colors.red(`postOpenpgpRoute readMessage has no keys ERROR end connecting!\n`))
		return distorySocket(socket)
	}

	const customerKeyID = encrypKeyID[0].toHex().toUpperCase()

	
	if (customerKeyID !== pgpPublicKeyID) {
		logger(Colors.blue(`postOpenpgpRouteSocket encrypKeyID  [${customerKeyID}] is not this node's key forward to destination node!`))
		return forwardEncryptedSocket(socket, pgpData, customerKeyID)
	}

	let content

	try {
		const decryptedObj = await decryptMessage ( messObj, pgpPrivateObj)
		content = JSON.parse(Buffer.from(decryptedObj.data.toString(),'base64').toString())
	} catch (ex) {
		logger (Colors.red(` decryptMessage EX ERROR, distorySocket!`))
		return distorySocket(socket)
	}

	if (!content.message ||!content.signMessage) {
		logger (Colors.red(`Command format Error`))
		logger(inspect(content, false,3, true))
		return distorySocket(socket)
	}
	const command = checkSignObj (content.message, content.signMessage)

	if (!command) {
		logger(Colors.red(`checkSignObj Error!`))
		return distorySocket(socket)
	}

	const payment = checkPayment(command.walletAddress)

	if (!payment) {
		logger(Colors.red(`[${command.walletAddress}] Payment Error!`))
		return distorySocket(socket, '402 Payment Required')
	}
	
	logger(Colors.magenta(`${command.walletAddress} passed payment [${payment}] process SaaS!`))
	return localNodeCommandSocket(socket, headers, command )
	
}


const socketForward = (ipAddr: string, port: number, sourceSocket: Socket, data: string) => {

	const rawHttpRequest = otherRequestForNet(JSON.stringify({data}), ipAddr, port)



	const conn = createConnection ( port, ipAddr, () => {

		logger (Colors.blue (`Fardward packet to node ${ ipAddr }:${port} success !`))
		
		//	conn.setNoDelay(true)

		sourceSocket.once ('end', () => {
			logger(Colors.magenta(`socketForward sourceSocket on Close, STOP connecting`))
			conn.end().destroy()
		})

		conn.pipe (sourceSocket).pipe(conn).on('error', err => {
			logger(`postOpenpgpRouteSocket createConnection conn.pipe on error`, err)
		})
		
		conn.write (rawHttpRequest)

	})

	
	conn.on ('error', err => {
		logger (Colors.red(`Fardward node ${ ipAddr }:${port} on error [${err.message}] STOP connect \n`) )
		sourceSocket.destroy()
	})

	conn.once ('close', () => {
		logger(Colors.magenta(`Fardward node ${ ipAddr }:${port} on Close!`))
		sourceSocket.destroy()
	})
}

const forwardEncryptedSocket = async (socket: Socket, encryptedText: string, gpgPublicKeyID: string) => {


	//			forward encrypted text
	const _route = getRoute (gpgPublicKeyID)

	if ( !_route ) {
		
		logger (Colors.magenta(`forwardEncryptedText can not find router for [${ gpgPublicKeyID }]`))
		return response200Html(socket, JSON.stringify({}))
	}

	return socketForward( _route, 80, socket, encryptedText)

}

export const checkSignObj = (message: string, signMess: string) => {
	if (!message || !signMess) {
		return null
	}
	let obj: minerObj
	try {
		obj = JSON.parse(message)
	} catch (ex) {
		logger (Colors.red(`checkSignObj JSON.parse(message) Error`), message)
		return null
	}

	let digest, recoverPublicKey, _digest
	try {
		digest = ethers.id(message)
		recoverPublicKey = ethers.recoverAddress(digest, signMess)
		ethers.getAddress(recoverPublicKey)
	} catch (ex) {
		// logger (colors.red(`checkSignObj recoverPublicKey ERROR digest = ${digest} signMess = ${signMess}`))
		return null
	}
	
	if (!recoverPublicKey || !obj?.walletAddress || recoverPublicKey.toLowerCase() !== obj?.walletAddress?.toLowerCase()) {
		logger (Colors.red(`checkSignObj obj Error! !recoverPublicKey[${!recoverPublicKey}] !obj?.walletAddress[${!obj?.walletAddress}] recoverPublicKey.toLowerCase() [${recoverPublicKey.toLowerCase()}]!== obj?.walletAddress?.toLowerCase() [${recoverPublicKey.toLowerCase() !== obj?.walletAddress?.toLowerCase()}]`),inspect(obj, false, 3, true) )
		return null
	}
	obj.walletAddress = recoverPublicKey.toLowerCase()
	return obj

}

const pgpTest = async () => {
	const password = 'ddd'
	const { privateKey, publicKey, revocationCertificate } = await generateKey({
        type: 'ecc', // Type of the key, defaults to ECC
        curve: 'curve25519', // ECC curve name, defaults to curve25519
        userIDs: [{ name: 'Jon Smith', email: 'jon@example.com' }], // you can pass multiple user IDs
        passphrase: password, // protects the private key
        format: 'armored' // output key format, defaults to 'armored' (other options: 'binary' or 'object')
    })
	const message = await createMessage({ text: 'hello' })
	const _key = await readKey({armoredKey: publicKey})
	const encrypted = await encrypt({
        message,
		encryptionKeys:[_key],
        format: 'armored' // don't ASCII armor (for Uint8Array output)
    })
	const enessage = await readMessage({
        armoredMessage: encrypted // parse armored message
    })
	const keys = await enessage.getEncryptionKeyIDs()
	logger (keys)
}


/**
 * 			TEST
 */

/*
pgpTest()

/** */