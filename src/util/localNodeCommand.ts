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
import {getRoute, startUp} from './util'
import { ethers } from 'ethers'
import IP from 'ip'
import {TLSSocket} from 'node:tls'
import {resolve4} from 'node:dns'
import {access, constants} from 'node:fs/promises'
import { routerInfo, checkPayment, CoNET_CancunRPC, putUserMiningToPaymendUser, getAllNodes} from '../util/util'

import P from 'phin'
import epoch_info_ABI from './epoch_info_managerABI.json'
import nodeRestartABI from './nodeRestartABI.json'
import { mapLimit } from 'async'




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
const CONETProvider = new ethers.JsonRpcProvider(CoNET_CancunRPC)
export const loadWalletAddress = async ( walletBase: string, password: string ) => {
	//logger (inspect(walletBase, false, 3, true))
	if (typeof walletBase === 'object') {
		walletBase = JSON.stringify(walletBase)
	}
	const account = await Wallet.fromEncryptedJson (walletBase, password)
	//logger (inspect(account, false, 3, true))
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

	//ogger (`register_to_DL [${ inspect(option, false, 3, true )}] connect to DL server`)

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
			dl_publicKeyArmored: setup.dl_publicKeyArmored,
			sslDate: setup.sslDate,
			restartBlockNumber: setup.restartBlockNumber||0
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
                                    // logger (Colors.blue(`connectWithHttp set-cookie requestHeaders['Cookie'] [${l}]`))
                                    // logger (inspect(requestHeaders, false, 3, true))
                                }
                            }
                        }
                    }
                    requestHeaders['Cookie'] = cookieNew.join(';')
                }

                logger (Colors.blue(`connectWithHttp got redirection [${_res.statusCode}] response from [${requestOrgnalUrl.origin}] to new Location [${reUrl}] with cookies! reDirect[${reDirect}] `))
                requestOrgnal1.href = reUrl.href

                return connectWithHttp(requestOrgnal1, clientRes, password, requestHeaders, reDirectCount)
            }
            default: {
                return processStream()
            }
        }
    }


    const httpConnecting = () => {
        logger (Colors.blue(`connectWithHttp connecting reDirectCount = [${reDirectCount}]`))
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


export const localNodeCommandSocket = async (socket: Socket, headers: string[], command: minerObj, wallet: ethers.Wallet|null) => {
	//logger(`wallet ${command.walletAddress} command = ${command.command}`)
	switch (command.command) {

		case 'SaaS_Sock5': {
			const payment = await checkPayment(command.walletAddress)

			if (!payment) {
				logger(Colors.red(`[${command.walletAddress}] Payment Error!`))
				return distorySocket(socket, '402 Payment Required')
			}
			
			logger(Colors.magenta(`${command.walletAddress} passed payment [${payment}] process SaaS!`))

			const prosyData = command.requestData[0]
			return socks5Connect(prosyData, socket, command.walletAddress)
		}

        case 'SaaS_Proxy': {
            
			const payment = checkPayment(command.walletAddress)

			if (!payment) {
				logger(Colors.red(`[${command.walletAddress}] Payment Error!`))
				return distorySocket(socket, '402 Payment Required')
			}
			const requestHeaders = command.requestData[1]
            const requestOrgnal = command.requestData[0]

            // logger (Colors.blue(`SaaS_Proxy get Request\n`))
            // logger (Colors.blue(`SaaS_Proxy requestHeaders\n`), inspect(requestHeaders, false, 3, true))
            // logger (`SaaS_Proxy clientReq headers\n`, headers)
			// logger(Colors.magenta(`${command.walletAddress} passed payment [${payment}] process SaaS!`))
            const password = command.Securitykey
            // const _encrypt = new encrypteStream (keyJSON, command.iv, MB)
            //#endregion 
            if (!password) {
                logger (Colors.red(`SaaS_Proxy have no password error! [${inspect(command, false, 3, true)}]`))
                return distorySocket(socket)
            }

            return connectWithHttp(requestOrgnal, socket, password, requestHeaders)
        }

		case 'mining': {		
			return addIpaddressToLivenessListeningPool(socket.remoteAddress||'', command.walletAddress, wallet, socket)
		}

		case 'mining_validator': {
			return validatorMining(command, socket)
		}

		// case 'mining_gossip': {
		// 	logger(`mining_gossip...`)
		// 	return addToGossipPool (socket.remoteAddress||'', command.walletAddress, socket)
		// }

		default : {
			logger (Colors.red(`postOpenpgpRoute invalid command [${inspect(command, false, 3, true)}]`))
			return distorySocket(socket)
		}
	}

}

const validatorMinerPool: Map<string, boolean> = new Map()
const validatorUserPool: Map<string,  NodeJS.Timeout> = new Map()

const validatorMining = async (command: minerObj, socket: Socket ) => {

	const validatorData: nodeResponse = command.requestData
	
	if (!validatorData|| !validatorData.nodeWallet|| !validatorData.hash||!command?.walletAddress) {
		logger(Colors.red(`${command.walletAddress} validatorMining has null validatorData`))
		logger(inspect(command, false, 3, true))
		return distorySocket(socket)
	}
	
	const wallet = command.walletAddress.toLowerCase()
	const message = {epoch: validatorData.epoch.toString(), wallet}
	const nodeWallet = ethers.verifyMessage(JSON.stringify(message), validatorData.hash).toLowerCase()
	//logger(`validatorMining [${wallet}]  ********************`)
	if (nodeWallet !== validatorData.nodeWallet.toLowerCase()) {
		logger(Colors.red(`validatorMining verifyMessage hash Error! nodeWallet ${nodeWallet} !== validatorData.nodeWallet.toLowerCase() ${validatorData.nodeWallet.toLowerCase()} wallet = ${wallet}`))
		logger(inspect(command, false, 3, true))
		return distorySocket(socket)
	}


	// logger(Colors.magenta(`Miner ${wallet} Epoch validator [${validatorData.epoch}] Success!`))
	// logger(inspect(validatorData, false, 3, true))
	const nodeInfo = routerInfo.get (validatorData.nodeDomain)

	if (!nodeInfo ) {
		logger(Colors.red(`wallet ${command.walletAddress} node ${nodeWallet} has no domain ${validatorData.nodeDomain} Error! routerInfo size = ${routerInfo.size}`))
		//logger(inspect(routerInfo.keys(), false, 3, true))
		return distorySocket(socket)
	}

	if(!nodeInfo.wallet){
		
		
		logger(Colors.blue(`${command.walletAddress} getGuardianNodeWallet Error!`))
		return distorySocket(socket)
	}

	if (nodeInfo.wallet !== nodeWallet) {
		logger(Colors.red(`${nodeWallet} node hash from domain ${validatorData.nodeDomain} of nodeInfo.wallet = ${nodeInfo ?nodeInfo.wallet: ''} !== nodeWallet ${nodeWallet} have not node information Error!`))
		
		logger(inspect(nodeInfo, false, 3, true))
		return distorySocket(socket)
	}

	const validatorWallet = ethers.verifyMessage(validatorData.hash, validatorData.minerResponseHash).toLowerCase()

	if (validatorWallet !== wallet) {
		logger(Colors.red(`${command.walletAddress} validator Wallet ${validatorWallet} different than command.walletAddress ${wallet} Error!`))
		return distorySocket(socket)
	}


	
	const epochNumber = parseInt(validatorData.epoch.toString())
	
	if (CurrentEpoch - epochNumber > 5) {
		logger(Colors.red(`wallet ${command.walletAddress} epochNumber ${epochNumber} < CurrentEpoch ${CurrentEpoch} = ${CurrentEpoch - epochNumber} 5 `))
		return distorySocket(socket)
	}

	if (validatorData.isUser) {


		//logger(`validatorData ${wallet} ephco ${epochNumber} CurrentEpoch ${CurrentEpoch} delay = [${CurrentEpoch - epochNumber}] goto USER Pool! `)
		const timeout = validatorUserPool.get(wallet)
		clearTimeout(timeout)

		const _timeout = setTimeout(() => {
			logger(`DELETE validatorWallet ${wallet} from pool total = ${validatorUserPool.size}`)
			validatorUserPool.delete(wallet)
		}, 1000 * 60 * 5)

		//logger(`Added validatorWallet ${wallet} to pool total = ${validatorUserPool.size}`)
		validatorUserPool.set (wallet, _timeout)
		return response200Html(socket, JSON.stringify(validatorData))
	}
	
	if (CurrentEpoch - epochNumber > 0) {
		//logger(Colors.red(`wallet ${command.walletAddress} node ${nodeWallet} epochNumber ${epochNumber} < CurrentEpoch ${CurrentEpoch} = ${CurrentEpoch - epochNumber}`))
		return distorySocket(socket)
	}
	
	validatorMinerPool.set (wallet, true)
	//logger(`added miner[${wallet}] to validatorMinerPool size = ${validatorMinerPool.size}`)
	return response200Html(socket, JSON.stringify(validatorData))
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

const socks5Connect = async (prosyData: VE_IPptpStream, resoestSocket: Socket, wallet: string) => {

    logger (Colors.blue (`${wallet} socks5Connect connect to [${prosyData.host}:${prosyData.port}]`))
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

	if ( port < 1 || port > 65535 || !host) {
		return distorySocket(resoestSocket)
	}

	try {
		const socket = createConnection ( port, host, () => {

			socket.pipe(resoestSocket).pipe(socket).on('error', err => {
				logger(Colors.red(`socks5Connect pipe on Error ${wallet}`), err)
			})
	
			const data = Buffer.from(prosyData.buffer, 'base64')
			socket.write (data)
			resoestSocket.resume()
		})
	
		socket.once ( 'end', () => {
			// logger (Colors.red(`socks5Connect host [${host}:${port}] on END!`))
			resoestSocket.end().destroy()
		})
	
		socket.once ( 'error', err => {
			resoestSocket.end().destroy()
			logger (Colors.red(`socks5Connect [${host}:${port}] on Error! [${err.message}]`))
	
		})
	
		resoestSocket.once('error', err => {
			resoestSocket.end().destroy()
			logger (Colors.red(`socks5Connect host [${host}:${port}] resoestSocket ON Err [${err.message}]`))
		})
	} catch (ex) {
		logger(`createConnection On catch ${wallet}`, ex)
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

export const postOpenpgpRouteSocket = async (socket: Socket, headers: string[],  pgpData: string, pgpPrivateObj: any, pgpPublicKeyID: string, wallet: ethers.Wallet|null) => {

	//logger (Colors.red(`postOpenpgpRoute clientReq headers = `), inspect(headers, false, 3, true ), Colors.grey (`Body length = [${pgpData?.length}]`))

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
		logger(Colors.blue(`postOpenpgpRouteSocket encrypKeyID  [${customerKeyID}] is not this node's key ${pgpPublicKeyID} forward to destination node!`))
		return forwardEncryptedSocket(socket, pgpData, customerKeyID)
	}

	let content

	try {
		const decryptedObj = await decryptMessage ( messObj, pgpPrivateObj)
		content = JSON.parse(Buffer.from(decryptedObj.data.toString(),'base64').toString())
		
		content.pgpSign
	} catch (ex) {
		logger (Colors.red(` decryptMessage EX ERROR, distorySocket!`))
		return distorySocket(socket)
	}

	if (!content.message ||!content.signMessage) {
		logger (Colors.red(`Command format Error`))
		logger(inspect(content, false,3, true))
		return distorySocket(socket)
	}



	const command = checkSign (content.message, content.signMessage)

	if (!command) {
		logger(Colors.red(`checkSignObj Error!`))
		return distorySocket(socket)
	}
	
	return localNodeCommandSocket(socket, headers, command, wallet )
	
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
	const _route = await getRoute (gpgPublicKeyID)

	if ( !_route ) {
		logger (Colors.magenta(`forwardEncryptedText can not find router for [${ gpgPublicKeyID }]`))
		return response200Html(socket, JSON.stringify({}))
	}
	logger(Colors.blue(`forwardEncryptedSocket ${gpgPublicKeyID} to node ${_route}`))
	return socketForward( _route, 80, socket, encryptedText)

}

export const checkSign = (message: string, signMess: string) => {
	let digest, recoverPublicKey, verifyMessage, obj: minerObj
	let wallet = ''
	try {
		obj = JSON.parse(message)
		wallet = obj.walletAddress
		digest = ethers.id(message)
		recoverPublicKey = ethers.recoverAddress(digest, signMess)
		verifyMessage = ethers.verifyMessage(message, signMess)

	} catch (ex) {
		logger (Colors.red(`checkSignObj recoverPublicKey ERROR`), ex)
		logger (`digest = ${digest} signMess = ${signMess}`)
		return null
	}
	

	if (wallet && (verifyMessage.toLowerCase() === wallet.toLowerCase() || recoverPublicKey.toLowerCase() === wallet.toLowerCase())) {
		obj.walletAddress = wallet.toLowerCase()
		return obj
		
	}
	
	logger (Colors.red(`checkSignObj recoveredAddress (${verifyMessage.toLowerCase()}) or recoverPublicKey ${recoverPublicKey.toLowerCase()} !== wallet (${wallet.toLowerCase()})`))
	return null
	
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

export const CertificatePATH = ['/etc/letsencrypt/live/slickstack/cert.pem','/etc/letsencrypt/live/slickstack/privkey.pem']
export const testCertificateFiles: () => Promise<boolean> = () => new Promise (async resolve => {
	try {
		await Promise.all([
			access(CertificatePATH[0], constants.R_OK),
			access(CertificatePATH[1], constants.R_OK),
		])
		logger(`testCertificateFiles success!`)
		return resolve (true)
	} catch (ex) {
		logger(ex)
		return resolve (false)
	}
})

interface livenessListeningPoolObj {
	res: Socket|TLSSocket
	ipaddress: string
	wallet: string
}
//			getIpAddressFromForwardHeader(req.header(''))

const livenessListeningPool: Map <string, livenessListeningPoolObj> = new Map()

const addIpaddressToLivenessListeningPool = async (ipaddress: string, wallet: string, nodeWallet: ethers.Wallet| null, res: TLSSocket|Socket) => {
	const _obj = livenessListeningPool.get (wallet)
	if (_obj) {
		if (_obj.res.writable && typeof _obj.res.end === 'function') {
			_obj.res.end().destroy()
		}
	}
	const obj: livenessListeningPoolObj = {
		ipaddress, wallet, res
	}
	
	livenessListeningPool.set (wallet, obj)

	const returnData = {
		ipaddress,
		epoch: CurrentEpoch,
		status: 200,
		nodeWallet: nodeWallet?.address?.toLowerCase(),
		hash: await nodeWallet?.signMessage(CurrentEpoch.toString())
	}

	// @ts-ignore
	const responseData = typeof res.getTLSTicket !== 'function'
	//@ts-ignore
		? `HTTP/1.1 200 OK\r\nDate: ${ new Date ().toGMTString()}\r\nContent-Type: text/plain\r\nAccess-Control-Allow-Origin: *\r\nConnection: keep-alive\r\nVary: Accept-Encoding\r\n\r\n${JSON.stringify(returnData)}\r\n\r\n` 
		: JSON.stringify(returnData)


	res.once('error', err => {
		logger(Colors.grey(`Clisnt ${wallet}:${ipaddress} on error! delete from Pool`), err.message)
		livenessListeningPool.delete(wallet)
	})

	res.once('close', () => {
		//logger(Colors.grey(`Clisnt ${wallet}:${ipaddress} on close! delete from Pool`))
		livenessListeningPool.delete(wallet)
	})

	//logger (Colors.cyan(` [${ipaddress}:${wallet}] Added to livenessListeningPool [${livenessListeningPool.size}]!`))

	return testMinerCOnnecting (res, responseData, wallet, ipaddress)
}

const gossipListeningPool: Map<string, livenessListeningPoolObj> = new Map()

// const addToGossipPool = (ipaddress: string, wallet: string, res: Socket|TLSSocket) => {
// 	const _obj = gossipListeningPool.get (wallet)
// 	if (_obj) {
// 		if (_obj.res.writable && typeof _obj.res.end === 'function') {
// 			_obj.res.end().destroy()
// 		}
// 	}
// 	const obj: livenessListeningPoolObj = {
// 		ipaddress, wallet, res
// 	}

// 	gossipListeningPool.set (wallet, obj)

// 	const returnData = `HTTP/1.1 200 OK\r\n` +
// 		//	@ts-ignore
// 		`Date: ${new Date().toGMTString()}\r\n` +
// 		`Server: nginx/1.24.0 (Ubuntu)\r\n` +
// 		`access-control-allow-origin: *\r\n` +
// 		`content-type: text/event-stream\r\n` +
// 		`Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n` +
// 		`Access-Control-Allow-Headers: X-PINGOTHER, Content-Type\r\n` +
// 		`Cache-Control: no-cache\r\n` +
// 		`Connection: Keep-Alive\r\n\r\n${JSON.stringify(
// 			{
// 				status: 200,
// 				epoch: CurrentEpoch - 1,
// 				rate: validatorPool.size.toString(),
// 				nodeWallet
// 			})}\r\n\r\n`

// 	res.once('error', err => {
// 		logger(Colors.grey(`Clisnt ${wallet}:${ipaddress} on error! delete from Gossip Pool`), err.message)
// 		gossipListeningPool.delete(wallet)
// 	})
// 	res.once('close', () => {
// 		logger(Colors.grey(`Clisnt ${wallet}:${ipaddress} on close! delete from Gossip Pool`))
// 		gossipListeningPool.delete(wallet)
// 	})

// 	logger (Colors.green(` [${ipaddress}:${wallet}] Added to Gossip Pool [${livenessListeningPool.size}]!`))
// 	return testMinerCOnnecting (res, returnData, wallet, ipaddress)
// }

const gossipCnnecting = (res: Socket|TLSSocket, returnData: any, wallet: string, ipaddress: string) => new Promise (resolve=> {
	logger(Colors.blue(`gossipCnnecting SENT DATA to ${res.remoteAddress}`))
	logger(inspect(returnData, false, 3, true))
	if (res.writable && !res.closed) {
		return res.write( typeof returnData === 'string' ? returnData : JSON.stringify(returnData)+'\r\n\r\n', async err => {
			if (err) {
				logger(Colors.grey (`gossipCnnecting write Error! delete ${wallet}:${ipaddress} from gossipListeningPool [${gossipListeningPool.size}]`))
				gossipListeningPool.delete(wallet)
			} else {
				logger(Colors.magenta(`gossipCnnecting to ${wallet}:${ipaddress} success!`))
			}
			
			return resolve (true)
		})
		
	}
	gossipListeningPool.delete(wallet)
	logger(Colors.grey (`gossipCnnecting write Error! delete ${wallet}:${ipaddress} from gossipListeningPool [${gossipListeningPool.size}]`))
	return resolve (true)
})

const testMinerCOnnecting = (res: Socket|TLSSocket, returnData: any, wallet: string, ipaddress: string) => new Promise (resolve=> {
	//logger(Colors.blue(`testMinerCOnnecting SENT DATA to ${res.remoteAddress}`))
	// logger(inspect(returnData, false, 3, true))
	if (res.writable && !res.closed) {
		return res.write( typeof returnData === 'string' ? returnData : JSON.stringify(returnData)+'\r\n\r\n', async err => {
			if (err) {
				//logger(Colors.red (`stratliveness write Error! delete ${wallet}:${ipaddress} from livenessListeningPool [${livenessListeningPool.size}]`))
				livenessListeningPool.delete(wallet)
			} else {
				//logger(Colors.grey(`testMinerCOnnecting to${wallet}:${ipaddress} success!`))
			}
			
			return resolve (true)
		})
		
	}
	livenessListeningPool.delete(wallet)
	logger(Colors.red (`stratliveness write Error! delete ${wallet}:${ipaddress} from livenessListeningPool [${livenessListeningPool.size}]`))
	return resolve (true)
})

let CurrentEpoch = 0
let listenValidatorEpoch = 0
let nodeWallet = ''

const epoch_mining_info_cancun_addr = '0x31680dc539cb1835d7C1270527bD5D209DfBC547'.toLocaleLowerCase()
const epoch_mining_infoSC = new ethers.Contract(epoch_mining_info_cancun_addr, epoch_info_ABI, CONETProvider)

const nodeRestartEvent_addr = '0x2b5e7A8477dB4977eC8309605B5293f3CD00fC39'
const epoch_RestartEvent_SC_readonly = new ethers.Contract(nodeRestartEvent_addr, nodeRestartABI, CONETProvider)

const checkCurrentRate = async (block: number) => {
	if ( block % 2) {
		return
	}
	let _epoch: BigInt
	let _totalMiners: BigInt
	let _minerRate: ethers.BigNumberish
	let _totalUsrs: BigInt

	try {
		[_epoch, _totalMiners, _minerRate, _totalUsrs] = await epoch_mining_infoSC.currentInfo()
	} catch (ex: any) {
		return logger(`checkCurrentRate Error! ${ex.message}`)
	}

	if (parseInt(_epoch.toString()) > 0) {
		const totalMiners = parseInt(_totalMiners.toString())
		const minerRate = parseFloat(ethers.formatEther(_minerRate))
		const totalUsrs = parseInt(_totalUsrs.toString())
		const epoch = parseInt(_epoch.toString())
		currentRate = {
			totalMiners,  minerRate, totalUsrs, epoch
		}
	}
	
	
}
let serttData: ICoNET_NodeSetup|null


const getRestart = async (block: number) => {
	if (block % 10 !== 0 ) {
		return
	}
	try {
		const restartBlockNumber = parseInt(await epoch_RestartEvent_SC_readonly.retsratBlockNumber())
		if (restartBlockNumber) {
			
			if (serttData) {
				if (serttData.restartBlockNumber < restartBlockNumber ) {
					logger(`getRestart ############################  retsratBlockNumber = ${restartBlockNumber}`)
					serttData.restartBlockNumber = restartBlockNumber
					await saveSetup(serttData, false)
					return exec("/home/peter/.sh/upgrade && sudo reboot")
				}
			}
			
		}
	} catch (ex: any) {
		logger(`getRestart Error! ${ex.message}`)
	}
	
}

let searchEpochEventProcess = false

let searchEpochEventRestartTimeout:  NodeJS.Timeout

const searchEpochEvent = (block: number) => new Promise (async resolve=> {

	logger(`searchEpochEvent started on block [${block}]`)
	clearTimeout(searchEpochEventRestartTimeout)

	logger('')
	logger('')
	if (searchEpochEventProcess) {
		resolve (false)
		return
	}

	searchEpochEventProcess = true
	await Promise.all([
		checkCurrentRate(block),
		getRestart(block)
	])

	searchEpochEventProcess = false

	searchEpochEventRestartTimeout = setTimeout(() => {
		logger(`searchEpochEvent TimeOut restart now`)
		exec("sudo systemctl restart conet.service")
	}, 1000 * 10)

	resolve (true)
})

export const startEPOCH_EventListeningForMining = async (nodePrivate: Wallet, domain: string, nodeIpAddr: string ) => {
	getAllNodes()
	serttData = await getSetup()
	listenValidatorEpoch = CurrentEpoch = await CONETProvider.getBlockNumber()
	nodeWallet = nodePrivate.address.toLowerCase()
	await getFaucet(nodePrivate)
	await startUp(nodePrivate, domain)
	
	currentRate = {
		totalMiners: 0,  minerRate: 0, totalUsrs: 0, epoch: listenValidatorEpoch
	}
	

	CONETProvider.on('block', block => {
		searchEpochEvent(block)
		if (block % 2) {
			return
		}

		logger(Colors.blue(`startEPOCH_EventListeningForMining on Block ${block} Success!`))
		
		
		CurrentEpoch = block
		moveData(block)
		// gossipStart(block)
		stratlivenessV2(block, nodePrivate, domain, nodeIpAddr)
	})
	logger(Colors.magenta(`startEPOCH_EventListeningForMining on Block ${listenValidatorEpoch} Success!`))
}

interface IGossipStatus {
	totalConnectNode: number
	epoch: number
	nodesWallets: Map<string, string[]>
	totalMiners: number
	nodeWallets: string[]
	userWallets: string []
	totalUsers: number
}

export let gossipStatus: IGossipStatus = {
	totalConnectNode: 0,
	epoch: 0,
	nodesWallets: new Map(),
	totalMiners: 0,
	nodeWallets: [],
	userWallets: [],
	totalUsers: 0
}

let previousGossipStatus = gossipStatus

interface nodeResponse {
	status: number
	epoch: number
	hash?: string
	rate: number
	online: number
	validatorPool?:string
	nodeWallet: string
	minerResponseHash: string
	nodeWallets?: string[]
	connetingNodes: number
	nodeDomain: string
	nodeIpAddr: string
	isUser?: boolean
	userWallets: string[]
	totalUsers: number
}

let moveDataProcess = false

const moveData = (block: number) => {
	if (moveDataProcess) {
		return
	}
	moveDataProcess = true
	const _wallets = [...validatorMinerPool.keys()]
	if (!_wallets) {
		moveDataProcess = false
		logger(Colors.magenta(`moveData doing ${block} validatorPool.get NULL size Error!`))
		return
	}

	logger(Colors.magenta(`moveData doing ${block} validatorPool.get (${_wallets.length}) `))
	const nodeWallets = _wallets
	const userWallets = [...validatorUserPool.keys()]
	// logger(inspect(nodeWallets, false, 3, true))
	let totalMiners = nodeWallets.length
	previousGossipStatus.nodeWallets = nodeWallets
	previousGossipStatus.totalConnectNode = gossipStatus.nodesWallets.size
	previousGossipStatus.totalMiners = totalMiners
	previousGossipStatus.userWallets = userWallets
	gossipStatus = {
		epoch: block,
		totalConnectNode: 0,
		nodesWallets: new Map(),
		totalMiners: 0,
		nodeWallets: [],
		userWallets: [],
		totalUsers: 0
	}

	userWallets.forEach(n => {
		putUserMiningToPaymendUser(n)
	})

	moveDataProcess = false
	logger(Colors.magenta(`gossipStart sendEpoch ${block} totalConnectNode ${previousGossipStatus.totalConnectNode}  totalMiners ${totalMiners} total Users ${userWallets.length}`))
}
const apiEndpoint = `https://apiv4.conet.network/api/`
const rateUrl = `${apiEndpoint}miningRate?eposh=`
const FaucetURL = `${apiEndpoint}conet-faucet`

interface rate {
	totalMiners: number
	minerRate: number
	totalUsrs: number
	epoch: number
}

const httpsPostToUrl = (url: string, body: string) => new Promise(resolve =>{
	const _url = new URL (url)
	const option: RequestOptions = {
		host: _url.host,
		port: 443,
		method: 'POST',
		protocol: 'https:',
		headers: {
			'Content-Type': 'application/json;charset=UTF-8'
		},
		path: _url.pathname,
	}
	const waitingTimeout = setTimeout(() => {
		logger(Colors.red(`httpsPostToUrl on('Timeout') [${url} ${JSON.parse(body)}!`))
		return resolve (false)
	}, 60 * 1000)

	const kkk = requestHttps(option, res => {
		clearTimeout(waitingTimeout)
		setTimeout(() => {
			resolve (true)
		}, 1000)
		
		res.once('end', () => {
			if (res.statusCode !==200) {
				return logger(`httpsPostToUrl ${url} statusCode = [${res.statusCode}] != 200 error!`)
			}

		})
		
	})

	kkk.once('error', err => {
		logger(Colors.red(`httpsPostToUrl on('error') [${url}] requestHttps on Error! no call relaunch`), err.message)
	})

	kkk.end(body)

})

export const getFaucet = async (wallet: Wallet) => {

	const data = JSON.stringify({ walletAddr: wallet.address})

	logger(Colors.blue(`getFaucet for ${wallet.address}`))
	await httpsPostToUrl(FaucetURL, data)
}

let currentRate: rate|null = null

export let lastRate = 0

let stratlivenessV2Process = false

const stratlivenessV2 = async (block: number, nodeWprivateKey: Wallet, nodeDomain: string, nodeIpAddr: string) => {
	if (stratlivenessV2Process) {
		return
	}
	stratlivenessV2Process = true
	const rate = currentRate
	if (!rate) {
		stratlivenessV2Process = false
		return logger(Colors.red(`stratlivenessV2 currentRate is NULL error STOP!`))
	}

	logger(Colors.grey(`stratliveness EPOCH ${block} starting! ${nodeWprivateKey.address} Pool length = [${livenessListeningPool.size}]`))
	logger(inspect(rate, false, 3, true))

	// clusterNodes = await getApiNodes()
	const processPool: any[] = []
	lastRate = rate?.minerRate
	
	livenessListeningPool.forEach(async (n, key) => {
		const res = n.res
		const message = {epoch: block.toString(), wallet: key}
		// logger(inspect(message, false, 3, true))
		const signMessage = await nodeWprivateKey.signMessage(JSON.stringify(message))

		const returnData = {
			status: 200,
			epoch: block.toString(),
			rate: rate?.minerRate,
			hash: signMessage,
			nodeWallet,
			online: rate?.totalMiners,
			connetingNodes: previousGossipStatus.nodesWallets.size,
			nodeDomain,
			nodeIpAddr,
			nodeWallets: previousGossipStatus.nodeWallets,
			minerResponseHash: '',
			userWallets: previousGossipStatus.userWallets,
			totalUsers: rate?.totalUsrs
		}

		processPool.push(testMinerCOnnecting(res, returnData, key, n.ipaddress))

	})

	await Promise.all(processPool)
	stratlivenessV2Process = false
}