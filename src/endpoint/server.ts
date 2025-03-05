
import { join } from 'node:path'
import { inspect, } from 'node:util'
import Cluster from 'node:cluster'
import {Socket, createServer} from 'node:net'
import {logger} from '../util/logger'
import {postOpenpgpRouteSocket, IclientPool, generateWalletAddress, getPublicKeyArmoredKeyID, getSetup, loadWalletAddress, makeOpenpgpObj, saveSetup, testCertificateFiles, CertificatePATH, startEPOCH_EventListeningForMining} from '../util/localNodeCommand'
import Colors from 'colors/safe'
import { readFileSync} from 'fs'
import {createServer as createServerSSL, TLSSocket} from 'node:tls'
import  { distorySocket } from '../util/htmlResponse'
import {Wallet} from 'ethers'
import {forwardToSolana } from './solanaRPC'
//@ts-ignore
import hexdump from 'hexdump-nodejs'

const packageFile = join (__dirname, '..', '..','package.json')
const packageJson = require ( packageFile )
const version = packageJson.version
const onlineClientPool: IclientPool[] = []

export const hexDebug = ( buffer: Buffer, length: number= 256 ) => {
    console.log(Colors.underline(Colors.green(`TOTAL LENGTH [${ buffer.length }]`)))
    console.log(Colors.grey( hexdump( buffer.slice( 0, length ))))
}

const getLengthHander = (headers: string[]) => {
	const index = headers.findIndex( n => /^Content-Length\:/i.test(n))
	if (index < 0) {
		//logger (inspect(headers, false, 3, true))
		return -1
	}
	const length = headers[index].split(/^Content-Length\: /i)[1]
	const ret = parseInt(length)
	return isNaN(ret) ? -1 : ret
}

const indexHtmlFileName = join(`${__dirname}`, 'index.html')

const responseRootHomePage = (socket: Socket|TLSSocket) => {
	const homepage = readFileSync(indexHtmlFileName, 'utf-8') + '\r\n\r\n'
	//	@ts-ignore
	const ret = `HTTP/1.1 200 OK\r\n` +
	`Server: nginx/1.24.0 (Ubuntu)\r\n` +
	//@ts-ignore
	`Date: ${new Date().toGMTString()}\r\n` +
	`Content-Type: text/html\r\n` +
	`Content-Length: ${homepage.length}\r\n`+
	`Connection: keep-alive\r\n` +
	'access-control-allow-origin: *\r\n' +
	`Accept-Ranges: bytes\r\n\r\n` + homepage
	
	if (socket.writable) {
		socket.write(ret, err => {
			socket.end(() => {
				logger(Colors.blue(`responseRootHomePage PIPE End() ${socket?.remoteAddress} socket.writable = ${socket.writable} homepage length =${homepage.length}`))
			})
			
		})
	}
	
}


//		curl -v -i -X OPTIONS https://solana-rpc.conet.network/
const responseOPTIONS = (socket: Socket|TLSSocket) => {
	let response = `HTTP/1.1 204 No Content\r\n`
		response += `Server: nginx/1.24.0 (Ubuntu)\r\n`
		//	@ts-ignore
		response += `Date: ${new Date().toGMTString()}\r\n`
		response += `Connection: keep-alive\r\n`
		response += `Access-Control-Allow-Origin: *\r\n`
		response += `Access-Control-Allow-Credentials: true\r\n`
		response += `Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n`
		response += `Access-Control-Allow-Headers: solana-client,DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type\r\n`
		response += `Content-Length\r\n\r\n`
	socket.end(response)
}

const getData = (socket: Socket, request: string, requestProtocol: string, conet_si_server: conet_si_server) => {

	if (!conet_si_server.initData || !conet_si_server.initData?.pgpKeyObj?.privateKeyObj) {
		logger (Colors.red(`this.initData?.pgpKeyObj?.privateKeyObj NULL ERROR \n`), inspect(conet_si_server.initData, false, 3, true), '\n')
		return distorySocket(socket)
	}
	let body
	const request_line = request.split('\r\n\r\n')
	try {
		body = JSON.parse(request_line[1])
	} catch (ex) {
		return distorySocket(socket)
	}

	const htmlHeaders = request_line[0].split('\r\n')
	//logger (Colors.magenta(`startServer getData request_line.length [${request_line[1].length}] bodyLength = [${bodyLength}]`))

	
	if (!body.data || typeof body.data !== 'string') {
		logger (Colors.magenta(`startServer HTML body is ont string error!`))
		logger(request_line[1])
		distorySocket(socket)
	}

	

	//logger (Colors.magenta(`SERVER call postOpenpgpRouteSocket nodePool = [${ this.nodePool }]`))
	return postOpenpgpRouteSocket (socket, htmlHeaders, body.data, conet_si_server.initData.pgpKeyObj.privateKeyObj, conet_si_server.publicKeyID, conet_si_server.nodeWallet)
}

class conet_si_server {

	private PORT=0
	private password = ''
	private debug = true
	private workerNumber = 0
	public  nodeWallet: Wallet|null = null
	public nodePool = []
	public publicKeyID = ''
	private nodeIpAddr = ''
	public initData:ICoNET_NodeSetup|null = null

	private initSetupData = async () => {
		
		this.initData = await getSetup ()
		if ( Cluster.isWorker && Cluster?.worker?.id ) {
			this.workerNumber = Cluster?.worker?.id
		}

		logger (inspect(this.initData, false, 3, true))

		if ( !this.initData?.keychain || this.initData?.passwd === undefined) {
            logger ('initData?.keychain = ',this.initData?.keychain,'initData.passwd = ', this.initData?.passwd)
			throw new Error (`Error: have no setup data!\nPlease restart CoNET-SI with node dist/cli start!`)
		}

        logger (`initSetupData initData.passwd = [${this.initData.passwd}]`)

		this.password = this.initData.passwd

		this.initData.pgpKeyObj = await makeOpenpgpObj(this.initData.pgpKey.privateKey, this.initData.pgpKey.publicKey, this.password)
		try {
			this.initData.keyObj = await loadWalletAddress ( this.initData.keychain, this.password )
		} catch (ex) {
			this.initData.keychain = await generateWalletAddress (this.password)
			this.initData.keyObj = await loadWalletAddress ( this.initData.keychain, this.password )
		}
		
		//this.publicKeyID = this.initData.pgpKeyObj.publicKeyObj.getKeyIDs()[1].toHex().toUpperCase()

		this.PORT = this.initData.ipV4Port

		const newID = await getPublicKeyArmoredKeyID(this.initData.pgpKey.publicKey)	//	same as this.initData.pgpKeyObj.publicKeyObj.getKeyIDs()[1].toHex().toUpperCase()
		this.publicKeyID = newID
		logger (`this.initData.pgpKey.keyID [${this.initData.pgpKey.keyID}] <= newID [${newID}]`)
		logger(Colors.blue(`pgpKey base64 \n`), Buffer.from(this.initData.pgpKey.publicKey).toString('base64'))
		this.initData.pgpKey.keyID = newID
		const ipaddress = this.initData.ipV4 ? this.initData.ipV4.split(':') : []
		this.nodeIpAddr = ipaddress.length ? ipaddress[ipaddress.length-1] : ''

		this.initData.platform_verison = version
		saveSetup ( this.initData, true )
		const wallet: Wallet = this.initData.keyObj
		this.nodeWallet = wallet

		const ssl = await testCertificateFiles ()
		if (ssl) {
			this.startSslServer ()
		}

		this.startServer ()
	}

	constructor () {
        this.initSetupData ()
    }

	private sockerdata = (socket: Socket|TLSSocket) => {
		//logger(Colors.gray(`sockerdata has new connect ${socket.remoteAddress}`))
		let first = true
		let data = ''


		const responseHeader = (option: boolean) => {
			// logger(`responseHeader send response headers to ${socket.remoteAddress}`)
			const ret = `HTTP/1.1 ${option ? 204 : 200 } OK\r\n` +
						//	@ts-ignore
						`Date: ${new Date().toGMTString()}\r\n` +
						`Server: nginx/1.24.0 (Ubuntu)\r\n` +
						`access-control-allow-origin: *\r\n` +
						`content-type: text/event-stream\r\n` +
						`Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n` +
						`Access-Control-Allow-Headers: X-PINGOTHER, Content-Type\r\n` +
						`Cache-Control: no-cache\r\n` +
						`Connection: Keep-Alive\r\n\r\n`
				
			if (socket.writable) {
				if (option) {
					return socket.end(ret).destroy()
				}
				return socket.write (ret, err => {
					if (err) {
						return socket.destroy()
					}
					
				})
			}
		}

		socket.on('data', (_data: Buffer) => {
			data += _data
			const request = data.toString()
			const request_line = request.split('\r\n\r\n')
			const htmlHeaders = request_line[0].split('\r\n')
			const requestProtocol = htmlHeaders[0]
			const requestPath = requestProtocol.split(' ')[1]
			const bodyLength = getLengthHander (htmlHeaders)

			if (first) {
				if (/^GET \/ HTTP\//.test(requestProtocol)) {
					return responseRootHomePage(socket)
				}
				first = false
				return responseHeader(/^OPTIONS /.test(requestProtocol))
			}

			if (request_line[1].length < bodyLength) {
				return 
			}

			if (/^POST \/post HTTP\/1.1/.test(requestProtocol)) {
				//logger (Colors.blue(`/post access! from ${socket.remoteAddress} bodyLength=${bodyLength}`))
				return getData (socket, request, requestProtocol, this)
			}

			if (/^OPTIONS \/ HTTP\//.test(requestProtocol)) {
				logger (inspect(htmlHeaders, false, 3, true))
				return responseOPTIONS(socket)
			}
			// const path = requestProtocol.split(' ')[1]
			// if (/\/solana\-rpc/i.test(path)) {
			// 	return forwardToSolana (socket, request_line[1], request_line)
			// }
			distorySocket(socket)
		})

		// socket.once('end', () => {
		// 	logger(Colors.green(`${socket.remoteAddress} on END`))
		// })

		socket.on('error', err => {
			
		})
	}

	private startServer = () => {
		
		const server = createServer( socket => {

			socket.once('data', data => {

				const request = data.toString()
				
				const request_line = request.split('\r\n\r\n')
				
				if (request_line.length < 2) {
					return distorySocket(socket)
				}
				const htmlHeaders = request_line[0].split('\r\n')
				const requestProtocol = htmlHeaders[0]
				const requestPath = requestProtocol.split(' ')[1]

				if (/^POST \/post HTTP\/1.1/.test(requestProtocol)) {
					//logger (Colors.blue(`/post access! from ${socket.remoteAddress}`))
					const bodyLength = getLengthHander (htmlHeaders)

					const readMore = () => {
						//logger (Colors.magenta(`startServer readMore request_line.length [${request_line[1].length}] bodyLength = [${bodyLength}]`))
						socket.once('data', _data => {
							
							request_line[1] += _data
							if (request_line[1].length < bodyLength) {
								//logger (Colors.magenta(`startServer readMore request_line.length [${request_line[1].length}] bodyLength = [${bodyLength}]`))
								return readMore ()
							}
							
							return getData (socket, request, requestProtocol, this)
						})
					}

					if (request_line[1].length < bodyLength) {
						return readMore ()
					}

					return getData (socket, request, requestProtocol, this)
					
				}

				if (/^GET \/ HTTP\//.test(requestProtocol)) {
					logger (inspect(htmlHeaders, false, 3, true))
					return responseRootHomePage(socket)
				}

				if (/^OPTIONS \/ HTTP\//.test(requestProtocol)) {
					logger (inspect(htmlHeaders, false, 3, true))
					return responseOPTIONS(socket)
				}
				const path = requestProtocol.split(' ')[1]

				if (/\/solana\-rpc/i.test(path)) {
					return forwardToSolana (socket, request_line[1], request_line)
				}
				return distorySocket(socket)
			})

		})

		server.on('error', err => {
			logger(Colors.red(`conet_si_server server on Error! ${err.message}`))
		})

		server.listen ( this.initData?.ipV4Port, () => {
			logger(Colors.blue(`__dirname = ${__dirname}`))
			
			return console.table([
                { 'CoNET SI node': `version ${version} startup success Url http://localhost:${ this.PORT } doamin name = ${this.publicKeyID}.conet.network` }
				
            ])
		})
	}

	private startSslServer = () => {
		const key = readFileSync(CertificatePATH[1])
		const cert = readFileSync(CertificatePATH[0])
		const options = {
			key,
			cert
		}
		
		const server = createServerSSL (options, socket => {
			this.sockerdata (socket)
		})

		server.listen(443, () => {
			if (this.nodeWallet) {
				startEPOCH_EventListeningForMining(this.nodeWallet, this.publicKeyID, this.nodeIpAddr)
			}
			
			return console.table([
                { 'CoNET SI SSL server started': `version ${version} startup success Url http://localhost:443 doamin name = ${this.publicKeyID}.conet.network wallet = ${this.nodeWallet?.address}` }
            ])
		})

	}
}

export default conet_si_server