
import { join } from 'node:path'
import { inspect, } from 'node:util'
import Cluster from 'node:cluster'
import {Socket, createServer} from 'node:net'
import {logger} from '../util/logger'
import {postOpenpgpRouteSocket, IclientPool, generateWalletAddress, getPublicKeyArmoredKeyID, getSetup, loadWalletAddress, makeOpenpgpObj, saveSetup, testCertificateFiles, CertificatePATH, startEPOCH_EventListeningForMining, Restart} from '../util/localNodeCommand'
import Colors from 'colors/safe'
import { readFileSync} from 'fs'
import {createServer as createServerSSL, TLSSocket} from 'node:tls'
import  { distorySocket } from '../util/htmlResponse'
import {Wallet} from 'ethers'
import {forwardToSolanaRpc, forwardToSilentpass, forwardTojup_ag } from './solanaRPC'
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

process.on('uncaughtException', (err, origin) => {
	console.error(`Caught exception: ${err}\n` +
					`Exception origin: ${origin}`)
	Restart()
})

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
// 輔助函數：處理 OPTIONS 預檢請求
const responseOPTIONS = (socket: Socket, requestHanders: string[]) => {
	const originHeader = requestHanders.find(h => h.toLowerCase().startsWith('origin:'))
	const origin = originHeader ? originHeader.split(/: */, 2)[1] : '*'

	const response = [
		'HTTP/1.1 204 No Content',
		`Access-Control-Allow-Origin: *`,
		'Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS',
		'Access-Control-Allow-Headers: solana-client, DNT, X-CustomHeader, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Content-Type',
		'Content-Length: 0',
		'Connection: keep-alive',
		'\r\n'
	].join('\r\n')

	socket.end(response)
}

const getDataPOST = async (socket: Socket, conet_si_server: conet_si_server, chunk: Buffer) => {
	
	const getMoreData = (data: string): Promise<string> => new Promise(async executor => {
		
		
		socket.once('data', _data => {
			data += _data.toString()
		})

		const request_line = data.split('\r\n\r\n')
		if (request_line.length < 2) {
			return await getMoreData(data)
		}
		executor (data)
	})



	if (!conet_si_server.initData || !conet_si_server.initData?.pgpKeyObj?.privateKeyObj) {
		logger (Colors.red(`this.initData?.pgpKeyObj?.privateKeyObj NULL ERROR \n`), inspect(conet_si_server.initData, false, 3, true), '\n')
		return distorySocket(socket)
	}

	const data = await getMoreData(chunk.toString())

	const request_line = data.split('\r\n\r\n')
	const htmlHeaders = request_line[0].split('\r\n')
	
	const requestProtocol = htmlHeaders[0]
	const path = requestProtocol.split(' ')[1]
	const method = requestProtocol.split(' ')[0]



	//	*********************
	if (/^\/solana\-rpc/i.test(path)) {
		return forwardToSolanaRpc (socket, request_line[1], htmlHeaders)
	}

	if (/^\/jup_ag/i.test(path)) {
		return forwardTojup_ag(socket, request_line[1], htmlHeaders)
	}

	if (method === 'GET') {
		//		GET Home
		if (path === '/') {
			return responseRootHomePage(socket)
		}
		//		forward to silentpass package
		if (/\/silentpass\-rpc/i.test(path)) {
			return forwardToSilentpass (socket, request_line[1], htmlHeaders)
		}
		//		unknow request!
		return distorySocket(socket)
	}

	let body: {data?: string}
	try {
		body = JSON.parse(request_line[1])
	} catch (ex) {
		console.log (`JSON.parse Ex ERROR! ${socket.remoteAddress}\n distorySocket request = ${request_line[0]}`, inspect({request:request_line[1], addr: socket.remoteAddress}, false, 3, true))
		return distorySocket(socket)
	}


	if (!body?.data || typeof body.data !== 'string') {
		logger (Colors.magenta(`startServer HTML body is ont string error! ${socket.remoteAddress}`))
		logger(request_line[1])
		return distorySocket(socket)
	}

	

	//logger (Colors.magenta(`SERVER call postOpenpgpRouteSocket body.data = ${body.data.length}  ${socket.remoteAddress}`))
	//console.log (`------${socket.remoteAddress}  [${JSON.stringify(body.data)}]`)
	return postOpenpgpRouteSocket (socket, htmlHeaders, body.data, conet_si_server.initData.pgpKeyObj.privateKeyObj, conet_si_server.publicKeyID, conet_si_server.nodeWallet)
}


const socketData = (socket: Socket, server: conet_si_server, incomeData = '') => {
	// ==========================================================
	// ===== 這是關鍵：為 socket 實例添加 'error' 事件監聽器 =====
	// ==========================================================

	socket.once('data', data => {

		const request = incomeData + data.toString()
		const request_line = request.split('\r\n\r\n')

		const htmlHeaders = request_line[0].split('\r\n')
		const requestProtocol = htmlHeaders[0]

		if (/^OPTIONS /.test(requestProtocol)) {
			logger (inspect(htmlHeaders, false, 3, true))
			return responseOPTIONS(socket, htmlHeaders)
		}

		if (/^(POST|GET)/.test(requestProtocol)) {
			
			return getDataPOST (socket, server, data )
			
		}

		return distorySocket(socket)
	})
	
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

	private startServer = () => {
		
		const server = createServer( socket => {
			socket.on('error', (err: any) => {
				// 專門處理 ECONNRESET 錯誤
				if (err.code === 'ECONNRESET') {
					// 這種錯誤很常見，通常表示客戶端非正常關閉了連線。
					console.warn(`[${socket.remoteAddress}] 發生 ECONNRESET 錯誤，客戶端可能已強制關閉。這是可預期的。`);
				} else {
					// 其他類型的錯誤
					console.error(`[${socket.remoteAddress}] 發生未預期的 socket 錯誤:`, err)
				}
				
				// 不需要手動銷毀 socket，因為發生錯誤後，'close' 事件會自動被觸發。
			})

			return socketData (socket, this)

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
			socket.on('error', (err: any) => {
				// 專門處理 ECONNRESET 錯誤
				if (err.code === 'ECONNRESET') {
					// 這種錯誤很常見，通常表示客戶端非正常關閉了連線。
					console.warn(`[${socket.remoteAddress}] 發生 ECONNRESET 錯誤，客戶端可能已強制關閉。這是可預期的。`);
				} else {
					// 其他類型的錯誤
					console.error(`[${socket.remoteAddress}] 發生未預期的 socket 錯誤:`, err)
				}
				
				// 不需要手動銷毀 socket，因為發生錯誤後，'close' 事件會自動被觸發。
			})

			return socketData( socket, this)
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