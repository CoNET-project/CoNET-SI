
import { join } from 'node:path'
import { inspect, } from 'node:util'
import Cluster from 'node:cluster'
import {Socket, createServer, Server} from 'node:net'
import {logger} from '../util/logger'
import {postOpenpgpRouteSocket, IclientPool, generateWalletAddress, getPublicKeyArmoredKeyID, getSetup, loadWalletAddress, makeOpenpgpObj, saveSetup, testCertificateFiles, CertificatePATH, startEPOCH_EventListeningForMining, Restart} from '../util/localNodeCommand'
import Colors from 'colors/safe'
import { readFileSync} from 'fs'
import {createServer as createServerSSL, TLSSocket} from 'node:tls'
import  { distorySocket } from '../util/htmlResponse'
import {Wallet} from 'ethers'
import {forwardToSolanaRpc, forwardToSilentpass, forwardTojup_ag, forwardToHome } from './solanaRPC'
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
	// Restart()
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


/**
 * @description 修正后的服务器主处理函数。
 * 主要修改了 GET 请求的路由逻辑。
 */
export const getDataPOST = async (socket: Socket, conet_si_server: conet_si_server, chunk: Buffer) => {
    
    const getMoreData = (buf: Buffer): Promise<{ header: string, body: string, tail: Buffer }> => {
        return new Promise((resolve) => {
            const sep = Buffer.from('\r\n\r\n')
            const tryResolve = (b: Buffer): boolean => {
                const sepIndex = b.indexOf(sep)
                if (sepIndex < 0) return false

                const headerPart = b.slice(0, sepIndex).toString('ascii')
                const m = /Content-Length:\s*(\d+)/i.exec(headerPart)
                const contentLength = m ? parseInt(m[1], 10) : 0

                const need = sepIndex + sep.length + contentLength
                if (b.length < need) return false

                const bodyBuf = b.slice(sepIndex + sep.length, need)
                const tail = b.slice(need); // ★ Content-Length 之后已到达的原始流
                resolve({ header: headerPart, body: bodyBuf.toString('utf8'), tail })
                return true
            }

            if (tryResolve(buf)) return
            socket.once('data', (more: Buffer) => {
                getMoreData(Buffer.concat([buf, more])).then(resolve)
            })
        })
    }

    if (!conet_si_server.initData?.pgpKeyObj?.privateKeyObj) {
        logger(Colors.red(`this.initData?.pgpKeyObj?.privateKeyObj NULL ERROR \n`), inspect(conet_si_server.initData, false, 3, true), '\n');
        return distorySocket(socket)
    }

    const { header, body, tail } = await getMoreData(chunk)
    const bodyStr = body           
    if (tail && tail.length) {
        socket.unshift(tail)
    }

    const headerLines = header.split('\r\n')
    const requestProtocol = headerLines[0]
    const path = requestProtocol.split(' ')[1]
    const method = requestProtocol.split(' ')[0]

    // RPC 和特定 API 的路由保持不变
    if (/^\/solana\-rpc/i.test(path)) {
        return forwardToSolanaRpc(socket, bodyStr, headerLines)
    }

    if (/^\/jup_ag/i.test(path)) {
        return forwardTojup_ag(socket, bodyStr, headerLines)
    }

    if (/^\/silentpass\-rpc/i.test(path)) {
        return forwardToSilentpass(socket, bodyStr, headerLines)
    }

    // **关键修正**: 处理所有 GET 请求
    if (method === 'GET') {
        // 不再需要检查 path === '/'。
        // 任何未被上面规则捕获的 GET 请求都应被转发。
        // forwardToHome 函数会使用请求中正确的 path (例如 /_next/static/css/...).
        return forwardToHome(socket, bodyStr, headerLines)
    }

    // 处理 POST 请求的逻辑
    if (method === 'POST') {
        let body: { data?: string }
        try {
            body = JSON.parse(bodyStr)
        } catch (ex) {
            console.log(`JSON.parse Ex ERROR! ${socket.remoteAddressShow }\n distorySocket request = ${requestProtocol}`, inspect({ request: bodyStr, addr: socket.remoteAddressShow, header  }, false, 3, true))
            return distorySocket(socket)
        }

        if (!body?.data || typeof body.data !== 'string') {
            logger(Colors.magenta(`startServer HTML body is not string error! ${socket.remoteAddressShow}`))
            logger(inspect(body, false, 3, true))
            return distorySocket(socket)
        }
		//console.log(`postOpenpgpRouteSocket from ${socket.remoteAddress}\n`, inspect({ request: bodyStr, addr: socket.remoteAddress }, false, 3, true))
        return postOpenpgpRouteSocket(socket, headerLines, body.data, conet_si_server.initData.pgpKeyObj.privateKeyObj, conet_si_server.publicKeyID, conet_si_server.nodeWallet)
    }

    // 对于其他方法 (PUT, DELETE, etc.) 或无法识别的请求，关闭连接
    //logger(Colors.yellow(`[WARN] Unhandled method '${method}' for path '${path}'. Closing connection.`))
    return distorySocket(socket)
}


// 支持的 Origin 白名单（可以改为从配置文件读取）
const originWhitelist = [
	/^https?:\/\/([a-zA-Z0-9-]+\.)?openpgp\.online(:\d+)?$/,
	/^https?:\/\/([a-zA-Z0-9-]+\.)?conet\.network(:\d+)?$/,
	/^https?:\/\/([a-zA-Z0-9-]+\.)?silentpass\.io(:\d+)?$/,
	/^local\-first:\/\/localhost(:\d+)?$/,
	/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/
]

const responseOPTIONS = (socket: Socket, requestHeaders: string[]) => {
	const originHeader = requestHeaders.find(h => h.toLowerCase().startsWith('origin:'));
	const rawOrigin = originHeader ? originHeader.slice(originHeader.indexOf(':') + 1).trim() : '*'

	// 检查 origin 是否在白名单中
	const isAllowed = originWhitelist.some(pattern => pattern.test(rawOrigin));
	const allowOrigin = isAllowed ? rawOrigin : 'null'; // or set to '*' only if no credentials used

	console.log(`[CORS] OPTIONS request from Origin: ${rawOrigin} => allowed: ${isAllowed}`)

	const response = [
		'HTTP/1.1 204 No Content',
		`Access-Control-Allow-Origin: ${allowOrigin}`,
		'Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE, PATCH',
		'Access-Control-Allow-Headers: solana-client, DNT, X-CustomHeader, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Content-Type',
		'Access-Control-Max-Age: 86400',
		'Content-Length: 0',
		'Connection: keep-alive',
		'',
		''
	].join('\r\n')
	console.log(response)
	socket.write(response)
}

const socketData = (socket: Socket, server: conet_si_server) => {
    let buffer = Buffer.alloc(0); // 在监听器外部定义一个缓冲区，用于拼接不完整的数据包
    let handledOptions = false; // 状态标记，标识是否处理过OPTIONS

    const remoteAddress = socket.remoteAddress?.split(':')
    const ip = remoteAddress ? remoteAddress[remoteAddress.length-1] : ''
    socket.remoteAddressShow = ip


    // 使用 .on 来持续监听数据，而不是 .once
    socket.on('data', (chunk: Buffer) => {
        buffer = Buffer.concat([buffer, chunk])

        
        const peek = buffer.subarray(0, Math.min(buffer.length, 2048)).toString('ascii')
        const separator = '\r\n\r\n'

        if (!handledOptions && peek.startsWith('OPTIONS')) {
            const end = peek.indexOf(separator)
            if (end !== -1) {
                const requestText = peek.substring(0, end)
                const lines = requestText.split('\r\n').filter(Boolean)
                responseOPTIONS(socket, lines)
                // 真正从 Buffer 中剥离已处理部分
                buffer = buffer.subarray(end + separator.length)
                handledOptions = true
            }
        }

        // 识别 POST/GET 起始
        const headStr = buffer.subarray(0, Math.min(buffer.length, 2048)).toString('ascii').trim()
        
        if (headStr.length > 0 && (headStr.startsWith('POST') || headStr.startsWith('GET'))) {
            socket.removeAllListeners('data')
            // 直接把当前 Buffer 交给 getDataPOST（它会继续按 Buffer 读取）
            return getDataPOST(socket, server, buffer)
        }
       
        return distorySocket(socket)
    })


}


const totalCOnnect = (server: Server ): Promise<number> => new Promise( executor => {
    server.getConnections((err, count) => {
        if (err) {
            return executor (0)
        }
        return executor (count)
    })
})


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

		if ( !this.initData?.keychain || this.initData?.passwd === undefined) {
            logger ('initData?.keychain = ',this.initData?.keychain,'initData.passwd = ', this.initData?.passwd)
			throw new Error (`Error: have no setup data!\nPlease restart CoNET-SI with node dist/cli start!`)
		}

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
		startEPOCH_EventListeningForMining(this.nodeWallet, this.publicKeyID, this.nodeIpAddr)
	}

	constructor () {
        this.initSetupData ()
    }
    
	private startServer = () => {
		
		const server = createServer( async socket => {
            const start = Date.now()
            logger(`startServer total connect =**************************  ${await totalCOnnect(server)} `)
            socket.setNoDelay(true)
            
			socket.on('error', (err: any) => {
				// 專門處理 ECONNRESET 錯誤
				if (err.code === 'ECONNRESET') {
					// 這種錯誤很常見，通常表示客戶端非正常關閉了連線。
					console.warn(`[${socket.remoteAddressShow}] 發生 ECONNRESET 錯誤，客戶端可能已強制關閉。這是可預期的。`);
				} else {
					// 其他類型的錯誤
					console.error(`[${socket.remoteAddress}] 發生未預期的 socket 錯誤:`, err)
				}
				
				// 不需要手動銷毀 socket，因為發生錯誤後，'close' 事件會自動被觸發。
			})

			socket.on('end', async () => {
                const duration = Date.now() - start
				logger(`startServer socket.on('end') total connect = ************************** ${await totalCOnnect(server)} keep time = ${duration}`)
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


		
		const server = createServerSSL (options, async socket => {
            logger(`createServerSSL total connect =  **************************  ${await totalCOnnect(server)} `)
            const start = Date.now()
            socket.setNoDelay(true)
			socket.on('error', (err: any) => {
				// 專門處理 ECONNRESET 錯誤
				if (err.code === 'ECONNRESET') {
					// 這種錯誤很常見，通常表示客戶端非正常關閉了連線。
					console.warn(`[${socket.remoteAddressShow}] 發生 ECONNRESET 錯誤，客戶端可能已強制關閉。這是可預期的。`);
                    
				} else {
					// 其他類型的錯誤
					console.error(`[${socket.remoteAddressShow}] 發生未預期的 socket 錯誤:`, err)
				}
				
				// 不需要手動銷毀 socket，因為發生錯誤後，'close' 事件會自動被觸發。
			})

			socket.on('end', async () => {
                const duration = Date.now() - start
				logger(`createServerSSL socket.on('end') total connect = ************************** ${await totalCOnnect(server)} keep time = ${duration}`)
				
			})
            
			return socketData( socket, this)
		})

		server.listen(443, () => {
		
			
			return console.table([
                { 'CoNET SI SSL server started': `version ${version} startup success Url http://localhost:443 doamin name = ${this.publicKeyID}.conet.network wallet = ${this.nodeWallet?.address}` }
            ])
		})

	}
}

export default conet_si_server