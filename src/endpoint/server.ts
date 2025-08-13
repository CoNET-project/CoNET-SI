
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


/**
 * @description 修正后的服务器主处理函数。
 * 主要修改了 GET 请求的路由逻辑。
 */
export const getDataPOST = async (socket: Socket, conet_si_server: conet_si_server, chunk: Buffer) => {
    
    const getMoreData = (data: string): Promise<string> => {
        return new Promise((resolve) => {
            const tryResolve = () => {
                const sepIndex = data.indexOf('\r\n\r\n')
                if (sepIndex < 0) return false

                const headerPart = data.slice(0, sepIndex)
                const bodyPart = data.slice(sepIndex + 4)

                const m = headerPart.match(/Content-Length:\s*(\d+)/i)
                const contentLength = m ? parseInt(m[1], 10) : 0

                if (bodyPart.length < contentLength) return false

                const full = headerPart + '\r\n\r\n' + bodyPart.slice(0, contentLength)
                resolve(full)
                return true
            }

            if (tryResolve()) return;

            socket.once('data', newChunk => {
                data += newChunk.toString()
                getMoreData(data).then(resolve)
            })
        })
    }

    if (!conet_si_server.initData?.pgpKeyObj?.privateKeyObj) {
        logger(Colors.red(`this.initData?.pgpKeyObj?.privateKeyObj NULL ERROR \n`), inspect(conet_si_server.initData, false, 3, true), '\n');
        return distorySocket(socket)
    }

    const data = await getMoreData(chunk.toString())
    const requestParts = data.split('\r\n\r\n')
    const headerLines = requestParts[0].split('\r\n')
    const requestProtocol = headerLines[0]
    const path = requestProtocol.split(' ')[1]
    const method = requestProtocol.split(' ')[0]
    const bodyStr = requestParts[1] || ''

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
            console.log(`JSON.parse Ex ERROR! ${socket.remoteAddress}\n distorySocket request = ${requestParts[0]}`, inspect({ request: bodyStr, addr: socket.remoteAddress }, false, 3, true))
            return distorySocket(socket)
        }

        if (!body?.data || typeof body.data !== 'string') {
            logger(Colors.magenta(`startServer HTML body is not string error! ${socket.remoteAddress}`))
            logger(inspect(body, false, 3, true))
            return distorySocket(socket)
        }
		//console.log(`postOpenpgpRouteSocket from ${socket.remoteAddress}\n = ${requestParts[0]}`, inspect({ request: bodyStr, addr: socket.remoteAddress }, false, 3, true))
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
    let buffer = ''; // 在监听器外部定义一个缓冲区，用于拼接不完整的数据包
    let handledOptions = false; // 状态标记，标识是否处理过OPTIONS

    // 使用 .on 来持续监听数据，而不是 .once
    socket.on('data', (chunk: Buffer) => {
        buffer += chunk.toString(); // 将新收到的数据追加到缓冲区

        // 因为预检请求和实际请求是两个独立的HTTP请求，我们需要分别解析
        // 预检请求没有消息体，以 `\r\n\r\n` 结尾
        const separator = '\r\n\r\n';

        // 检查是否是 OPTIONS 请求（只在第一次检查）
        if (!handledOptions && buffer.startsWith('OPTIONS')) {
            const requestEndIndex = buffer.indexOf(separator);
            
            if (requestEndIndex !== -1) { // 找到了完整的 OPTIONS 请求头
                const requestText = buffer.substring(0, requestEndIndex);
                const lines = requestText.split('\r\n').filter(Boolean);
                
                console.log("[CORS] Handling OPTIONS request...");
                logger(inspect(lines, false, 3, true));

                // 发送 OPTIONS 响应，保持连接
                responseOPTIONS(socket, lines);
                
                // 从缓冲区中移除已处理的 OPTIONS 请求
                buffer = buffer.substring(requestEndIndex + separator.length);
                handledOptions = true; // 标记已处理，不再进入此逻辑

                // 注意：这里不做任何返回，让代码继续向下执行，
                // 因为 POST 请求的数据可能已经紧跟着在缓冲区里了。
            }
        }
        
        // 检查 POST/GET 请求 (在处理完 OPTIONS 或一开始就不是 OPTIONS 的情况下)
        // 确保缓冲区里有内容，并且是以 POST 或 GET 开头
        const trimmedBuffer = buffer.trim();
        if (trimmedBuffer.length > 0 && (trimmedBuffer.startsWith('POST') || trimmedBuffer.startsWith('GET'))) {
            // 此处，我们已经确认收到了POST/GET请求的开始部分
            // 我们可以直接把当前的socket和数据交给getDataPOST处理
            // getDataPOST内部有处理不完整包的逻辑，所以这是安全的
            
            // 关键：为了避免重复监听，要先移除当前的 'data' 监听器
            socket.removeAllListeners('data');
            
            // 然后调用你的POST处理器，并将当前已缓冲的数据作为初始数据块传给它
            getDataPOST(socket, server, Buffer.from(buffer));

        } else if (handledOptions && trimmedBuffer.length === 0) {
            // 如果处理完OPTIONS后缓冲区为空，则什么都不做，等待下一个 data 事件
        } else if (!handledOptions && buffer.length > 2000) { // 防止恶意请求撑爆内存
            distorySocket(socket);
        }
    });
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
		startEPOCH_EventListeningForMining(this.nodeWallet, this.publicKeyID, this.nodeIpAddr)
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

			socket.on('end', () => {
				console.log('Client disconnected.');
			});

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

			socket.on('end', () => {
				console.log('Client disconnected.');
			});

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

new conet_si_server()