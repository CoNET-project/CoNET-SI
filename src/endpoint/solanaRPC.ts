import Net from 'node:net'
import { inspect, } from 'node:util'
import {logger} from '../util/logger'
import Tls from 'node:tls'
import Colors from 'colors/safe'
import  { distorySocket } from '../util/htmlResponse'
import Http2 from 'node:http2'
import {readFileSync} from 'node:fs'
import { join } from 'node:path'
import Https from 'node:https'
import Http from 'node:http'

//		curl -v -H -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0","id": 1,"method": "getBalance","params": ["mDisFS7gA9Ro8QZ9tmHhKa961Z48hHRv2jXqc231uTF"]}' https://api.mainnet-beta.solana.com
//		curl -v --http0.9 -H -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0","id": 1,"method": "getBalance","params": ["mDisFS7gA9Ro8QZ9tmHhKa961Z48hHRv2jXqc231uTF"]}' http://9977e9a45187dd80.conet.network/solana-rpc
//		curl -v --http0.9 -H -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0","id": 1,"method": "getBalance","params": ["mDisFS7gA9Ro8QZ9tmHhKa961Z48hHRv2jXqc231uTF"]}' http://127.0.0.1:4000/solana-rpc
//		curl -v -i -X OPTIONS https://api.mainnet-beta.solana.com

const iOSUrl = 'vpn9.conet.network'
const androidUrl = 'vpn4.silentpass.io'
const solanaRPC_host = 'api.mainnet-beta.solana.com'
const ios_test ='ios-test.silentpass.io'
const appHost = (host: string) => {
	switch (host.toLowerCase()) {
		
		case androidUrl: {
			return androidUrl
		}
		default:
		case ios_test: {
			return ios_test
		}
		case iOSUrl: {
			return iOSUrl
		}
	}
}
const solanaRPCURL = `https://${solanaRPC_host}`

const indexHtmlFileName = join(`${__dirname}`, 'index.html')

//		curl -v -i -X OPTIONS https://solana-rpc.conet.network/
// 輔助函數：處理 OPTIONS 預檢請求
const responseOPTIONS = (socket: Net.Socket, requestHanders: string[]) => {
    const originHeader = requestHanders.find(h => h.toLowerCase().startsWith('origin:'))
    const origin = originHeader ? originHeader.split(/: */, 2)[1] : '*'

    const response = [
        'HTTP/1.1 204 No Content',
        `Access-Control-Allow-Origin: ${origin}`,
        'Access-Control-Allow-Credentials: true',
        'Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS',
        'Access-Control-Allow-Headers: solana-client, DNT, X-CustomHeader, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Content-Type',
        'Content-Length: 0',
        'Connection: keep-alive',
        '\r\n'
    ].join('\r\n')

    socket.end(response)
}

const responseRootHomePage = (socket: Net.Socket| Tls.TLSSocket) => {
	const homepage = readFileSync(indexHtmlFileName, 'utf-8') + '\r\n\r\n'
	//	@ts-ignore
	const ret = `HTTP/1.1 200 OK\r\n` +
	`date: ${new Date().toUTCString()}\r\n` +
	`Server: nginx/1.24.0 (Ubuntu)\r\n` +
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

const getData = (socket: Net.Socket, request: string, requestProtocol: string) => {

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

}

/**
curl --include \
     --no-buffer \
     --header "Connection: Upgrade" \
     --header "Upgrade: websocket" \
     "https://api.mainnet-beta.solana.com"
 */

	//logger (Colors.magenta(`SERVER call postOpenpgpRouteSocket nodePool = [${ this.nodePool }]`))

const getResponseHeaders = ( _headers: string[]) => {
	const checkMac = _headers.findIndex(n => / AppleWebKit\//.test(n))
	const orgionIndex = _headers.findIndex(n => /^Origin\:\s*https*\:\/\//i.test(n))
	const orgion = checkMac < 0 ? '*': orgionIndex < 0 ? '*' : _headers[orgionIndex].split(/^Origin\: /i)[1]
	
	let headers = `HTTP/1.1 200\r\n`
	headers += `date: ${new Date().toUTCString()}\r\n`
	headers += `server: nginx/1.24.0 (Ubuntu)\r\n`
	headers += `content-type: application/json; charset=utf-8\r\n`
	headers += `vary: origin\r\n`
	headers += `vary: accept-encoding\r\n`
	headers += `access-control-allow-origin: ${orgion}\r\n`
	headers += `access-control-allow-credentials: true\r\n`
	headers += `access-control-allow-methods: GET,HEAD,PUT,PATCH,POST,DELETE\r\n`
	headers += `access-control-allow-headers: solana-client,DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type\r\n`
	logger(inspect(headers, false, 3, true))
	return headers
}


const getHeaderJSON = (requestHanders: string[]) => {
	let _ret = "{"
	requestHanders.forEach((n, index) => {
		const key = n.split(': ')
		
		if (key[0] !=='' && key[1] !== '' && !/(^Host|^Origin|^Referer|^Accept\-Encoding)/i.test(key[0])) {

			key[1] = key[1].replaceAll('"', '')
			_ret += `"${key[0]}": "${key[1]}"`
			if (index < requestHanders.length-1) {
				_ret += ','
			}
		}

	})
	if (_ret[_ret.length - 1] === ',') {
		_ret = _ret.slice(0, _ret.length-1)
	}
	_ret += "}"
	let ret = {}
	try {
		ret = JSON.parse(_ret)
	} catch (ex: any) {
		logger(Colors.red(`getHeaderJSON JSON parse Error`))
		logger(inspect(_ret, false, 3, true))
	}
	return ret
	
}

var createHttpHeader = (line: string, headers: Http.IncomingHttpHeaders) => {
	return Object.keys(headers).reduce(function (head, key) {
	  var value = headers[key]
	  if (/Access-Control-Allow-Origin/i.test(key)) {
		head.push(key + ': *')
		return head
	}
	  if (!Array.isArray(value)) {
		head.push(key + ': ' + value)
		return head
	  }

	  for (var i = 0; i < value.length; i++) {
		
		head.push(key + ': ' + value[i])
	  }
	  return head
	}, [line])
	.join('\r\n') + '\r\n\r\n'
}


// 輔助函數：將 header 陣列轉換為 Node.js 需要的物件格式
function parseHeaders(requestHeaders: string[]): Record<string, string> {
    const headers: Record<string, string> = {}
    for (let i = 1; i < requestHeaders.length; i++) {
        const line = requestHeaders[i];
        const separatorIndex = line.indexOf(':')
        if (separatorIndex > 0) {
            const key = line.substring(0, separatorIndex).trim()
            const value = line.substring(separatorIndex + 1).trim()
            headers[key.toLowerCase()] = value
        }
    }
    return headers
}

/**
 * 將客戶端請求代理轉發到指定的 Solana RPC 主機。
 * 完整處理標準 HTTPS 請求（含 CORS 修改）和 WebSocket (WSS) 升級請求。
 *
 * @param socket 客戶端的 net.Socket 連接。
 * @param body 初始請求中可能包含的 body 數據。
 * @param requestHanders 原始的 HTTP 請求頭陣列。
 * @param solanaRpcHost 要轉發到的 Solana RPC 主機名。
 */
export const forwardToSolanaRpc = (
    socket: Net.Socket,
    body: string,
    requestHanders: string[],
    solanaRpcHost = solanaRPC_host
) => {
    const [method, path] = requestHanders[0].split(' ')
    const headers = parseHeaders(requestHanders)

    if (method === 'OPTIONS') {
        console.log('[Proxy] Handling pre-flight OPTIONS request.')
        return responseOPTIONS(socket, requestHanders)
    }
    
    const clientOrigin = headers['origin'] || '*'
    const isUpgradeRequest = headers['upgrade']?.toLowerCase() === 'websocket'

    const options: Https.RequestOptions = {
        hostname: solanaRpcHost,
        port: 443,
        path,
        method,
        headers: {
            ...headers,
            'host': solanaRpcHost,
        },
    }

    const proxyReq = Https.request(options)

    proxyReq.on('error', (err) => {
        console.error(`[Proxy] Error connecting to ${solanaRpcHost}:`, err)
        if (!socket.destroyed) {
            socket.write(`HTTP/1.1 502 Bad Gateway\r\n\r\n`)
            socket.end()
        }
    })

    // ========================================================================
    // --- 開始填充 if/else 區塊 ---
    // ========================================================================

    if (isUpgradeRequest) {
        // --- 處理 WebSocket 升級請求 ---
        console.log(`[Proxy] Handling WebSocket Upgrade request for ${path}`)

        // 監聽來自 Solana RPC 的 'upgrade' 成功事件
        proxyReq.on('upgrade', (proxyRes, targetSocket, head) => {
            console.log(`[Proxy] Successfully upgraded to WebSocket with ${solanaRpcHost}`)
            
            // 檢查客戶端 socket 是否仍然存活，防止在已關閉的 socket 上寫入
            if (socket.destroyed) {
                targetSocket.destroy()
                return
            }

            // 手動回覆客戶端 101 Switching Protocols 響應，完成握手
            const responseHeaders = [
                'HTTP/1.1 101 Switching Protocols',
                // 從 Solana RPC 的響應中獲取所有升級所需的標頭
                ...Object.entries(proxyRes.headers).map(([key, value]) => `${key}: ${value}`)
            ]
            
            socket.write(responseHeaders.join('\r\n') + '\r\n\r\n');

            // 建立雙向數據隧道：客戶端 <==> Solana RPC
            // 這是 WebSocket 代理的核心，數據將在兩個 socket 之間自由流動
            socket.pipe(targetSocket).pipe(socket)

            // 如果從目標伺服器收到了升級後的初始數據，立即轉發給客戶端
            if (head && head.length > 0) {
                targetSocket.write(head)
            }

            // 監聽錯誤並清理資源。任何一方斷開，另一方也應立即斷開。
            const cleanup = (source: string) => (err?: Error) => {
                if (err) console.error(`[Proxy] WebSocket error on ${source} side:`, err.message);
                if (!socket.destroyed) socket.destroy()
                if (!targetSocket.destroyed) targetSocket.destroy()
            }

            socket.on('error', cleanup('client'))
            socket.on('close', cleanup('client'))
            targetSocket.on('error', cleanup('target'))
            targetSocket.on('close', cleanup('target'))
        })

        // 對於升級請求，我們不需要發送 body，只需結束請求以觸發 'upgrade' 事件
        proxyReq.end()

    } else {
        // --- 處理標準 HTTP/HTTPS 請求 ---
        console.log(`[Proxy] Handling standard HTTP request for ${path}`)

        // 監聽來自 Solana RPC 的響應
        proxyReq.on('response', (proxyRes) => {
            console.log(`[Proxy] Intercepting response from Solana: ${proxyRes.statusCode}`)

            if (socket.destroyed) {
                return
            }
            
            // 1. 寫入狀態行
            socket.write(`HTTP/${proxyRes.httpVersion} ${proxyRes.statusCode} ${proxyRes.statusMessage}\r\n`)

            // 2. 過濾並注入 CORS 標頭
            // 需要過濾掉的原始標頭，以避免衝突
            const keysToFilter = [
                'access-control-allow-origin',
                'access-control-allow-methods',
                'access-control-allow-headers',
                'access-control-allow-credentials',
                'connection', // 由 Node.js 和代理邏輯管理
                'transfer-encoding' // 體數據將被直接 pipe，這個頭可能不適用
            ]

            for (let i = 0; i < proxyRes.rawHeaders.length; i += 2) {
                const key = proxyRes.rawHeaders[i].toLowerCase()
                const value = proxyRes.rawHeaders[i + 1]
                if (!keysToFilter.includes(key)) {
                    socket.write(`${proxyRes.rawHeaders[i]}: ${value}\r\n`)
                }
            }

            // 注入我們自定義的、寬鬆的 CORS 標頭
            socket.write(`Access-Control-Allow-Origin: ${clientOrigin}\r\n`)
            socket.write(`Access-Control-Allow-Credentials: true\r\n`)
            
            // 3. 標頭結束
            socket.write('\r\n')

            // 4. 將響應主體（body）通過管道高效地傳輸給客戶端
            proxyRes.pipe(socket)

            proxyRes.on('error', (err) => {
                console.error('[Proxy] Error on response stream from target:', err)
                socket.destroy()
            })
        })

        // 將客戶端的請求體轉發到 Solana RPC
        // 這一步確保了像 POST 這樣有較大請求體的請求能被完整轉發
        if (body && body.length > 0) {
            proxyReq.write(body)
        }
        
        // 將客戶端後續的數據流也 pipe 到代理請求中。
        // 對於 GET 請求，這一步不會執行任何操作。
        // 對於 POST 請求，它會轉發所有剩餘的請求體數據。
        // 當客戶端 socket 結束時，它會自動觸發 proxyReq.end()。
        socket.pipe(proxyReq)

        socket.on('error', (err) => {
            console.error('[Proxy] Error on client request stream:', err)
            proxyReq.destroy()
        })
    }
}



const getHeader = (requestHanders: string[], key: string) => {
	const keyLow = key.toLowerCase()
	let ret = ''
	requestHanders.forEach(n => {
		const keys = n.split(': ')
		if (keys[0].toLowerCase() == keyLow) {
			ret = keys[1]
		}
	})
	return ret
}

export const forwardToSilentpass = (socket: Net.Socket, body: string, requestHanders: string[]) => {


	const method = requestHanders[0].split(' ')[0]
	const path = requestHanders[0].split(' ')[1].split(/\/silentpass\-rpc/i)[1]||'/'
	const origin = appHost(getHeader(requestHanders, 'Origin'))
	
	logger(`forwardToSilentpass ${requestHanders[0]} ${origin}`)
	logger(inspect(requestHanders, false, 3, true))
	forwardToSolanaRpc(socket, body, requestHanders, origin)
	
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


const startServer = (port: number, publicKey: string) => {
		
	const server = Net.createServer( socket => {

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
						
						return getData (socket, request, requestProtocol)
					})
				}

				if (request_line[1].length < bodyLength) {
					return readMore ()
				}

				return getData (socket, request, requestProtocol)
				
			}

			if (/^GET \/ HTTP\//.test(requestProtocol)) {
				logger ('^GET',inspect(htmlHeaders, false, 3, true))
				return responseRootHomePage(socket)
			}

			if (/^OPTIONS \/ HTTP\//.test(requestProtocol)) {
				logger ('^OPTIONS',inspect(htmlHeaders, false, 3, true))
				return responseOPTIONS(socket, htmlHeaders)
			}

			const path = requestProtocol.split(' ')[1]
			if (/\/solana\-rpc/i.test(path)) {
				return forwardToSolanaRpc (socket, request_line[1], htmlHeaders)
			}

			if (/\/silentpass\-rpc/i.test(path)) {
				return forwardToSilentpass (socket, request_line[1], htmlHeaders)
			}
			logger ('unknow request!',inspect(htmlHeaders, false, 3, true))
			return distorySocket(socket)
		})

	})

	server.on('error', err => {
		logger(Colors.red(`conet_si_server server on Error! ${err.message}`))
	})

	server.listen ( port, () => {
		logger(Colors.blue(`__dirname = ${__dirname}`))
		
		return console.table([
			{ 'CoNET SI node': `Layer Minus Node start success! Url https://${publicKey}.conet.network` }
		])
	})
}


// const k = 'GET /solana-rpc HTTP/1.1\r\n' +
//     'Host: 9977e9a45187dd80.conet.network\r\n' +
//     'Connection: Upgrade\r\n' +
//     'Pragma: no-cache\r\n' +
//     'Cache-Control: no-cache\r\n' +
//     'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36\r\n' +
//     'Upgrade: websocket\r\n' +
//     'Origin: http://localhost:3000\r\n' +
//     'Sec-WebSocket-Version: 13\r\n' +
//     'Accept-Encoding: gzip, deflate\r\n' +
//     'Accept-Language: en-US,en;q=0.9,ja;q=0.8,zh-CN;q=0.7,zh-TW;q=0.6,zh;q=0.5\r\n' +
//     'Sec-WebSocket-Key: KYwY6NBeaSzpQZxJe3fUyA==\r\n' +
//     'Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n'

// logger(inspect(getHeaderJSON(k.split('\r\n').slice(1)), false, 3, true))

startServer(4000, 'pppp')

