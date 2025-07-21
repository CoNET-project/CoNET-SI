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
import WebSocket from 'ws'
import Crypto from 'node:crypto'

//		curl -v -H -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0","id": 1,"method": "getBalance","params": ["mDisFS7gA9Ro8QZ9tmHhKa961Z48hHRv2jXqc231uTF"]}' https://api.mainnet-beta.solana.com
//		curl -v --http0.9 -H -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0","id": 1,"method": "getBalance","params": ["mDisFS7gA9Ro8QZ9tmHhKa961Z48hHRv2jXqc231uTF"]}' http://9977e9a45187dd80.conet.network/solana-rpc
//		curl -v --http0.9 -H -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0","id": 1,"method": "getBalance","params": ["mDisFS7gA9Ro8QZ9tmHhKa961Z48hHRv2jXqc231uTF"]}' http://127.0.0.1:4000/solana-rpc
//		curl -v -i -X OPTIONS https://api.mainnet-beta.solana.com

const iOSUrl = 'vpn9.conet.network'
const iOSVPN = 'ios-vpn.silentpass.io'
const testVPN = 'vpn-beta.conet.network'
const solanaRPC_host = 'api.mainnet-beta.solana.com'
const ios_test ='ios-test.silentpass.io'
const appHost = (host: string) => {
	switch (host.toLowerCase()) {
		case 'sp-test': {
			return testVPN
		}
		case 'sp-ios': {
			return iOSVPN
		}
		default:
		case ios_test: {
			return ios_test
		}
	}
}
const solanaRPCURL = `https://${solanaRPC_host}`

const indexHtmlFileName = join(`${__dirname}`, 'index.html')

//		curl -v -i -X OPTIONS https://solana-rpc.conet.network/
// 輔助函數：處理 OPTIONS 預檢請求
const responseOPTIONS = (socket: Net.Socket, headers: string[]) => {
	const checkMac = headers.findIndex(n => / AppleWebKit\//.test(n))
	const orgionIndex = headers.findIndex(n => /^Origin\:\s*https*\:\/\//i.test(n))
	const orgion = checkMac < 0 ? '*': orgionIndex < 0 ? '*' : headers[orgionIndex].split(/^Origin\: /i)[1]

	let response = `HTTP/1.1 204 no content\r\n`
		// response += `date: ${new Date().toUTCString()}\r\n`
		// response += `server: nginx/1.24.0 (Ubuntu)\r\n`
		// response += `Connection: keep-alive\r\n`
		response += `access-control-allow-origin: ${orgion}\r\n`
		//response += `access-control-allow-headers: content-type\r\n`
		// response += `vary: Access-Control-Request-Headers\r\n`
		response += `access-control-allow-methods: GET,HEAD,PUT,PATCH,POST,DELETE\r\n`
		response += `access-control-allow-credentials: true\r\n`
		response += `access-control-allow-headers: solana-client,DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type\r\n`
		response += `content-length: 0\r\n\r\n`

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


/**
 * 解析原始 HTTP 標頭陣列，過濾掉特定標頭，並將剩餘標頭的鍵轉換為小寫。
 * @param requestHeaders - 從 socket 收到的原始標頭字串陣列。
 * @returns 一個鍵值對物件，其中所有鍵均為小寫。
 */
const getHeaderJSON = (requestHeaders: string[]): { [key: string]: string } => {
    const headers: { [key: string]: string } = {}
    const filterRegex = /^(host|origin|referer|accept-encoding)$/i

    requestHeaders.forEach(line => {
        const separatorIndex = line.indexOf(':')
        if (separatorIndex > 0) {
            const key = line.substring(0, separatorIndex).trim()
            const value = line.substring(separatorIndex + 1).trim()
            if (!filterRegex.test(key)) {
                headers[key.toLowerCase()] = value
            }
        }
    })
    return headers
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
 * 将请求转发到 Solana RPC，同时支持 HTTP 和 WebSocket 协议。
 * @param socket 客户端的原始 TCP socket 连接。
 * @param body 从客户端收到的初始请求体 (主要用于POST请求)。
 * @param requestHanders 原始的 HTTP 请求头数组。
 */
export const forwardToSolanaRpc = (
    socket: Net.Socket,
    body: string,
    requestHanders: string[]
) => {
    // 解析请求行和请求头
    const requestLine = requestHanders[0].split(' ')
    const method = requestLine[0]

    const headers = getHeaderJSON(requestHanders.slice(1))

    // 检查是否是 WebSocket 升级请求
	//@ts-ignore

	const isWebSocketUpgradeindex = requestHanders.findIndex(n => /Upgrade:/i.test(n))
    
	logger(inspect(requestHanders, false, 3, true))
	console.log('\n\n\n')

    if (isWebSocketUpgradeindex > -1) {
		socket.setTimeout(0)
		socket.setNoDelay(true)
		socket.setKeepAlive(true, 0)
        /**************************************************
         * 处理 WebSocket 升级请求             *
         **************************************************/
        logger(Colors.magenta(`[WebSocket] 收到 WebSocket 升级请求`))
		//@ts-ignore
        const clientKey = headers['sec-websocket-key'];
        if (!clientKey) {
            logger(Colors.red('[WebSocket] 错误: 请求缺少 "sec-websocket-key" 头。'))
            socket.end('HTTP/1.1 400 Bad Request\r\n\r\n')
            return
        }

        // 1. 构造到上游 Solana RPC WebSocket 服务的 URL
        const upstreamWsUrl = `wss://${solanaRPC_host}`
        logger(Colors.cyan(`[WebSocket] 正在连接到上游服务器: ${upstreamWsUrl}`))

        // 2. 创建一个 WebSocket 客户端实例，连接到 Solana
        const upstreamSocket = new WebSocket(upstreamWsUrl)

        // 3. 当与上游服务器的连接建立后，完成与客户端的握手
        upstreamSocket.on('open', () => {
            logger(Colors.green(`[WebSocket] 已成功连接到上游: ${upstreamWsUrl}`))

            // 计算 Sec-WebSocket-Accept 的值用于响应
            const acceptKey = Crypto
                .createHash('sha1')
                .update(clientKey + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
                .digest('base64')

            // 构造 101 Switching Protocols 响应
            const responseHeaders = [
                'HTTP/1.1 101 Switching Protocols',
                'Upgrade: websocket',
                'Connection: Upgrade',
                `Sec-WebSocket-Accept: ${acceptKey}`
            ];

            // 发送握手响应给客户端
            socket.write(responseHeaders.join('\r\n') + '\r\n\r\n')
            logger(Colors.green('[WebSocket] 与客户端握手成功，开始代理数据...'))

            // 4. 在两个连接之间双向代理数据
            // 从客户端接收数据 -> 发送到上游
            socket.on('data', data => {
                if (upstreamSocket.readyState === WebSocket.OPEN) {
                    upstreamSocket.send(data)
                }
            })

            // 从上游接收消息 -> 发送到客户端
            upstreamSocket.on('message', message => {
                if (socket.writable) {
					//@ts-ignore
                    socket.write(message)
                }
            })
        })

        // 5. 处理连接关闭
        socket.on('close', () => {
            logger(Colors.yellow('[WebSocket] 客户端连接已关闭。'))
            if (upstreamSocket.readyState === WebSocket.OPEN || upstreamSocket.readyState === WebSocket.CONNECTING) {
                upstreamSocket.close()
            }
        });

        upstreamSocket.on('close', () => {
            logger(Colors.yellow(`[WebSocket] 上游连接 ${upstreamWsUrl} 已关闭。`))
            if (socket.writable) {
                socket.end()
            }
        })

        // 6. 处理错误
        socket.on('error', err => {
            logger(Colors.red(`[WebSocket] 客户端 Socket 发生错误: ${err.message}`));
            if (upstreamSocket.readyState === WebSocket.OPEN || upstreamSocket.readyState === WebSocket.CONNECTING) {
                upstreamSocket.close()
            }
        })

        upstreamSocket.on('error', err => {
            logger(Colors.red(`[WebSocket] 上游 WebSocket 发生错误: ${err.message}`))
            if (socket.writable) {
                socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
            }
        })

    } else {
        /**************************************************
         * 处理普通 HTTP/HTTPS 请求             *
         **************************************************/
        // logger(Colors.cyan(`[HTTP] 转发标准 HTTP 请求到: ${path}`))
		
        const options: Https.RequestOptions = {
            host: solanaRPC_host,
            port: 443,
            path: '/',
            method: method,
            headers: {
                ...headers, // 包含從客戶端轉發過來的、已過濾的頭
                'host': solanaRPC_host // 手動設置正確的 Host 頭
            }
        }

		// logger(inspect(headers, false, 3, true))

        const req = Https.request(options, res => {
            // 将上游服务器的响应头和响应体转发给客户端，同时剥离限制性头
            // 构造状态行
            const statusLine = `HTTP/${res.httpVersion} ${res.statusCode} ${res.statusMessage}`;
            socket.write(statusLine + '\r\n');
			// logger(statusLine)
            // 构造并写入过滤后的响应头
            for (let i = 0; i < res.rawHeaders.length; i += 2) {
                const key = res.rawHeaders[i];
                const value = res.rawHeaders[i + 1];
                // 过滤掉可能包含客户端限制的头 (例如 CORS, Date, Allow)
                if (!/^(Access-Control-|Date|Allow)/i.test(key)) {
                    socket.write(`${key}: ${value}\r\n`);
                }
            }
            
            // 添加自定义的、更宽松的CORS头
            socket.write('Access-Control-Allow-Origin: *\r\n')
            socket.write('Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n')
            socket.write('Access-Control-Allow-Headers: Content-Type, Authorization\r\n')

            socket.write('\r\n');

            // 使用 pipe 将响应体直接流式传输给客户端
            res.pipe(socket);

            res.on('error', err => {
                logger(Colors.red(`[HTTP] 上游响应错误: ${err.message}`))
                if (socket.writable) {
                    socket.destroy()
                }
            })
        })

        req.on('error', err => {
            logger(Colors.red(`[HTTP] 转发请求错误: ${err.message}`))
            if (socket.writable) {
                socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
            }
        });

        // 如果有请求体 (例如 POST)，则写入请求体
        if (body) {
            req.write(body)
        }

        req.end()
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
	const origin = appHost(getHeader(requestHanders, 'Referer'))
	logger(`forwardToSilentpass ${requestHanders[0]}`)
	logger(inspect(requestHanders, false, 3, true))

	// if (/^OPTIONS/i.test(method) ) {
		
	// 	return responseOPTIONS(socket, requestHanders)
	// }

	
	let Upgrade = false
	const rehandles = getHeaderJSON(requestHanders.slice(1))
	if (/^Upgrade/i.test(method)) {
		Upgrade = true
		socket.setTimeout(0)
		socket.setNoDelay(true)
		socket.setKeepAlive(true, 0)
	}
	
	const option: Https.RequestOptions = {
		host: origin,
		port: 443,
		path,
		method,
		headers: rehandles
	}

	logger(Colors.magenta(`getHeaderJSON! Upgrade = ${Upgrade} `))
	logger(inspect(option, false, 3, true))

	let responseHeader = ''

	const req = Https.request(option, res => {
    
    // 对于非 WebSocket 请求 (文件下载属于此类)
    if (!Upgrade) {
        
        // 1. 先写入状态行和响应头。
        //    我们直接使用上游服务器返回的状态码、信息和头文件。
        //    res.headers 包含了所有必要的头，如 Content-Type, Content-Length 等。
        socket.write(`HTTP/${res.httpVersion} ${res.statusCode} ${res.statusMessage}\r\n`);
        
        // 将所有上游响应头原样转发给客户端
        for (const key in res.headers) {
            // res.headers[key] 的值可能是字符串或字符串数组
            const value = Array.isArray(res.headers[key]) 
                ? (res.headers[key] as string[]).join(', ') 
                : res.headers[key];
            socket.write(`${key}: ${value}\r\n`);
        }

        // 写入一个空行，表示头的结束
        socket.write('\r\n');

        // 2. 在所有头都发送完毕后，再使用 .pipe() 高效地传输响应体。
        //    Node.js 的流会自动处理 'data', 'end', 'error' 等事件。
        //    我们不再需要手写 res.on('data', ...) 和 res.on('end', ...)。
        res.pipe(socket);
        
        return; // 处理完毕，直接返回
    }

    // ... 处理 Upgrade (WebSocket) 的逻辑保留在这里 ...
    // 注意：原始代码中的 Upgrade 逻辑也有类似问题，这里暂时只修复非 Upgrade 的情况。
})

	req.on('error', err => {

	})

	req.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
		logger(`req.on('upgrade')`)
		logger(inspect(proxyRes.headers, false, 3, true))
		proxySocket.on('error', err => {
			logger(Colors.red(`proxySocket.on('error')`), err.message)
		})

		proxySocket.on('end', function () {
			logger(Colors.red(`proxySocket.on('end')`))
		})

		proxySocket.setTimeout(0)
		proxySocket.setNoDelay(true)
		proxySocket.setKeepAlive(true, 0)

		if (proxyHead && proxyHead.length) {
			proxySocket.unshift(proxyHead)
		}
		logger(inspect(proxyRes.headers, false, 3, true))
		const socketHandle = createHttpHeader('HTTP/1.1 101 Switching Protocols', proxyRes.headers)

		logger(inspect(socketHandle, false, 3, true))

		socket.write(socketHandle)
		
		proxySocket.pipe(socket).pipe(proxySocket)

	})

	req.once('end', () => {
		
	})


	if (body) {
		logger(`req.write body size = ${body.length}`)
		req.write(body)
		if (!Upgrade) {
			req.end()
		}
		return
	}

	if (/GET/.test(method)) {
		return req.end('\r\n')
	}

	responseHeader = getResponseHeaders(requestHanders)

	if (socket.writable) {
		socket.once ('data', data => {
			
			req.write(data)
			logger(`!body on body`, data.toString())
			if (!Upgrade) {
				logger(`req.end()`)
				req.end()
			}
		})
		socket.write(responseHeader)
	}
	
	
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

