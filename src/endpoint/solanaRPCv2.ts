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

/**
 * Updated getData function to work with the new server logic.
 * It now accepts the body directly, not the entire request.
 */
const getData = (socket: Net.Socket, bodyString: string, requestProtocol: string) => {
	logger(`Handling /post data for ${requestProtocol}`, `Body length: ${bodyString.length}`)
	let body
	try {
		body = JSON.parse(bodyString)
	} catch (ex) {
		logger(Colors.red('Failed to parse JSON body.'), bodyString)
		return distorySocket(socket)
	}

	if (!body.data || typeof body.data !== 'string') {
		logger(Colors.magenta('Validation failed: body.data is not a string!'), body);
		return distorySocket(socket)
	}

	// At this point, the body is valid JSON with a 'data' property.
	logger('Successfully processed valid data from /post request.')
	
	// Send a success response back to the client.
	socket.write('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n')
	socket.end(JSON.stringify({ status: 'received' }))
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
 * =============================================================================
 * Optimized RPC Forwarding Function
 * =============================================================================
 */

/**
 * Forwards a raw TCP socket connection to a specified Solana RPC host.
 * It handles both standard HTTPS requests and WebSocket (ws) upgrade requests.
 *
 * This function acts as a proxy, with the following key features:
 * - Forwards the client's request (headers and body) to the Solana RPC host.
 * - For WebSocket connections, it properly handles the 'Upgrade' handshake and establishes a
 * bidirectional pipe between the client and the RPC host.
 * - For all responses from the RPC host, it filters out headers that could interfere with
 * the client's security policy (e.g., Access-Control-*, Date, Allow).
 * - Implements robust error handling and resource cleanup to prevent socket leaks.
 *
 * @param clientSocket The incoming net.Socket from the client.
 * @param requestHeaders An array of raw request header strings.
 * @param initialBody The initial part of the request body, if it was received with the headers.
 * @param solanaRpcHost The hostname of the target Solana RPC server.
 */
export const forwardToSolanaRpc = (
	clientSocket: Net.Socket,
	requestHeaders: string[],
	initialBody: string,
	solanaRpcHost: string = solanaRPC_host
) => {
	// --- 1. Parse the initial client request ---
	const [requestLine, ...headerLines] = requestHeaders
	if (!requestLine) {
		logger("Error: Received empty request. Closing socket.")
		clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n')
		return
	}

	const [method, path] = requestLine.split(' ')
	const headers: { [key: string]: string } = headerLines.reduce((acc, line) => {
		const parts = line.split(': ')
		if (parts.length === 2) {
			acc[parts[0].toLowerCase()] = parts[1]
		}
		return acc
	}, {} as { [key: string]: string })

	const isUpgradeRequest = headers['upgrade']?.toLowerCase() === 'websocket'
	logger(`Forwarding request: ${method} ${path} (WebSocket: ${isUpgradeRequest})`)

	// --- 2. Configure the outgoing request to the Solana RPC host ---
	const requestOptions: Https.RequestOptions = {
		hostname: solanaRpcHost,
		port: 443,
		path: path,
		method: method,
		headers: headers,
	}

	// --- 3. Create the proxy request ---
	const proxyReq = Https.request(requestOptions)

	// --- 4. Set up error handling to prevent crashes and resource leaks ---
	const cleanup = () => {
		// Remove listeners to avoid them being called again
		clientSocket.removeAllListeners()
		proxyReq.removeAllListeners()
		// Ensure both sockets are destroyed
		clientSocket.destroy()
		proxyReq.destroy()
		logger("Cleaned up sockets and listeners.")
	}

	proxyReq.on('error', (err) => {
		logger("Error from Solana RPC host:", err.message)
		if (!clientSocket.destroyed) {
			clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
		}
		cleanup()
	})

	clientSocket.on('error', (err) => {
		logger("Error from client socket:", err.message)
		cleanup()
	})
	
	clientSocket.on('close', () => {
		logger("Client socket closed.")
		cleanup()
	})

	// --- 5. Handle the 'upgrade' event for WebSocket connections ---
	if (isUpgradeRequest) {
		// For WebSockets, we need to handle the 'upgrade' event specifically.
		proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
			logger("Received 'upgrade' response from Solana RPC host.")

			// Configure the proxy socket for long-lived connection
			proxySocket.setTimeout(0)
			proxySocket.setNoDelay(true)
			proxySocket.setKeepAlive(true, 0)

			// Forward the 101 Switching Protocols response to the client
			const responseHeaders = [
				'HTTP/1.1 101 Switching Protocols',
				...Object.entries(proxyRes.headers)
					.filter(([key]) => !/^access-control-|^date$|^allow$/i.test(key))
					.map(([key, value]) => `${key}: ${value}`)
			];

			clientSocket.write(responseHeaders.join('\r\n') + '\r\n\r\n')
			logger("Sent 101 Switching Protocols to client.")

			// Establish the bidirectional pipe
			proxySocket.pipe(clientSocket).pipe(proxySocket)

			// Handle any data that came with the upgrade request
			if (proxyHead && proxyHead.length) {
				proxySocket.write(proxyHead);
			}
			
			// Handle cleanup for the proxy socket
			proxySocket.on('error', (err) => {
				logger("Error on proxy WebSocket:", err.message)
				cleanup();
			});
			proxySocket.on('close', () => {
				logger("Proxy WebSocket closed.")
				cleanup()
			})
		})
	} else {
		// --- 6. Handle standard HTTPS responses ---
		proxyReq.on('response', (proxyRes) => {
			logger(`Received response from Solana RPC host: ${proxyRes.statusCode}`)

			// Filter headers before sending them to the client
			const filteredHeaders = Object.entries(proxyRes.headers)
				.filter(([key]) => !/^access-control-|^date$|^allow$/i.test(key))
				.map(([key, value]) => `${key}: ${value}`)

			const statusLine = `HTTP/${proxyRes.httpVersion} ${proxyRes.statusCode} ${proxyRes.statusMessage}`
			
			// Write the status line and filtered headers to the client
			clientSocket.write([statusLine, ...filteredHeaders].join('\r\n') + '\r\n\r\n')

			// Pipe the response body from the RPC host directly to the client
			proxyRes.pipe(clientSocket);

			proxyRes.on('error', (err) => {
				logger("Error on proxy response stream:", err.message)
				cleanup()
			})
		})
	}

	// --- 7. Write the initial body and pipe subsequent data from the client ---
	// This forwards the client's request body to the Solana RPC host.
	if (initialBody) {
		proxyReq.write(initialBody)
	}

	// For standard HTTP, we pipe the client socket to the proxy request.
	// For WebSockets, piping is handled after the 'upgrade' event.
	if (!isUpgradeRequest) {
		clientSocket.pipe(proxyReq)
	} else {
		// For Upgrade requests, we must call end() to finalize the request.
		proxyReq.end()
	}
};


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

const getLengthHander = (headers: string[]): number => {
	const lengthHeader = headers.find(h => h.toLowerCase().startsWith('content-length:'))
	if (lengthHeader) {
		return parseInt(lengthHeader.split(':')[1].trim(), 10) || 0
	}
	return 0
}


/**
 * =============================================================================
 * Refactored Server Implementation
 * =============================================================================
 */

export const startServer = (port: number, publicKey: string) => {
	const server = Net.createServer(socket => {
		let buffer = Buffer.alloc(0);

		const onData = (data: Buffer) => {
			buffer = Buffer.concat([buffer, data])
			const separatorIndex = buffer.indexOf('\r\n\r\n')

			// If we haven't found the end of the headers, wait for more data.
			if (separatorIndex === -1) {
				// To prevent buffer attacks, you might want to add a size limit here.
				if (buffer.length > 8192) { // 8KB header limit
					socket.end('HTTP/1.1 413 Payload Too Large\r\n\r\n')
					distorySocket(socket)
				}
				return
			}

			// Once we have the headers, we can stop listening with this handler
			// and pass control to the appropriate request handler.
			socket.removeListener('data', onData)

			// Separate the header block from the initial part of the body
			const headerBlock = buffer.subarray(0, separatorIndex).toString('utf8')
			const initialBody = buffer.subarray(separatorIndex + 4)

			// --- Start Routing ---
			const htmlHeaders = headerBlock.split('\r\n')
			const requestProtocol = htmlHeaders[0] || ''
			const [method, path] = requestProtocol.split(' ')

			logger(`Request received: ${method} ${path}`)

			// Route to Solana RPC
			if (path && /\/solana-rpc/i.test(path)) {
				// The forwarder function will now handle the socket, including the `initialBody`
				// and any subsequent data that arrives on the stream.
				return forwardToSolanaRpc(socket, htmlHeaders, initialBody.toString('utf8'))
			}

			// Route to Silentpass RPC
			if (path && /\/silentpass-rpc/i.test(path)) {
				// You would need a similar streaming handler for this or buffer the full body.
				// For now, we pass the initial body part.
				socket.unshift(initialBody); // Put the remaining buffer back into the stream
				return forwardToSilentpass(socket, initialBody.toString('utf8'), htmlHeaders)
			}
			
			// Route for GET /
			if (method === 'GET' && path === '/') {
				return responseRootHomePage(socket)
			}

			// Route for OPTIONS
			if (method === 'OPTIONS') {
				return responseOPTIONS(socket, htmlHeaders)
			}

			// Route for POST /post
			if (method === 'POST' && path === '/post') {
				const bodyLength = getLengthHander(htmlHeaders)
				let currentBody = initialBody;

				if (currentBody.length >= bodyLength) {
					// Full body was already in the first packet
					return getData(socket, currentBody.toString('utf8').slice(0, bodyLength), requestProtocol)
				}

				// If body is not complete, set up a listener for the rest
				const onBodyData = (moreData: Buffer) => {
					currentBody = Buffer.concat([currentBody, moreData])
					if (currentBody.length >= bodyLength) {
						socket.removeListener('data', onBodyData)
						getData(socket, currentBody.toString('utf8').slice(0, bodyLength), requestProtocol)
					}
				};
				socket.on('data', onBodyData)
				return
			}

			logger('Unknown request!', inspect(htmlHeaders, false, 3, true))
			return distorySocket(socket)
		}

		socket.on('data', onData)

		socket.on('error', err => {
			logger(Colors.red(`Socket error: ${err.message}`))
			distorySocket(socket)
		});

		socket.on('close', () => {
			logger('Socket closed.')
		})
	})

	server.on('error', err => {
		logger(Colors.red(`Server error! ${err.message}`))
	})

	server.listen(port, () => {
		logger(Colors.blue(`__dirname = ${__dirname}`))
		console.table([
			{ 'CoNET SI node': `Layer Minus Node started successfully! URL: https://${publicKey}.conet.network` }
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

// startServer(4000, 'pppp')

