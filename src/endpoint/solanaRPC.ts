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
const appHost = (host: string) => {
	switch (host.toLowerCase()) {
		default:
		case androidUrl: {
			return androidUrl
		}
		case iOSUrl: {
			return iOSUrl
		}
	}
}
const solanaRPCURL = `https://${solanaRPC_host}`

const indexHtmlFileName = join(`${__dirname}`, 'index.html')

//		curl -v -i -X OPTIONS https://solana-rpc.conet.network/
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

export const forwardToSolana = (socket: Net.Socket, body: string, requestHanders: string[]) => {
	const method = requestHanders[0].split(' ')
	const path = method[1]
	logger(`forwardToSolana path = ${path}`)
	logger(inspect(requestHanders, false, 3, true))

	if (/^OPTIONS/i.test(method[0]) ) {
		
		return responseOPTIONS(socket, requestHanders)
	}

	
	let Upgrade = false
	const rehandles = getHeaderJSON(requestHanders.slice(1))
	if (/^Upgrade/i.test(method[0])) {
		Upgrade = true
		socket.setTimeout(0)
		socket.setNoDelay(true)
		socket.setKeepAlive(true, 0)
	}
	
	const option: Https.RequestOptions = {
		host: solanaRPC_host,
		port: 443,
		path: '/',
		method: method[0],
		headers: rehandles
	}

	logger(Colors.magenta(`getHeaderJSON! Upgrade = ${Upgrade} `))
	logger(inspect(option, false, 3, true))

	let responseHeader = ''

	const req = Https.request(option, res => {
		
		if (!Upgrade) {
			res.pipe(socket)
		}

		let _responseHeader = Upgrade ? createHttpHeader('HTTP/' + res.httpVersion + ' ' + res.statusCode + ' ' + res.statusMessage, res.headers) : !responseHeader ? getResponseHeaders(requestHanders) : ''

		for (let i = 0; i < res.rawHeaders.length; i += 2) {
			const key = res.rawHeaders[i]
			const value = res.rawHeaders[i+1]
			if (!/^Access|^date|^allow|^content\-type/i.test(key)) {
				_responseHeader += `${key}: ${value}\r\n`
			}
		}

		socket.write(_responseHeader + '\r\n')
		logger(`const req = Https.request(option, res => socket.write(responseHeader + '\r\n')`, inspect(responseHeader, false, 3, true))
		
		res.on('data', chunk => {
			console.log(`on data chunk = ${chunk.toString()}`)
		})
		
		res.once ('end', () => {
			console.log(`on end chunk = close`)
			
		})

		res.once('error', () => {
			console.log(`on error chunk = close`)
			
		})

		
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
		
		if (!Upgrade) {
			res.pipe(socket)
		}

		let _responseHeader = Upgrade ? createHttpHeader('HTTP/' + res.httpVersion + ' ' + res.statusCode + ' ' + res.statusMessage, res.headers) : !responseHeader ? getResponseHeaders(requestHanders) : ''

		for (let i = 0; i < res.rawHeaders.length; i += 2) {
			const key = res.rawHeaders[i]
			const value = res.rawHeaders[i+1]
			if (!/^Access|^date|^allow|^content\-type/i.test(key)) {
				_responseHeader += `${key}: ${value}\r\n`
			}
		}

		socket.write(_responseHeader + '\r\n')
		logger(`const req = Https.request(option, res => socket.write(responseHeader + '\r\n')`, inspect(responseHeader, false, 3, true))
		
		res.on('data', chunk => {
			console.log(`on data chunk = ${chunk.toString()}`)
		})
		
		res.once ('end', () => {
			console.log(`on end chunk = close`)
			
		})

		res.once('error', () => {
			console.log(`on error chunk = close`)
			
		})

		
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
				return forwardToSolana (socket, request_line[1], htmlHeaders)
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

// startServer(4000, 'pppp')