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
         * 使用 'ws' 庫處理 WebSocket 代理 (推薦方式) *
         **************************************************/
        logger(Colors.magenta(`[WebSocket] 收到 WebSocket 升級請求`));
        
        const clientKey = headers['sec-websocket-key'];
        if (!clientKey) {
            logger(Colors.red('[WebSocket] 錯誤: 請求缺少 "sec-websocket-key" 頭。'));
            socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
            return;
        }

        // 【關鍵】: 使用客戶端請求的 path 來建構上游 WebSocket URL
        const upstreamWsUrl = `wss://${solanaRPC_host}/`;
        logger(Colors.cyan(`[WebSocket] 正在連接到上游伺服器: ${upstreamWsUrl}`));

        const forwardHeaders = {
            'Origin': headers['origin']
        };

        const upstreamSocket = new WebSocket(upstreamWsUrl, { headers: forwardHeaders });

        upstreamSocket.on('open', () => {
            logger(Colors.green(`[WebSocket] 已成功連接到上游: ${upstreamWsUrl}`));
            const acceptKey = Crypto.createHash('sha1').update(clientKey + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
            const responseHeaders = [
                'HTTP/1.1 101 Switching Protocols', 'Upgrade: websocket', 'Connection: Upgrade', `Sec-WebSocket-Accept: ${acceptKey}`
            ];
            socket.write(responseHeaders.join('\r\n') + '\r\n\r\n');
            logger(Colors.green('[WebSocket] 與客戶端握手成功，開始代理數據...'));

            // 【修正】: 建立兩個獨立的管道來雙向轉發數據
            // 客戶端 -> 上游
            socket.on('data', data => { if (upstreamSocket.readyState === WebSocket.OPEN) upstreamSocket.send(data); });
            // 上游 -> 客戶端
            upstreamSocket.on('message', message => { if (socket.writable) socket.write(message as Buffer); });
        });

        // 處理關閉和錯誤事件
        socket.on('close', () => { logger(Colors.yellow('[WebSocket] 客戶端連接已關閉。')); if (upstreamSocket.readyState < 2) upstreamSocket.close(); });
        upstreamSocket.on('close', (code, reason) => { logger(Colors.yellow(`[WebSocket] 上游連接 ${upstreamWsUrl} 已關閉。 Code: ${code}, Reason: ${reason.toString()}`)); if (socket.writable) socket.end(); });
        socket.on('error', err => { logger(Colors.red(`[WebSocket] 客戶端 Socket 錯誤: ${err.message}`)); if (upstreamSocket.readyState < 2) upstreamSocket.close(); });
        upstreamSocket.on('error', err => { logger(Colors.red(`[WebSocket] 上游 WebSocket 錯誤: ${err.message}`)); if (socket.writable) socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); });


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
            const originHeader = requestHanders.find(h => h.toLowerCase().startsWith('origin:'));
			const origin = originHeader ? originHeader.slice(originHeader.indexOf(':') + 1).trim() : '*';

			// 写入状态行
			let statusLine = `HTTP/${res.httpVersion} ${res.statusCode} ${res.statusMessage}\r\n`;
			

			// 写入原始响应头（去掉 Access-Control-* 和 Date 等）
			for (let i = 0; i < res.rawHeaders.length; i += 2) {
				const key = res.rawHeaders[i];
				const value = res.rawHeaders[i + 1];
				if (!/^(Access-Control-|Date|Allow)/i.test(key)) {
					statusLine += `${key}: ${value}\r\n`
				}
			}



			

			// 注入 CORS 响应头

			statusLine += `Access-Control-Allow-Origin: ${origin}\r\n`
			statusLine += 'Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n'
			statusLine += 'Access-Control-Allow-Headers: solana-client, DNT, X-CustomHeader, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Content-Type, Authorization\r\n'
			statusLine += 'Access-Control-Allow-Credentials: true\r\n'
			statusLine += '\r\n'

			
			socket.write(statusLine)

			console.log(statusLine)

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

const baseRPC = 'chain-proxy.wallet.coinbase.com'
let uuidv4
let baseHeaders: Record<string, string>
import("uuid").then(mod => {
    uuidv4 = mod.v4

    baseHeaders = {
        accept: 'application/json',
        'content-type': 'application/json',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9,ja;q=0.8,zh-CN;q=0.7,zh-TW;q=0.6,zh;q=0.5',
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
        'x-app-version': '3.133.0',
        'x-cb-device-id': uuidv4(),
        'x-cb-is-logged-in': 'true',
        'x-cb-pagekey': 'send',
        'x-cb-platform': 'extension',
        'x-cb-project-name': 'wallet_extension',
        'x-cb-session-uuid': uuidv4(),
        'x-cb-version-name': '3.133.0',
        'x-platform-name': 'extension',
        'x-release-stage': 'production',
        'x-wallet-user-id': '98630690',
        // 如需身份态就带上 cookie（注意隐私与时效）
        cookie: `cb_dm=${uuidv4()};...`,
        // 若需要伪装扩展来源（可能仍被服务端策略拦截）
        origin: 'chrome-extension://hnfanknocfeofbddgcijnmhnfnkdnaad',
    }
})




export const forwardToBaseRpc = (
    socket: Net.Socket,
    body: string,
    requestHanders: string[]
) => {
            // 解析请求行和请求头
    const requestLine = requestHanders[0].split(' ')
    const method = requestLine[0]

    // 检查是否是 WebSocket 升级请求
	//@ts-ignore

	const isWebSocketUpgradeindex = requestHanders.findIndex(n => /Upgrade:/i.test(n))
    
	logger(inspect(requestHanders, false, 3, true))
	console.log('forwardToBaseRpc \n\n\n')

    const options: Https.RequestOptions = {
        hostname: baseRPC,
        port: 443,
        path:'/?targetName=base',
        method,
        headers: {
            ...baseHeaders,
            Host: baseRPC
        }
    }

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
		logger(Colors.red(`forwardToBaseRpc [HTTP] 转发请求错误: ${err.message}`))
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

const host_jup_ag = 'lite-api.jup.ag'
export const forwardTojup_ag = (
    socket: Net.Socket,
    body: string,
    requestHanders: string[]
) => {
    // 解析请求行和请求头
    const requestLine = requestHanders[0].split(' ')
    const method = requestLine[0]
	const path = '/' + requestLine[1].split('jup_ag/')[1]||''
    const headers = getHeaderJSON(requestHanders.slice(1))

	/**************************************************
	 * 处理普通 HTTP/HTTPS 请求             *					https://lite-api.jup.ag/v6/quote?inputMint=Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB&outputMint=Bzr4aEQEXrk7k8mbZffrQ9VzX6V3PAH4LvWKXkKppump&amount=100000000&slippageBps=250&swapMode=ExactOut
	 **************************************************/
	logger(Colors.cyan(`forwardTojup_ag [HTTP] 转发标准 HTTP 请求到: ${path}`))
	
	const options: Https.RequestOptions = {
		host: host_jup_ag,
		port: 443,
		path: path,
		method: method,
		headers: {
			...headers, // 包含從客戶端轉發過來的、已過濾的頭
			'host': host_jup_ag // 手動設置正確的 Host 頭
		}
	}



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

/**
 * @description 修正后的请求转发函数。
 * 这个函数现在更健壮，并且只负责转发，不再处理读取 socket 的逻辑。
 * 它会正确设置 Host 头，并处理响应流。
 */
export const forwardToHome = (socket: Net.Socket, body: string, requestHanders: string[]) => {
    const method = requestHanders[0].split(' ')[0];
    const path = requestHanders[0].split(' ')[1] || '/';
    
    // 从原始请求头中解析出 headers 对象
    const rehandles = getHeaderJSON(requestHanders.slice(1));
    
    // **关键修正**: 强制设置 Host 头。目标服务器依赖这个头来正确路由请求。
    rehandles['Host'] = 'silentpass.io';
    // 移除一些代理时不应直接转发的 "hop-by-hop" 头
    delete rehandles['connection'];
    delete rehandles['proxy-connection'];

    const option: Https.RequestOptions = {
        host: 'silentpass.io',
        port: 443,
        path,
        method,
        headers: rehandles
    };

    logger(Colors.cyan(`[FORWARDING] ${method} ${path} to silentpass.io`));

    const req = Https.request(option, res => {
        // 成功从目标服务器收到响应

        // 1. 构建并发送状态行 (e.g., "HTTP/1.1 200 OK")
        const statusLine = `HTTP/${res.httpVersion} ${res.statusCode} ${res.statusMessage}\r\n`;
        socket.write(statusLine);
        
        // 2. 构建并发送所有响应头
        // 我们需要原样转发大部分头，但同样要处理 "hop-by-hop" 头
        for (const key in res.headers) {
            // 'connection' 和 'transfer-encoding' 是 hop-by-hop 的，不应由代理直接转发
            if (/^connection|transfer-encoding$/i.test(key)) {
                continue;
            }
            const value = res.headers[key];
            socket.write(`${key}: ${value}\r\n`);
        }
        
        // 为了简化，我们告诉客户端在响应结束后关闭连接
        socket.write('Connection: close\r\n');

        // 3. 发送头和主体之间的空行
        socket.write('\r\n');

        // 4. 使用 pipe 高效地将响应主体（如 HTML, CSS 文件内容）直接流式传输给客户端
        res.pipe(socket);
        
        res.on('error', (err) => {
            logger(Colors.red(`[ERROR] Response stream error from silentpass.io: ${err.message}`));
            socket.end();
        });
    });

    req.on('error', err => {
        // 请求无法发送到目标服务器（例如，DNS错误，连接被拒绝）
        logger(Colors.red(`[ERROR] Request failed to silentpass.io: ${err.message}`));
        if (!socket.destroyed) {
            // 向客户端发送一个 502 Bad Gateway 错误
            socket.write('HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n');
            socket.end('Proxy Error: Could not connect to the upstream server.');
        }
    });

    // 如果原始请求是 POST 或 PUT，它会有一个主体。我们需要将这个主体写入到转发请求中。
    if (body) {
        req.write(body);
    }

    // 结束请求，这会实际将其发送出去。
    req.end();
};

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

// startServer(4000, 'pppp')

