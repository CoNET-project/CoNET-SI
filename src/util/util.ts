import { ethers } from 'ethers'
import {inspect} from 'node:util'
import cCNTPABI from './cCNTP.json'
import { logger } from './logger'
import Colors from 'colors/safe'
import {getAllNodeWallets} from './localNodeCommand'
import type { Socket } from 'node:net'
import {abi as GuardianNodesV2ABI} from './GuardianNodesV2.json'
import openPGPContractAbi from './GuardianNodesInfoV3.json'
import type {RequestOptions} from 'node:http'
import {request} from 'node:http'
import P from 'phin'
import { mapLimit } from 'async'
import {readKey, createMessage, enums, encrypt} from 'openpgp'
import { getServerIPV4Address } from './localNodeCommand'
import CoNETDePIN_PassportABI from './CoNETDePIN_Passport.json'
import { throws } from 'node:assert'
import passport_distributor_ABI from './passport_distributor-ABI.json'
import duplicateFactoryABI from './duplicateFactoryABI.json'
import newNodeInfoABI from './newNodeInfoABI.json'
import {distorySocket, response200Html, distorySocketPayment} from './htmlResponse'
import CoNET_PGP_ABI from './ABI/conetPgp.json'
import path from 'node:path'
import os from 'node:os'
import fs from 'node:fs'


export const CoNET_CancunRPC = 'https://cancun-rpc.conet.network'
export const CoNET_mainnet_RPC = 'https://mainnet-rpc.conet.network'
const ipfsEndpoint = `https://ipfs.conet.network/api/`

const CONETP_mainnet_rovider = new ethers.JsonRpcProvider(CoNET_mainnet_RPC)
const GuardianPlan_CancunAddr = '0x312c96DbcCF9aa277999b3a11b7ea6956DdF5c61'
const GuardianNodeInfo_CancunAddr = '0x88cBCc093344F2e1A6c2790A537574949D711E9d'
const GuardianNodeInfo_mainnet = '0x2DF3302d0c9aC19BE01Ee08ce3DDA841BdcF6F03'.toLowerCase()

const conet_PGP_address = '0x84de3EA6446489E6a267B0AAD2fAe1462564C32E'
const PGP_manager_readonly = new ethers.Contract(conet_PGP_address, CoNET_PGP_ABI, CONETP_mainnet_rovider)


let GlobalIpAddress = ''

export const routerInfo: Map<string, nodeInfo> = new Map()

let gossipNodes: nodeInfo[] = []

let getNodeInfoProssing = false

const CoNETDePIN_Passport_cancun_addr = '0xb889F14b557C2dB610f283055A988952953E0E94'
const CoNETDePIN_passport_distributor_mainnet_addr = '0x40d64D88A86D6efb721042225B812379dc97bc89'
const  CoNETDePIN_Passport_mainnet_addr = '0x054498c353452A6F29FcA5E7A0c4D13b2D77fF08'


const CoNETDePIN_PassportSC_mainnet_readonly = new ethers.Contract(CoNETDePIN_Passport_mainnet_addr, CoNETDePIN_PassportABI, CONETP_mainnet_rovider)
const CoNETDePIN_passport_distributor_mainnet_readonly = new ethers.Contract(CoNETDePIN_passport_distributor_mainnet_addr, passport_distributor_ABI, CONETP_mainnet_rovider)

const paymendUser: Map<string, boolean> = new Map()
const GuardianNodesMainnet = new ethers.Contract(GuardianNodeInfo_mainnet, newNodeInfoABI, CONETP_mainnet_rovider)

	//		_nftIDs, _expires, _expiresDays, _premium

const _checkNFT = (nft: any[], fromAddr: string) => {
	let _nftIDs: ethers.BigNumberish
	let _expires: ethers.BigNumberish
	let _expiresDays: ethers.BigNumberish
	let _premium: boolean
	[_nftIDs, _expires, _expiresDays, _premium] = nft
	logger(inspect(nft, false, 3, true))
	const today = parseFloat(new Date().getTime().toString())

	const expires =  parseFloat(_expires.toString()) * 1000			//		Convert to milliseconds

	if (!_nftIDs|| expires < today) {
		return false
	}
	paymendUser.set(fromAddr, true)
	return true
}
const duplicateFactory_addr = '0x87A70eD480a2b904c607Ee68e6C3f8c54D58FB08'
const duplicateFactory_readOnly = new ethers.Contract(duplicateFactory_addr, duplicateFactoryABI, CONETP_mainnet_rovider)


export const checkPayment = async(fromAddr: string) => {

	const pay = paymendUser.get(fromAddr)

	if (pay) {
		return true
	}

	try {
		const [cancun, mainnet] = await Promise.all([
			duplicateFactory_readOnly.getCurrentPassport(fromAddr),
			CoNETDePIN_passport_distributor_mainnet_readonly.getCurrentPassport(fromAddr)
		])
		//	check balance
		let balanceCancun = parseInt(cancun[0].toString())
		let balancemainnet = parseInt(mainnet[0].toString())
		logger(`cancun`, inspect(cancun))

		if (balanceCancun + balancemainnet > 0) {
			const [a1, a2] = await Promise.all([
				_checkNFT(cancun, fromAddr),
				_checkNFT(mainnet, fromAddr),
			])
	
			if (a1 || a2) {
				return true
			}
		}

	} catch (ex: any) {
		logger(Colors.red(`checkPayment CoNETDePIN_PassportSC_readonly.getCurrentPassport Error!, ${ex.message}`))
		return false
	}

	return false
	
}

export const putUserMiningToPaymendUser = (fromAddr: string) => {
	paymendUser.set(fromAddr, true)
}


let getAllNodesProcess = false
let Guardian_Nodes: nodeInfo[] = []


const _getAllNodes = (): Promise<any[]> => new Promise ( async executor => {

	let i = 0
	let nodes: any [] = []
	let loop = true
	const length = 100
	do {
		try {
            logger(`_getAllNodes LOOP from ${i} to ${i + length}`)
			const _nodes: any[] = await GuardianNodesMainnet.getAllNodes(i, length)
			
			if (_nodes.length < length || !_nodes) {
				loop = false
			}
			i += length
            
            nodes = [...nodes, ..._nodes]
		} catch (ex) {
			await new Promise(executor=> setTimeout(() => executor(true), 2000))
		}

	} while (loop)

	return executor(nodes)
	
})

let reScanAllWalletsProcess = false

export const reScanAllWallets = async () => {
    if (!routerInfo.size) {
        return logger(`reScanAllWallets Error! no DATA in routerInfo `)
    }
    if (reScanAllWalletsProcess) {
        return
    }

    reScanAllWalletsProcess = true
    const wallets = await getAllNodeWallets()

    if (!wallets) {
        reScanAllWalletsProcess = false
        return logger(`reScanAllWallets Error! getAllNodeWallets got NULL!`)
    }


    routerInfo.forEach((val, key) => {
        
        const index = wallets.findIndex(n => n.ipAddr === val.ipaddress)
        if ( index< 0) {
            logger(`reScanAllWallets Error! ********************* NODE ${val.ipaddress} have no wallet to find in API server! **************`)
            return
        }
        val.wallet = wallets[index].wallet
        routerInfo.set(key, val)
    })
    reScanAllWalletsProcess = false
    logger(`r********************* reScanAllWallets  SUCCESS!   **************`)


}

export const getAllNodes = () => new Promise(async resolve=> {
	
	if (getAllNodesProcess) {
		return resolve (true)
	}

    const wallets = await getAllNodeWallets()
    if (!wallets) {
        logger(`getAllNodes Error: getAllNodeWallets NULL!!`)
    }

	getAllNodesProcess = true


    const _node = await _getAllNodes()
	for (let i = 0; i < _node.length; i ++) {
		const node = _node[i]
		const id = parseInt(node[0].toString())
		const pgpString: string = Buffer.from( node[1], 'base64').toString()
		const domain: string = node[2]
		const ipAddr: string = node[3]
		const region: string = node[4]
        let wallet = ''
        if (wallets) {
            const index = wallets.findIndex(n => n.ipAddr === ipAddr)
            if (index > -1) {
                wallet = wallets[index].wallet
            }
        }
       
		const itemNode: nodeInfo = {
			ipaddress: ipAddr,
			pgpArmored: pgpString,
			domain: domain,
			nftNumber: id,
			regionName: region,
			pgpKeyID: domain,
			wallet
		}
		
		routerInfo.set(domain, itemNode)
        const index = Guardian_Nodes.findIndex(n => n.ipaddress === ipAddr)
        if (index) {
            Guardian_Nodes.splice(index, 1)
        }
		Guardian_Nodes.push(itemNode)
  	}
	
	getAllNodesProcess = false

    logger(Colors.red(`getAllNodes success! Guardian_Nodes = ${Guardian_Nodes.length} `))
	resolve(true)
})


export const aesGcmEncrypt = async (plaintext: string, password: string) => {
	const pwUtf8 = new TextEncoder().encode(password)                                 // encode password as UTF-8
	const pwHash = await crypto.subtle.digest('SHA-256', pwUtf8)                      // hash the password

	const iv = crypto.getRandomValues(new Uint8Array(12))                             // get 96-bit random iv
	const ivStr = Array.from(iv).map(b => String.fromCharCode(b)).join('')            // iv as utf-8 string

	const alg = { name: 'AES-GCM', iv: iv }                                           // specify algorithm to use

	const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['encrypt']) // generate key from pw

	const ptUint8 = new TextEncoder().encode(plaintext)                               // encode plaintext as UTF-8
	const ctBuffer = await crypto.subtle.encrypt(alg, key, ptUint8)                   // encrypt plaintext using key

	const ctArray = Array.from(new Uint8Array(ctBuffer))                              // ciphertext as byte array
	const ctStr = ctArray.map(byte => String.fromCharCode(byte)).join('')             // ciphertext as string

	return btoa(ivStr+ctStr)   
}

export const aesGcmDecrypt= async (ciphertext: string, password: string) => {
	const pwUtf8 = new TextEncoder().encode(password)                                 // encode password as UTF-8
	const pwHash = await crypto.subtle.digest('SHA-256', pwUtf8)                      // hash the password

	const ivStr = atob(ciphertext).slice(0,12)                                        // decode base64 iv
	const iv = new Uint8Array(Array.from(ivStr).map(ch => ch.charCodeAt(0)))          // iv as Uint8Array

	const alg = { name: 'AES-GCM', iv: iv }                                           // specify algorithm to use

	const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['decrypt']) // generate key from pw

	const ctStr = atob(ciphertext).slice(12)                                          // decode base64 ciphertext
	const ctUint8 = new Uint8Array(Array.from(ctStr).map(ch => ch.charCodeAt(0)))     // ciphertext as Uint8Array
	// note: why doesn't ctUint8 = new TextEncoder().encode(ctStr) work?

	try {
		const plainBuffer = await crypto.subtle.decrypt(alg, key, ctUint8)            // decrypt ciphertext using key
		const plaintext = new TextDecoder().decode(plainBuffer)                       // plaintext from ArrayBuffer
		return plaintext                                                              // return the plaintext
	} catch (e) {
		throw new Error('Decrypt failed')
	}
}



//          Client route to Node
const clientRoute: Map<string, nodeInfo> = new Map()

const pgp_managerSCPool: ethers.Contract[] = []
let nodePrivatekey: string
export const initPGPRouteManager = (privateKey: string) => {
    nodePrivatekey = privateKey
    const wallet = new ethers.Wallet(privateKey, CONETP_mainnet_rovider)
    const conet_PGP_manager_SC = new ethers.Contract(conet_PGP_address, CoNET_PGP_ABI, wallet)
    pgp_managerSCPool.push(conet_PGP_manager_SC)
}


export const getWalletFromKeyID = async (wallet: string) => {
    try{
        const [userPgpKeyID,
            userPublicKeyArmored,
            routePgpKeyID,
            routePublicKeyArmored,
            routeOnline] = await PGP_manager_readonly.searchKey(wallet)
        if (!userPgpKeyID || userPgpKeyID.length === 0) {
            return null
        }
        return userPgpKeyID
    } catch(ex: any) {
        logger(`getWalletFromKeyID Error ${ex.message}`)
    }
    return null
}

const getRouteFromPGP = async (keyFormat: string): Promise<nodeInfo|false> => {
    logger(` await PGP_manager_readonly.getRouteKeyIDByUserPgpKeyID(${keyFormat})`)
    try {
        const client = clientRoute.get(keyFormat)
        if (!client) {
            if (pgp_managerSCPool.length) {
                try {
                    const route = await PGP_manager_readonly.getRouteKeyIDByUserPgpKeyID(keyFormat)
                    if (!route) {
                        logger(`PGP_manager_readonly.getRouteKeyIDByUserPgpKeyID(${keyFormat}) GOT !route `)
                        return false
                    }

                    //      keyID ==> node
                    const node = routerInfo.get(route.toUpperCase())
                    if (node) {
                        logger(`routerInfo.get(route.toUpperCase()=${route.toUpperCase()}) === ${node.ipaddress}`)
                        clientRoute.set(keyFormat, node)
                        return node
                    }
                    
                } catch (ex: any) {
                    logger(`await PGP_manager_readonly.getRouteKeyIDByUserPgpKeyID(keyFormat) Error`, ex.message)
                }

            } else {
                logger(`getRouteFromPGP pgp_managerSCPool NULL Error!`)
            }
            
        } else {
            return client
        }
        
    } catch (ex: any) {
        logger(`getRouteFromPGP Error`, ex.message)
        
    }
    return false
    
}


const clientStatusPool: {
    wallet: string
    status: boolean
}[]  = []

export const isMyRoute = async (userAddress: string, nodeAddress: string): Promise<boolean> => {
  try {
        if (!ethers.isAddress(userAddress)) return false

    const wallet = new ethers.Wallet(nodePrivatekey, CONETP_mainnet_rovider)
    

        const SC = new ethers.Contract(conet_PGP_address, CoNET_PGP_ABI, wallet)

        // 1️⃣ node 是否是已注册节点
        const nodeHash: string = await SC.nodeWallet2KeyHash(nodeAddress)
        if (!nodeHash || nodeHash === ethers.ZeroHash) return false

        const nodeExists: boolean = await SC.nodeKeyExists(nodeHash)
        if (!nodeExists) return false

        // 2️⃣ 用户当前 route 是否指向该 node
        const userRouteHash: string = await SC.userRouteHash(userAddress)
        if (!userRouteHash || userRouteHash === ethers.ZeroHash) return false

        return userRouteHash.toLowerCase() === nodeHash.toLowerCase()
  } catch (e) {
        return false
  }
}


const statusProcess = async () => {
    const obj = clientStatusPool.shift()
    if (!obj) return

    const SC = pgp_managerSCPool.shift()
    if (!SC) {
        clientStatusPool.unshift(obj)
        return setTimeout(() => statusProcess(), 1000)
    }


    try {
        const tx = await SC.setUserOnlineOnMe(obj.wallet, obj.status)
        await tx.wait()
        logger(`statusProcess success ${obj.wallet} ===> ${obj.status}`)
    } catch (ex: any) {
        logger(`statusProcess Error!`, ex.message)
    }

    pgp_managerSCPool.push(SC)
    setTimeout(() => statusProcess(), 1000)

}

export const setClientOnline = (wallet: string, status: boolean) => {

    clientStatusPool.push({
        wallet,
        status
    })
    
    statusProcess()
}

//      get client route
export const getRoute = async (keyID: string): Promise<[string, string]|[]> => {
    const keyFormat = keyID.toUpperCase()
	const node = routerInfo.get(keyFormat)
    logger(``)
	if (!node) {
        logger(`routerInfo.get ${keyFormat} NULL`)
        const client = await getRouteFromPGP(keyFormat)
        if (!client) {
            logger(Colors.red(`getRoute has not !client`))
            return []
        }
       
        
		logger(Colors.red(`getRoute has not Node has this key ${keyID.toUpperCase()}`)) //inspect(routerInfo.keys(), false, 3, true))
		return [client.ipaddress, client.wallet]
	}
    
	return [node.ipaddress, node.wallet]
}

export const tryGetLocal = (clentKeyID: string): string[] => {
    if (!clentKeyID) return []

    const homeDir = os.homedir()
    const baseDir = path.join(homeDir, '.data')

    if (!fs.existsSync(baseDir)) {
        return []
    }

    const safeKey = clentKeyID.replace(/[^a-zA-Z0-9._-]/g, '_').toUpperCase()
    const filePath = path.join(baseDir, `${safeKey}.json`)

    if (!fs.existsSync(filePath)) {
        return []
    }

    let result: string[] = []

    try {
        const raw = fs.readFileSync(filePath, 'utf8')
        const parsed = JSON.parse(raw)
        if (Array.isArray(parsed)) {
        result = parsed.filter(v => typeof v === 'string')
        }
    } catch {
        // ignore parse errors
    } finally {
        // ✅ 关键：无论成功与否，读取后立即删除
        try {
        fs.unlinkSync(filePath)
        } catch {
        // ignore delete errors
        }
    }

    return result
}


export const saveLocal = (pgpMessage: string, clentKeyID: string) => {
    if (!pgpMessage || !clentKeyID) return

    // 跨 OS 的 home 目录
    const homeDir = os.homedir()

    // ~/.data
    const baseDir = path.join(homeDir, '.data')

    // 如果目录不存在，先创建
    if (!fs.existsSync(baseDir)) {
        fs.mkdirSync(baseDir, { recursive: true })
    }

    // 按 key 分文件
    const safeKey = clentKeyID.replace(/[^a-zA-Z0-9._-]/g, '_').toUpperCase()
    const filePath = path.join(baseDir, `${safeKey}.json`)

    let list: string[] = []

    // 如果文件存在，读取已有数组
    if (fs.existsSync(filePath)) {
        try {
            const raw = fs.readFileSync(filePath, 'utf8')
            const parsed = JSON.parse(raw)
            if (Array.isArray(parsed)) {
                list = parsed
            }
        } catch {
        // 文件损坏 / 非 JSON → 重置
            list = []
        }
    }

    // 追加 pgpMessage
    list.push(pgpMessage)

    // 写回文件
    fs.writeFileSync(filePath, JSON.stringify(list, null, 2), 'utf8')
    logger(`${clentKeyID} messge save to Local`)
}

export const forWardPGPMessageToClient = async (pgpMessage: string, clentKeyID: string, clent: livenessListeningPoolObj|undefined, callback: () => void) => {
    

    
    if (!clent) {
        logger(`forWardPGPMessageToClient clentKeyID ${clentKeyID} off line! save to local `)
        await saveLocal (pgpMessage, clentKeyID)
        return true
    }
    const data = JSON.stringify({data: pgpMessage})+'\r\n\r\n'
    const res = clent.res

    if (res.writable && !res.closed) {
		res.write( data, (err: any) => {
			if (err) {
				//logger(Colors.red (`stratliveness write Error! delete ${wallet}:${ipaddress} from livenessListeningPool [${livenessListeningPool.size}]`))
				
			} else {
				//logger(Colors.grey(`testMinerCOnnecting to${wallet}:${ipaddress} success!`))
			}
			callback()
			
		})
		
	}

    

}


const startGossip = (node: nodeInfo, POST: string, callback: (err: string, data?: string) => void) => {

	const option: RequestOptions = {
		host: node.ipaddress,
		port: 80,
		method: 'POST',
		protocol: 'http:',
		headers: {
			'Content-Type': 'application/json;charset=UTF-8'
		},
		path: "/post",
	}

	let first = true

	const kkk = request(option, res => {

		if (res.statusCode !==200) {
			return logger(`startTestMiner ${node.domain}:${node.ipaddress} got res.statusCode = [${res.statusCode}] != 200 error! restart`)
		}

		let data = ''
		let _Time: NodeJS.Timeout

		res.on ('data', _data => {
			
			data += _data.toString()
			
			if (/\r\n\r\n/.test(data)) {
				
				if (first) {
					first = false
					// logger(Colors.magenta(`first`))
					try{
						const uu = JSON.parse(data)
						callback('', uu)
					} catch(ex) {
						logger(Colors.red(`first JSON.parse Error`), data)
					}
					data = ''
					res._destroy(null, () => {
						//logger(Colors.magenta(`startGossip stop connecting!`))
					})
				}
			}
		})

		res.once('error', err => {
			//logger(Colors.red(`startGossip [${node.ipaddress}] res on ERROR!`), err.message)
		})

		res.once('end', () => {
			kkk.destroy()
		})
		
	})

	kkk.on('error', err => {
		logger(Colors.red(`startGossip [${node.ipaddress}] requestHttps on Error! Try to restart! `), err.message)
	})

	kkk.end(POST)

}

export const getGuardianNodeWallet: (node: nodeInfo, _localWallet: ethers.Wallet) => Promise<{nodeWallet: string}> = (node: nodeInfo, _localWallet: ethers.Wallet) => new Promise(async resolve => {

	const command = {
		command: 'mining',
		walletAddress: _localWallet?.address?.toLowerCase()
	}
	
	const message =JSON.stringify(command)
	const signMessage = await _localWallet.signMessage(message)
	const encryptObj = {
        message: await createMessage({text: Buffer.from(JSON.stringify ({message, signMessage})).toString('base64')}),
		encryptionKeys: await readKey({ armoredKey: node.pgpArmored}),
		config: { preferredCompressionAlgorithm: enums.compression.zlib } 		// compress the data with zlib
    }

	const postData = await encrypt (encryptObj)
	//logger(Colors.blue(`connectToGossipNode ${node.domain}`))
	startGossip (node, JSON.stringify({data: postData}), (err, _data: any) => {
		resolve(_data)
	})
})

let localWallet: ethers.Wallet
let localPublicKeyID: string

export const startUp = async (nodePrivate: ethers.Wallet, keyID: string) => {
	localPublicKeyID = keyID
	const ip = getServerIPV4Address ( false )
	if (ip && ip.length) {
		GlobalIpAddress = ip[0]
	}
	localWallet = nodePrivate
}

export const getNodeWallet = (nodeIpaddress: string) => {
	const index = gossipNodes.findIndex(n => n.ipaddress === nodeIpaddress)
	if (index < 0 ) {
		return null
	}
	
}


const getClientWalletAddress = async (
    pgpKeyID: string
): Promise<string | null> => {
    try {
        if (!pgpKeyID || typeof pgpKeyID !== "string") return null


        const wallet: string = await PGP_manager_readonly.getUserByPgpKeyID(pgpKeyID)

        // 合约语义：address(0) = 不存在
        if (!wallet || wallet === ethers.ZeroAddress) {
            return null
        }

        return wallet.toLowerCase()
    } catch (err) {
        console.error("getClientWalletAddress failed:", err)
        return null
    }
}


const test = async () => {
    
	await getAllNodes()
	// const kkk = await getRoute('F81BF37456250CCF')
	// logger(kkk)
    

}
// test()