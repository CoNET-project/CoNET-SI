import { ethers } from 'ethers'
import {inspect} from 'node:util'
import cCNTPABI from './cCNTP.json'
import { logger } from './logger'
import Colors from 'colors/safe'

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


export const CoNET_CancunRPC = 'https://cancun-rpc.conet.network'
const ipfsEndpoint = `https://ipfs.conet.network/api/`
export const CONETProvider = new ethers.JsonRpcProvider(CoNET_CancunRPC)

const GuardianPlan_CancunAddr = '0x312c96DbcCF9aa277999b3a11b7ea6956DdF5c61'
const GuardianNodeInfo_CancunAddr = '0x88cBCc093344F2e1A6c2790A537574949D711E9d'


let GlobalIpAddress = ''

export const useNodeReceiptList: Map<string, NodList> = new Map()
export const routerInfo: Map<string, nodeInfo> = new Map()

let gossipNodes: nodeInfo[] = []

let getNodeInfoProssing = false

const CoNETDePIN_Passport_cancun_addr = '0xb889F14b557C2dB610f283055A988952953E0E94'

const CoNETDePIN_PassportSC_readonly = new ethers.Contract(CoNETDePIN_Passport_cancun_addr, CoNETDePIN_PassportABI, CONETProvider)

const paymendUser: Map<string, boolean> = new Map()



export const checkPayment = async(fromAddr: string) => {

	const pay = paymendUser.get(fromAddr)

	if (pay) {
		return true
	}

	let _nftIDs: ethers.BigNumberish
	let _expires: ethers.BigNumberish
	let _expiresDays: ethers.BigNumberish
	let _premium: boolean
	try {
		[_nftIDs, _expires, _expiresDays, _premium] = await CoNETDePIN_PassportSC_readonly.getCurrentPassport(fromAddr)
	} catch (ex: any) {
		logger(Colors.red(`checkPayment CoNETDePIN_PassportSC_readonly.getCurrentPassport Error!, ${ex.message}`))
		return false
	}
	const today = parseFloat(new Date().getTime().toString())
	const expires =  parseFloat(_expires.toString()) * 1000			//		Convert to milliseconds

	if (!_nftIDs|| expires < today) {
		return false
	}
	paymendUser.set(fromAddr, true)
	return true
}

export const putUserMiningToPaymendUser = (fromAddr: string) => {
	paymendUser.set(fromAddr, true)
}

const initGuardianNodes = async () => new Promise(async resolve => {
	if (getNodeInfoProssing) {
		 logger(`initGuardianNodes already running!`)
		 return resolve(false)
	}
	logger(`initGuardianNodes start running!`)
	getNodeInfoProssing = true

	const guardianSmartContract_Cancun = new ethers.Contract(GuardianPlan_CancunAddr, GuardianNodesV2ABI, CONETProvider)

	const GuardianNodesInfoV3Contract_Cancun = new ethers.Contract(GuardianNodeInfo_CancunAddr, openPGPContractAbi, CONETProvider)
	let nodes
	try {
		nodes = await guardianSmartContract_Cancun.getAllIdOwnershipAndBooster()
	} catch (ex: any) {
		getNodeInfoProssing = false
		console.error(Colors.red(`guardianReferrals guardianSmartContract.getAllIdOwnershipAndBooster() Error!`), ex.mesage)
		return resolve(false)
	}


	const _nodesAddress: string[] = nodes[0].map((n: string) => n)

	const NFTIds = _nodesAddress.map ((n, index) => 100 + index)
	
	const getNodeInfo = async (nodeID: number) => {

		//	logger(Colors.gray(`getNodeInfo [${nodeID}]`))
		const nodeInfo: nodeInfo = {
			ipaddress: '',
			regionName: '',
			pgpArmored: '',
			pgpKeyID: '',
			domain: '',
			wallet: ''
		}

		const [ipaddress, regionName, pgp] = await GuardianNodesInfoV3Contract_Cancun.getNodeInfoById(nodeID)

		if (ipaddress) {
			if (ipaddress !== GlobalIpAddress) {
				nodeInfo.ipaddress = ipaddress
				nodeInfo.regionName = regionName
				nodeInfo.pgpArmored = pgp
				// nodeInfo.pgpArmored = await GuardianNodesInfoV3Contract.getNodePGP(nodeInfo.ipaddress)
				return nodeInfo
			}
			return true
		}

		return null
	}

	_nodesAddress.forEach(async (n, index) => {
		
		const node: NodList = {
			isGuardianNode: true,
			wallet: n.toLowerCase(),
			nodeID: NFTIds[index],
			nodeInfo:null,
			Expired: 0
		}

		useNodeReceiptList.set(node.wallet, node)
		//logger(Colors.grey(`Add Guardian owner wallet [${node.wallet}] to list!`))
	})

	let i = 0
	gossipNodes = []

	mapLimit(useNodeReceiptList.entries(), 5, async ([n, v], next) => {
		
		const result = await getNodeInfo(v.nodeID)
		
		
		if (typeof result === 'object' && result?.ipaddress) {
			
			if (v.nodeInfo && v.nodeInfo.pgpArmored){
				v.nodeInfo.pgpArmored = Buffer.from(v.nodeInfo.pgpArmored, 'base64').toString()
				const pgpKey = await readKey({ armoredKey: v.nodeInfo.pgpArmored})
				v.nodeInfo.pgpKeyID = pgpKey.getKeyIDs()[1].toHex().toUpperCase()
				v.nodeInfo.domain = v.nodeInfo.pgpKeyID + '.conet.network'
				const kkk = await getGuardianNodeWallet(v.nodeInfo)
				//logger(inspect(kkk, false, 3, true))
				
				v.wallet = v.nodeInfo.wallet = kkk.nodeWallet
				
				//logger(inspect(v, false, 3, true))
				routerInfo.set(v.nodeInfo.pgpKeyID, v.nodeInfo)
				
				if (localPublicKeyID !== v.nodeInfo.pgpKeyID) {
					gossipNodes.push(v.nodeInfo)
				}
				logger(`added node info ${v.wallet}:${v.nodeInfo.pgpKeyID} total nodes = ${routerInfo.size}`)
			}
		}
	}, err => {
		logger(Colors.magenta(`initGuardianNodes finished! routerInfo size = ${routerInfo.size}`))
		return resolve(true)
	})
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

const iface = new ethers.Interface(cCNTPABI)

let currentEpoch: number
let lastrate: number
let localPublicKeyID = ''
let localWallet: ethers.Wallet

// const detailTransfer = async (tx: string, provider: ethers.JsonRpcProvider) => {
	
// 	const transObj = await provider.getTransactionReceipt(tx)

// 	const toAddr = transObj?.to?.toLowerCase()
	
// 	if ( GuardianNodesInfoV6 === toAddr) {
// 		return await initGuardianNodes()
// 	}

// 	if (!toAddr || toAddr !== newCNTP_v8 || transObj?.logs?.length !== 1 ) {
// 		return //logger(Colors.gray(`Skip tx ${tx}`))
// 	}

// 	let uu: ethers.LogDescription|null
// 	try {
// 		uu = iface.parseLog(transObj.logs[0])
// 	} catch (ex) {
// 		return logger(Colors.red(`iface.parseLog [${tx}] Error!`))
// 	}
// 	const args = uu?.args
	
// 	if (uu?.name !== 'Transfer' || args?.length !== 3 || args[1] !== '0x0000000000000000000000000000000000000000') {
// 		return //logger(Colors.grey(`detailTransfer skip [${tx}]`))
// 	}
// 	const wallet = args[0].toLowerCase()
// 	//	admin brun
// 	if (wallet === '0x418833b70f882c833ef0f0fcee3fb9d89c79d47c') {
// 		return //logger(Colors.grey(`detailTransfer skip [${wallet}]`))
// 	}

// 	const startEpoch = transObj.blockNumber
// 	const value = parseFloat(ethers.formatEther(args[2]))
	
	

// 	const keepEpoch = Math.round(value/lastrate)
// 	const endEpoch = startEpoch + keepEpoch
// 	if (endEpoch < currentEpoch) {
// 		return logger(Colors.blue(`Brun cCNTP [${wallet}] , value [${value}] rate type = ${typeof lastrate} [${lastrate}] start [${startEpoch}] end = [${Colors.magenta(endEpoch.toString())}] current epoch = [${Colors.red(currentEpoch.toString())}]`))
// 	}
// 	const pass: NodList = {
// 		wallet: wallet,
// 		isGuardianNode: false,
// 		Expired: endEpoch,
// 		nodeID: 0,
// 		nodeInfo: null,
// 		value
// 	}
// 	useNodeReceiptList.set (wallet, pass)
// 	logger(Colors.magenta(`add Silent Pass [${pass.wallet}] end Epoch = [${pass.Expired}] `))
	
// }

const cleanupUseNodeReceiptList = (epoch: number) => {
	useNodeReceiptList.forEach((v,key) => {
		if (v.isGuardianNode) {
			return
		}
		if (v.Expired < epoch) {
			useNodeReceiptList.delete(key)
		}
	})
}

export const getRoute = async (keyID: string) => {

	const node = routerInfo.get(keyID.toUpperCase())
	if (!node) {
		logger(Colors.red(`getRoute has not Node has this key ${keyID.toUpperCase()}`)) //inspect(routerInfo.keys(), false, 3, true))
		return null
	}
	return node.ipaddress
}

const getEpochRate1: (epoch: number) => Promise<boolean|string> = async (epoch) => new Promise(resolve => {
	const cloudStorageEndpointUrl = `${ipfsEndpoint}getFragment/${epoch}_free`
	
		P({
			url: cloudStorageEndpointUrl,
			parse: 'json'
		}).then (res => {
			if (res?.body) {
				//@ts-ignore
				return resolve(res?.body['minerRate'])
			}
			return resolve (false)
		})
		.catch(ex => {
			logger(`getEpochRate catch EX!`, ex.message)
			return resolve (false)
		})
		
	
})

// const checkBlock = async (block: number) => {
// 	//logger(Colors.gray(`checkBlock doing epoch [${Colors.blue(block.toString())}]`))
// 	const blockDetail = await CONETProvider.getBlock(block)
// 	if (!blockDetail?.transactions) {
// 		return logger(Colors.gray(`checkBlock block ${block} hasn't any transactions`))
// 	}

// 	const execPoll = []
// 	for (let u of blockDetail.transactions) {
// 		execPoll.push(detailTransfer(u, CONETProvider))
// 	}

// 	await Promise.all([...execPoll])
// }

// const scanPassedEpoch = async () => {
// 	const endEpoch = currentEpoch
// 	const startEpoch = currentEpoch - (5*60) * 3
// 	const execPool: number[] = []
// 	for (let i = startEpoch; i <= endEpoch; i ++) {
// 		execPool.push(i)
// 	}

// 	await mapLimit(execPool,1, async (n, next) => {
// 		await checkBlock(n)
// 	})
// }

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

export const getGuardianNodeWallet: (node: nodeInfo) => Promise<{nodeWallet: string}> = (node: nodeInfo) => new Promise(async resolve => {

	const command = {
		command: 'mining',
		walletAddress: localWallet.address.toLowerCase()
	}
	
	const message =JSON.stringify(command)
	const signMessage = await localWallet.signMessage(message)
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

// const connectToGossipNode = async (privateKey: string, node: nodeInfo ) => {
	
// 	const wallet = new ethers.Wallet(privateKey)
// 	const command = {
// 		command: 'mining',
// 		walletAddress: wallet.address.toLowerCase()
// 	}
	
// 	const message =JSON.stringify(command)
// 	const signMessage = await wallet.signMessage(message)
// 	const encryptObj = {
//         message: await createMessage({text: Buffer.from(JSON.stringify ({message, signMessage})).toString('base64')}),
// 		encryptionKeys: await readKey({ armoredKey: node.pgpArmored}),
// 		config: { preferredCompressionAlgorithm: enums.compression.zlib } 		// compress the data with zlib
//     }

// 	const postData = await encrypt (encryptObj)
// 	logger(Colors.blue(`connectToGossipNode ${node.domain}`))
// 	startGossip(node, JSON.stringify({data: postData}), (err, _data ) => {
// 		if (!_data) {
// 			return logger(Colors.magenta(`connectToGossipNode ${node.ipaddress} push ${_data} is null!`))
// 		}

// 		try {
// 			const data = JSON.parse(_data)
// 			const wallets = data.nodeWallets||[]
// 			gossipStatus.nodesWallets.set(node.ipaddress, wallets)
// 			if (wallets.length) {
// 				//logger(inspect(wallets, false, 3, true))
// 			}
// 			logger(`connectToGossipNode ${node.ipaddress} wallets ${data.nodeWallets} to gossipStatus nodesWallets Pool length = ${gossipStatus.nodesWallets.size}`)
			
// 		} catch (ex) {
// 			logger(Colors.blue(`${node.ipaddress} => \n${_data}`))
// 			logger(Colors.red(`connectToGossipNode JSON.parse(_data) Error!`))
// 		}

// 	})
// }



export const startUp = async (nodePrivate: ethers.Wallet, keyID: string) => {
	currentEpoch = await CONETProvider.getBlockNumber()
	localPublicKeyID = keyID
	const ip = getServerIPV4Address ( false )
	if (ip && ip.length) {
		GlobalIpAddress = ip[0]
	}
	localWallet = nodePrivate
	await initGuardianNodes()
	// startGossipListening(privateKey)
	// await scanPassedEpoch()
	
	// CONETProvider.on('block', async block => {

	// 	// currentEpoch = block
	// 	// cleanupUseNodeReceiptList(block)
	// 	// const blockDetail = await CONETProvider.getBlock(block)
	// 	// if (!blockDetail?.transactions) {
	// 	// 	return logger(Colors.gray(`startEventListening block ${block} hasn't any transactions`))
	// 	// }
		
	// 	// const transactions: string[] = blockDetail.transactions

	// 	// await mapLimit(transactions, 1, async (n, next) => {
	// 	// 	await detailTransfer(n, CONETProvider)
	// 	// })
		
	// })
	
}

// const startGossipListening = (privateKey: string) => {
// 	if (!gossipNodes.length) {
// 		return logger(Colors.red(`startGossipListening Error! gossipNodes is null!`))
// 	}
// 	logger(Colors.blue(`startGossipListening gossipNodes = ${gossipNodes.length}`))
// 	gossipNodes.forEach(n => {
// 		connectToGossipNode(privateKey, n)
// 	})
	
// }

export const getNodeWallet = (nodeIpaddress: string) => {
	const index = gossipNodes.findIndex(n => n.ipaddress === nodeIpaddress)
	if (index < 0 ) {
		return null
	}
	
}