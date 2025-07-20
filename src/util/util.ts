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
import passport_distributor_ABI from './passport_distributor-ABI.json'
import duplicateFactoryABI from './duplicateFactoryABI.json'


export const CoNET_CancunRPC = 'https://cancun-rpc.conet.network'
export const CoNET_mainnet_RPC = 'https://mainnet-rpc.conet.network'
const ipfsEndpoint = `https://ipfs.conet.network/api/`
export const CONETCancun= new ethers.JsonRpcProvider(CoNET_CancunRPC)
const CONETP_mainnet_rovider = new ethers.JsonRpcProvider(CoNET_mainnet_RPC)
const GuardianPlan_CancunAddr = '0x312c96DbcCF9aa277999b3a11b7ea6956DdF5c61'
const GuardianNodeInfo_CancunAddr = '0x88cBCc093344F2e1A6c2790A537574949D711E9d'


let GlobalIpAddress = ''

export const routerInfo: Map<string, nodeInfo> = new Map()

let gossipNodes: nodeInfo[] = []

let getNodeInfoProssing = false

const CoNETDePIN_Passport_cancun_addr = '0xb889F14b557C2dB610f283055A988952953E0E94'
const CoNETDePIN_passport_distributor_mainnet_addr = '0x40d64D88A86D6efb721042225B812379dc97bc89'
const  CoNETDePIN_Passport_mainnet_addr = '0x054498c353452A6F29FcA5E7A0c4D13b2D77fF08'

const CoNETDePIN_PassportSC_readonly = new ethers.Contract(CoNETDePIN_Passport_cancun_addr, CoNETDePIN_PassportABI, CONETCancun)
const CoNETDePIN_PassportSC_mainnet_readonly = new ethers.Contract(CoNETDePIN_Passport_mainnet_addr, CoNETDePIN_PassportABI, CONETP_mainnet_rovider)
const CoNETDePIN_passport_distributor_mainnet_readonly = new ethers.Contract(CoNETDePIN_passport_distributor_mainnet_addr, passport_distributor_ABI, CONETP_mainnet_rovider)
const GuardianNodes = new ethers.Contract(GuardianPlan_CancunAddr, GuardianNodesV2ABI, CONETCancun)
const paymendUser: Map<string, boolean> = new Map()
const GuardianNodesInfo = new ethers.Contract(GuardianNodeInfo_CancunAddr, openPGPContractAbi, CONETCancun)

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
const duplicateFactory_addr = '0xb8777d4b0e1c07dF073fAf75a5F42D9e29BfD0F5'
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


export const getAllNodes = () => new Promise(async resolve=> {
	
	if (getAllNodesProcess) {
		return resolve (true)
	}

	getAllNodesProcess = true

	
	let scanNodes = 0
	
	const maxNodes: BigInt = await GuardianNodes.currentNodeID()
	scanNodes = parseInt(maxNodes.toString())

	
	if (!scanNodes) {
		getAllNodesProcess = false
		resolve (false)
		return logger(`getAllNodes STOP scan because scanNodes == 0`)
	}



	for (let i = 0; i < scanNodes; i ++) {
		Guardian_Nodes.push({
			regionName: '',
			ipaddress: '',
			pgpArmored: '',
			nftNumber: 100 + i,
			domain: '',
			pgpKeyID: '',
			wallet: ''
		})
	}
		
	
	let i = 0
	mapLimit(Guardian_Nodes, 10, async (n: nodeInfo, next) => {
		i = n.nftNumber
		const nodeInfo = await GuardianNodesInfo.getNodeInfoById(n.nftNumber)
		n.regionName = nodeInfo.regionName
		n.ipaddress = nodeInfo.ipaddress
		n.pgpArmored = Buffer.from(nodeInfo.pgp,'base64').toString()
		const pgpKey1 = await readKey({ armoredKey: n.pgpArmored})
		n.domain = pgpKey1.getKeyIDs()[1].toHex().toUpperCase()
		routerInfo.set(n.domain, n)
	}, err => {
		const index = Guardian_Nodes.findIndex(n => n.nftNumber === i) - 1
		Guardian_Nodes = Guardian_Nodes.slice(0, index)
		logger(Colors.red(`mapLimit catch ex! Guardian_Nodes = ${Guardian_Nodes.length} `))
		getAllNodesProcess = false
		resolve(true)
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



export const getRoute = async (keyID: string) => {

	const node = routerInfo.get(keyID.toUpperCase())
	if (!node) {
		logger(Colors.red(`getRoute has not Node has this key ${keyID.toUpperCase()}`)) //inspect(routerInfo.keys(), false, 3, true))
		return null
	}
	return node.ipaddress
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
const test = async () => {
	const aa = await checkPayment('0x45e5feb3288b9400f0e054fc23da2f1b1c9880cd')
	logger(Colors.magenta(`test aa = ${aa}`))
}
// test()