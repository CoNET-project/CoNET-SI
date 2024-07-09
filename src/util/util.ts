import { ethers } from 'ethers'
import {inspect} from 'node:util'
import cCNTPABI from './cCNTP.json'
import { logger } from './logger'
import Colors from 'colors/safe'
import {abi as GuardianNodesV2ABI} from './GuardianNodesV2.json'
import openPGPContractAbi from './GuardianNodesInfoV3.json'
import P from 'phin'
import { mapLimit } from 'async'
import {readKey} from 'openpgp'
import { getServerIPV4Address } from './localNodeCommand'

const conetHoleskyRPC = 'https://rpc.conet.network'
const ipfsEndpoint = `https://ipfs.conet.network/api/`
const cCNTPAddr = '0x530cf1B598D716eC79aa916DD2F05ae8A0cE8ee2'.toLowerCase()
const GuardianNodes_ContractV3 = '0x453701b80324C44366B34d167D40bcE2d67D6047'
const GuardianNodesInfoV5 = '0x617b3CE079c653c8A9Af1B5957e69384919a7084'.toLowerCase()
let GlobalIpAddress = ''

const useNodeReceiptList: Map<string, NodList> = new Map()
const routerInfo: Map<string, nodeInfo> = new Map()


const CONETProvider = new ethers.JsonRpcProvider(conetHoleskyRPC)

const initGuardianNodes = async () => {
	
	const guardianSmartContract = new ethers.Contract(GuardianNodes_ContractV3, GuardianNodesV2ABI, CONETProvider)
	const GuardianNodesInfoV3Contract = new ethers.Contract(GuardianNodesInfoV5, openPGPContractAbi, CONETProvider)
	let nodes
	try {
		nodes = await guardianSmartContract.getAllIdOwnershipAndBooster()
	} catch (ex: any) {
		return console.error(Colors.red(`guardianReferrals guardianSmartContract.getAllIdOwnershipAndBooster() Error!`), ex.mesage)
	}


	const _nodesAddress: string[] = nodes[0].map((n: string) => n)
	let NFTAssets: number[]

	const NFTIds = _nodesAddress.map ((n, index) => 100 + index)
	try {
		NFTAssets = await guardianSmartContract.balanceOfBatch(_nodesAddress, NFTIds)
	} catch (ex: any) {
		return logger(Colors.red(`nodesAirdrop guardianSmartContract.balanceOfBatch(${_nodesAddress},${NFTIds}) Error! STOP`), ex.mesage)
	}
	

	const getNodeInfo = async (nodeID: number) => {
		logger(Colors.gray(`getNodeInfo [${nodeID}]`))
		const nodeInfo = {
			ipaddress: '',
			regionName: '',
			pgpArmored: '',
			pgpKeyID: ''
		}
		const [ipaddress, regionName, pgp] = await GuardianNodesInfoV3Contract.getNodeInfoById(nodeID)
		if (ipaddress && ipaddress !== GlobalIpAddress) {
			nodeInfo.ipaddress = ipaddress
			nodeInfo.regionName = regionName
			nodeInfo.pgpArmored = pgp
			// nodeInfo.pgpArmored = await GuardianNodesInfoV3Contract.getNodePGP(nodeInfo.ipaddress)
			return nodeInfo
		}
		return null
	}

	NFTAssets.forEach(async (n, index) => {
		if (n) {
			const node: NodList = {
				isGuardianNode: true,
				wallet: _nodesAddress[index].toLowerCase(),
				nodeID: NFTIds[index],
				nodeInfo:null,
				Expired: 0
			}
			useNodeReceiptList.set(node.wallet,node)
		} else {
			//logger(Color.red(`nodesAddress [${_nodesAddress[index]}] has no NFT ${NFTIds[index]}`))
		}
	})

	return await mapLimit(useNodeReceiptList.entries(), 1, async ([n, v], next) => {
		
			v.nodeInfo = await getNodeInfo(v.nodeID)
			logger(inspect(v.nodeInfo, false, 3, true))
			if (v.nodeInfo && v.nodeInfo.pgpArmored){
				const pgpKey = await readKey({ armoredKey: Buffer.from(v.nodeInfo.pgpArmored, 'base64').toString() })
				v.nodeInfo.pgpKeyID = pgpKey.getKeyIDs()[1].toHex().toUpperCase()
				logger(Colors.blue(`Add Guardian Node[${v.nodeInfo.ipaddress}] keyID [${v.nodeInfo.pgpKeyID}]`))
				routerInfo.set(v.nodeInfo.pgpKeyID, v.nodeInfo)
			} else {
				next(new Error(`SPIP scan!`))
			}
		
	}, err => {
		logger(`mapLimit scan STOPed!`, err)
	})
	
}

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


const detailTransfer = async (tx: string, provider: ethers.JsonRpcProvider) => {
	
	const transObj = await provider.getTransactionReceipt(tx)

	const toAddr = transObj?.to?.toLowerCase()
	
	if ( GuardianNodesInfoV5 === toAddr) {
		return await initGuardianNodes()
	}

	if (!toAddr || toAddr !== cCNTPAddr || transObj?.logs?.length !== 1 ) {
		return //logger(Colors.gray(`Skip tx ${tx}`))
	}

	let uu: ethers.LogDescription|null
	try {
		uu = iface.parseLog(transObj.logs[0])
	} catch (ex) {
		return logger(Colors.red(`iface.parseLog [${tx}] Error!`))
	}
	const args = uu?.args

	if (uu?.name !== 'Transfer' || args?.length !== 3 || args[1] !== '0x0000000000000000000000000000000000000000') {
		return logger(Colors.grey(`detailTransfer skip [${tx}]`))
	}

	const startEpoch = transObj.blockNumber
	const value = parseFloat(ethers.formatEther(args[2]))
	const wallet = args[0].toLowerCase()
	const _rate = await getEpochRate(currentEpoch - transObj.blockNumber < 5 ? currentEpoch - 5 : transObj.blockNumber)
	
	const rate = (typeof _rate !== 'string'||_rate === '') ? lastrate : parseFloat(_rate)
	lastrate = rate

	const keepEpoch = Math.round(value/rate)
	const endEpoch = startEpoch + keepEpoch
	if (endEpoch < currentEpoch) {
		return logger(Colors.blue(`Brun cCNTP [${wallet}] , value [${value}] rate type = ${typeof rate} [${rate}] start [${startEpoch}] end = [${Colors.magenta(endEpoch.toString())}] current epoch = [${Colors.red(currentEpoch.toString())}]`))
	}
	const pass: NodList = {
		wallet: wallet,
		isGuardianNode: false,
		Expired: endEpoch,
		nodeID: 0,
		nodeInfo: null,
		value
	}
	useNodeReceiptList.set (wallet, pass)
	logger(Colors.magenta(`add Silent Pass [${pass.wallet}] end Epoch = [${pass.Expired}] `))
	
}

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

export const getRoute = (keyID: string) => {
	const node = routerInfo.get(keyID.toUpperCase())
	if (!node) {
		initGuardianNodes()
		return null
	}
	return node.ipaddress
}


export const checkPayment = (fromAddr: string) => {

	const nodes = useNodeReceiptList.get(fromAddr.toLowerCase())
	if (!nodes) {
		logger(Colors.blue(`checkPayment [${fromAddr}] has none in list!`))
		return false
	}
	if (!nodes.isGuardianNode && nodes.Expired < currentEpoch) {
		logger(Colors.blue(`checkPayment [${fromAddr}] Expired!`))
		useNodeReceiptList.delete (fromAddr.toLowerCase())
		return false
	}

	return true
}


const getEpochRate: (epoch: number) => Promise<boolean|string> = async (epoch) => new Promise(resolve => {
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
			logger(`getEpochRate catch EX!`)
			return resolve (false)
		})
		
	
})

const checkBlock = async (block: number) => {
	logger(Colors.gray(`checkBlock doing epoch [${Colors.blue(block.toString())}]`))
	const blockDetail = await CONETProvider.getBlock(block)
	if (!blockDetail?.transactions) {
		return logger(Colors.gray(`checkBlock block ${block} hasn't any transactions`))
	}

	const execPoll = []
	for (let u of blockDetail.transactions) {
		execPoll.push(detailTransfer(u, CONETProvider))
	}

	await Promise.all([...execPoll])
}

const scanPassedEpoch = async () => {
	const endEpoch = currentEpoch
	const startEpoch = currentEpoch - (5*60) * 3
	const execPool: number[] = []
	for (let i = startEpoch; i <= endEpoch; i ++) {
		execPool.push(i)
	}

	await mapLimit(execPool,1, async (n, next) => {
		await checkBlock(n)
	})
}

export const startEventListening = async () => {
	currentEpoch = await CONETProvider.getBlockNumber()
	const ip = getServerIPV4Address ( false )
	if (ip && ip.length) {
		GlobalIpAddress = ip[0]
	}
	await initGuardianNodes()

	CONETProvider.on('block', async block => {
		currentEpoch = block
		cleanupUseNodeReceiptList(block)
		const blockDetail = await CONETProvider.getBlock(block)
		if (!blockDetail?.transactions) {
			return logger(Colors.gray(`startEventListening block ${block} hasn't any transactions`))
		}
		//@ts-ignore
		const transactions: string[] = blockDetail.transactions

		await mapLimit(transactions, 1, async (n, next) => {
			await detailTransfer(n, CONETProvider)
		})
		

	})
	
	await scanPassedEpoch()
}