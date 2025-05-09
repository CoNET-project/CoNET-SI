import {logger} from './logger'
import Colors from 'colors/safe'
import { ethers } from 'ethers'
import IP from 'ip'
export const checkSign = (message: string, signMess: string) => {
	let digest, recoverPublicKey, verifyMessage, obj: minerObj
	let wallet = ''
	try {
		obj = JSON.parse(message)
		wallet = obj.walletAddress.toLowerCase()
		digest = ethers.id(message)
		recoverPublicKey = ethers.recoverAddress(digest, signMess)
		verifyMessage = ethers.verifyMessage(message, signMess)

	} catch (ex) {
		logger (Colors.red(`checkSignObj recoverPublicKey ERROR`), ex)
		logger (`digest = ${digest} signMess = ${signMess}`)
		return null
	}
	

	if (wallet && (verifyMessage.toLowerCase() === wallet || recoverPublicKey.toLowerCase() === wallet)) {
		obj.walletAddress = wallet
		return obj
	}
	
	logger (Colors.red(`checkSignObj recoveredAddress (${verifyMessage.toLowerCase()}) or recoverPublicKey ${recoverPublicKey.toLowerCase()} !== wallet (${wallet})`))
	return null
	
}

const tx = '0x5d2074da118044ebc0f90f935da8045a543aa1031d9f55b8af668ab5b2dfcc93'
const test = async () => {
	// const kk = {"message":"{\"Securitykey\":\"[B@e57d9d6\",\"algorithm\":\"aes-256-cbc\",\"command\":\"SaaS_Sock5\",\"requestData\":{\"buffer\":\"\",\"host\":\"www.google.com\",\"port\":80,\"uuid\":\"682c17bb-2030-46b2-bc0e-9f44c2d661aa\"},\"walletAddress\":\"0x779cc0dda545201396daa3c7df85392471e21579\"}","signMessage":"0xf6621d456a8ba0f53bf5c0be5c994660919e341cf418946bbd7fba419f5caa5b4186380f11f9f53a5238365a25a2ccb76ec4991e12783b5d4a2c75a3e3977b181c"}
	// //await checkPaymentReceiptTx(tx, '0x73940fcb2211c1c09eceb6f42846e30af6b459bc')
	// // startEventListening()
	// const kk1 = checkSign(kk.message, kk.signMessage)
	// logger(kk1)
	const kkk = IP.isPublic('192.168.0.1')
	logger(kkk)
}

test()

//			curl -4 --socks5 "127.0.0.1:3003" "https://www.google.com/"