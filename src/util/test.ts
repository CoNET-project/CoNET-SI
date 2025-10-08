import {logger} from './logger'
import Colors from 'colors/safe'
import { ethers } from 'ethers'
import IP from 'ip'
import {readPrivateKey, readMessage, decrypt, decryptKey} from 'openpgp'
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
    const privateKey=`-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n\r\nxVgEaJxh1RYJKwYBBAHaRw8BAQdA7F2ANsQhQGu5wHqZat174ppVm7LHY+MQ\r\nVdruFSASyiYAAQCJlDNdNsWOGpekXPuWNAeXcByV1z+us66uukQS35VKvQ/K\r\nzSoweGEzMENhOTY3NkFmNzNkNjA3OWIyZTIxM2RiQjVCMzZmOGY3NjJmMzbC\r\nwBMEExYKAIUFgmicYdUDCwkHCRAYhIrtaIbLqEUUAAAAAAAcACBzYWx0QG5v\r\ndGF0aW9ucy5vcGVucGdwanMub3Jn0sHkOvBc2AUiUYH5ZoDhlasko7nxLREe\r\nyOWQ4YoCTgEFFQoIDgwEFgACAQIZAQKbAwIeARYhBJ5s3yHYsc6ZeavIpxiE\r\niu1ohsuoAAC7VwD/RNAjzlqYM9LqTuQ8gWnb/fJUCuaxOCuPXFI6OU9q1hYA\r\n/2a7jqqg9G3XGhwalR3BmjEpMu+BDXbXM4p1OZet6BsMx10EaJxh1RIKKwYB\r\nBAGXVQEFAQEHQMXJRhstWCtUaVYA1p/rFTTIRMBeuyfr3+sHbLpVVhEYAwEI\r\nBwAA/0IcXCbKc9Bjb8W1/kaAFI99h4bGlELQDGzoNxNa2dPQERXCvgQYFgoA\r\ncAWCaJxh1QkQGISK7WiGy6hFFAAAAAAAHAAgc2FsdEBub3RhdGlvbnMub3Bl\r\nbnBncGpzLm9yZ39P3niJnXQyrGyQrX33EXKt4OoeBY8fnwvq4jM6VkLNApsM\r\nFiEEnmzfIdixzpl5q8inGISK7WiGy6gAALOAAQDTStPwSZ9Y0pQz8wmKSu1f\r\nehPcLOGya3N7mwhnXuMA9gEAx5gWXc4P8AvNgxNSmDtC/K01pMiES4fYoIdF\r\nC/WzjQ8=\r\n=boWN\r\n\r\n-----END PGP PRIVATE KEY BLOCK-----\r\n`
    const kk = await readPrivateKey({armoredKey: privateKey})
    // const decryptionKeys = await decryptKey ({privateKey: kk})
    const messagePGP = ` -----BEGIN PGP MESSAGE-----\r\nVersion: PGPainless\r\n\r\n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\r\n=wu+9\r\n-----END PGP MESSAGE-----`
    const message = await readMessage({armoredMessage: messagePGP})
    const dd = decrypt({message, decryptionKeys: kk})
    logger(dd)
    //const kk = {"message":"{\"Securitykey\":\"[B@e57d9d6\",\"algorithm\":\"aes-256-cbc\",\"command\":\"SaaS_Sock5\",\"requestData\":{\"buffer\":\"\",\"host\":\"www.google.com\",\"port\":80,\"uuid\":\"682c17bb-2030-46b2-bc0e-9f44c2d661aa\"},\"walletAddress\":\"0x779cc0dda545201396daa3c7df85392471e21579\"}","signMessage":"0xf6621d456a8ba0f53bf5c0be5c994660919e341cf418946bbd7fba419f5caa5b4186380f11f9f53a5238365a25a2ccb76ec4991e12783b5d4a2c75a3e3977b181c"}
	// //await checkPaymentReceiptTx(tx, '0x73940fcb2211c1c09eceb6f42846e30af6b459bc')
	// // startEventListening()
	// const kk1 = checkSign(kk.message, kk.signMessage)
	// logger(kk1)
	// const kkk = IP.isPublic('192.168.0.1')
	// logger(kkk)
}

test()

//			curl -4 --socks5 "127.0.0.1:3003" "https://www.google.com/"