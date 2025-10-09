import {logger} from './logger'
import Colors from 'colors/safe'
import { ethers } from 'ethers'
import IP from 'ip'
import {readPrivateKey, readMessage, decrypt, decryptKey} from 'openpgp'
import { inspect}from 'node:util'

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
    const privateKey="-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nxVgEaJxyORYJKwYBBAHaRw8BAQdA24Gm5iZlYwpNucozguPJR89R58yZelFL\nv4CeDuZFUU4AAQDOD1SfvfKzYwXhYHZkE3tgE3qJBR1UT6TndVR7JrIjWg2j\nzSoweDBkMDU5YWE1NjcxRmNDMTkxODYyODA5YjQ0MjEwY2FlQmQ1ZjlENTLC\nwBMEExYKAIUFgmiccjkDCwkHCRDhxqmNQbtQ4EUUAAAAAAAcACBzYWx0QG5v\ndGF0aW9ucy5vcGVucGdwanMub3JnK+J+c2x9F4KzG5SmjXxz5CahE9rCCZbX\n2AFjYe4s15QFFQoIDgwEFgACAQIZAQKbAwIeARYhBJsx/JReCrEDSud9SuHG\nqY1Bu1DgAACX7gEA22+zrcPrSNG4sgAMnDgasJA2CBmswzuVlsBI1s/oXbQB\nAJHm5/6HpztPl0tyMQAO4ICFA02Ln6bCaBPFAEvDsGsFx10EaJxyORIKKwYB\nBAGXVQEFAQEHQFuMt6jgpNiKA+JKKRXbUBgOpGGDkKY5gvRlsoDryYAJAwEI\nBwAA/1Bf1QHLIXPvQ2UDsNYzEZNoVXG6A7YeS3OUsDPgHWCoDtPCvgQYFgoA\ncAWCaJxyOQkQ4capjUG7UOBFFAAAAAAAHAAgc2FsdEBub3RhdGlvbnMub3Bl\nbnBncGpzLm9yZ2CD9x1kivzdI46l5sieIQhDBeIFhW5XQJ2yN74q2V0+ApsM\nFiEEmzH8lF4KsQNK531K4capjUG7UOAAABgxAP9mOmHUqzhIEXjdytSvwHKz\nbOcpKlHzbhcgsLEdpU998AD/avTYrCtk4Mfet1HGTEqtJzGe7eYguYiZJ8fz\nvPZqdgY=\n=8F3D\n-----END PGP PRIVATE KEY BLOCK-----\n"
    const kk = await readPrivateKey({armoredKey: privateKey})
    // const decryptionKeys = await decryptKey ({privateKey: kk})
    const messagePGP = "-----BEGIN PGP MESSAGE-----\nVersion: PGPainless\n\n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\n=S9DM\n-----END PGP MESSAGE-----\n"
    const message = await readMessage({armoredMessage: messagePGP})
    logger(inspect(message.packets))
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