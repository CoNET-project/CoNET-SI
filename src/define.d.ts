

interface ICoNET_NodeSetup {
	ipV4: string
	ipV4Port: number
	ipV6: string
	ipV6Port: number
	keychain: WalletBase
	keyObj?: any
	storage_price: number
	outbound_price: number
	DL_registeredData?: string
	pgpKeyObj?: pgpObj
	cpus: number
	pgpKey: {
		privateKey: string
		publicKey: string
		keyID: string
	}
	passwd?: string
	platform_verison: string
	dl_publicKeyArmored: string
}

interface ICoNET_DL {
	public: string
	wallet: string
	ipAddr: string
	PORT: number
}
interface IPGP_DecryptedInfo {
	signKeyID?: string
	publicKeyArmored: string
}

interface ICoNET_Router_Base {
	gpgPublicKeyID?: string
	armoredPublicKey: string
	walletAddr?: string
	signPgpKeyID?: string
}

interface ICoNET_DL_POST_register_SI extends ICoNET_Router_Base {
	walletAddr: string
	ipV4: string
	storage_price: number
	outbound_price: number
	ipV4Port: number
	ip_api?: any
	platform_verison: string
	nft_tokenid: string
	cpus: number
	walletAddrSign: string
}

interface ICoNET_DL_POST_health_SI extends ICoNET_Router_Base {
	nft_tokenid: string
	platform_verison: string
	walletAddr: string
	walletAddrSign: string
}


interface s3pass {
	ACCESS_KEY: string
	SECRET_KEY: string
}

interface pgpObj {
	publicKeyObj: any
	privateKeyObj: any
}

interface SICommandObj {
	command: 'SaaS_Proxy'|'SaaS_Sock5'|'mining'
	publicKeyArmored: string
	responseError: string|null
	responseData: any[]
	algorithm: 'aes-256-cbc'
	Securitykey: string
	requestData: any[]
}




interface authorized {
	date: string
	serial: string
	amount: number
	tx: string
}

interface use_history {
	type: 'storage'|'outbound'
	data_length: number				//		Gbyte
	price: number
	fee: number
	date: number
}

interface eth_crypto_key_obj {
	privateKey: string
    publicKey: string
    address: string
	balance: number
	authorized?: authorized
	amount: number
	paid?: use_history[]
	unpaid?: use_history[]
}

interface SI_Client_CoNETCashData {
	walletKeyArray: eth_crypto_key_obj[]
	publicKeyArmored: string
}

interface ICoNET_Router {

	gpgPublicKeyID?: string
	armoredPublicKey?: string
	walletAddr?: string
	walletPublicArmored?: string
	ipv4?: string
	nickName?: string
	profileImg?: string
	emailAddr?: string
	forward?: string
	ip_addr: string
}

interface ethSignedObj {
	message: string
	messageHash: string
	r: string
	s: string
	signature: string
	v: string
}

interface CoNETCashBalanceResponse {
	id: string
	balance: number
	owner: string
}

interface VE_IPptpStream {
    type?: string
    buffer: string
    host: string|null
    port: number
    cmd: string
    //ATYP: number
    uuid?: string
    length?:number
    randomBuffer?: Buffer
    ssl: boolean
    hostIPAddress: string|null
    hostName?: string       //      for test gateway from client
	order: number
}

type RequestOrgnal = {
	href: string
	method: string
	port: number
	json: string
}


interface nodeInfo {
	ipaddress: string
	regionName: string
	pgpArmored: string
	pgpKeyID: string
}

interface NodList {
	isGuardianNode: boolean
	wallet: string
	nodeInfo: nodeInfo|null
	nodeID: number
	Expired: number
	value?: number
}


interface minerObj extends SICommandObj{
	walletAddress: string
	ipAddress: string
	weidth: number
	blockNumber?:string
	referrer?:string
	fork: any
	hash?: string
	data?: any
	allWallets?: string[]
}