

interface ICoNET_NodeSetup {
	ipV4: string
	ipV4Port: number
	ipV6: string
	ipV6Port: number
	keychain: any
	keyObj?: any
	storage_price: number
	outbound_price: number
	DL_registeredData?: string
	pgpKeyObj?: pgpObj
	pgpKey: {
		privateKey: string
		publicKey: string
		keyID: string
	}
}

interface ICoNET_DL {
	public: string
	wallet: string
	ipAddr: string
	PORT: number
}

interface ICoNET_DL_POST_register_SI {
	wallet_CoNET: string
	pgpPublicKey: string
	ipV4: string
	storage_price: number
	outbound_price: number
	ipV4Port: number
}

interface s3pass {
	ACCESS_KEY: string
	SECRET_KEY: string
}

interface pgpObj {
	publicKeyObj: any
	privateKeyObj: any
}