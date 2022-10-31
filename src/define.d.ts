interface ICoNET_NodeSetup {
	ipV4: string
	ipV4Port: number
	ipV6: string
	ipV6Port: number
	keychain: any
	keyObj: any
	storage_price: number
	outbound_price: number
	setupPath: string
	DL_nodes: ICoNET_DL[]
	DL_registeredData: any
}

interface ICoNET_DL {
	public: string
	wallet: string
	ipAddr: string
	PORT: number
}

interface ICoNET_DL_POST_register_SI {
	wallet_CoNET: string
	publicKey: string
	ipV4: string
	storage_price: number
	outbound_price: number
	wallet_CNTCash: string
	ipV4Port: number

}