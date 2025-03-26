import axios from 'axios'

interface EtherscanResponse {
    status: string
    message: string
    result: string
}

export class EtherscanService {
    private readonly apiKey: string
    private readonly baseUrl: string
    private readonly cache: Map<string, { verified: boolean; timestamp: number }>
    private readonly CACHE_DURATION = 24 * 60 * 60 * 1000 // 24 hours

    constructor(apiKey: string, network: 'mainnet' | 'testnet' = 'mainnet') {
        this.apiKey = apiKey
        this.baseUrl = network === 'mainnet' 
            ? 'https://api.etherscan.io/api'
            : 'https://api-goerli.etherscan.io/api'
        this.cache = new Map()
    }

    /**
     * Checks if a contract is verified on Etherscan
     */
    public async isContractVerified(address: string): Promise<boolean> {
        // Check cache first
        const cached = this.cache.get(address)
        if (cached && Date.now() - cached.timestamp < this.CACHE_DURATION) {
            return cached.verified
        }

        try {
            const response = await axios.get<EtherscanResponse>(this.baseUrl, {
                params: {
                    module: 'contract',
                    action: 'getabi',
                    address,
                    apikey: this.apiKey
                }
            })

            const isVerified = response.data.status === '1' && response.data.result !== '[]'

            // Cache the result
            this.cache.set(address, {
                verified: isVerified,
                timestamp: Date.now()
            })

            return isVerified
        } catch (error) {
            console.error('Error checking contract verification:', error)
            return false
        }
    }

    /**
     * Gets contract source code from Etherscan
     */
    public async getContractSourceCode(address: string): Promise<string | null> {
        try {
            const response = await axios.get<EtherscanResponse>(this.baseUrl, {
                params: {
                    module: 'contract',
                    action: 'getsourcecode',
                    address,
                    apikey: this.apiKey
                }
            })

            if (response.data.status === '1' && response.data.result !== '[]') {
                return response.data.result
            }

            return null
        } catch (error) {
            console.error('Error getting contract source code:', error)
            return null
        }
    }
} 