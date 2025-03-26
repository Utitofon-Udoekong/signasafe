import { DetectionService } from './service'
import { DetectionRequest } from './dtos'
import { EtherscanService } from './services/etherscan'

// Mock EtherscanService
jest.mock('./services/etherscan')

describe('DetectionService', () => {
    let mockEtherscanService: jest.Mocked<EtherscanService>

    beforeEach(() => {
        // Reset all mocks before each test
        jest.clearAllMocks()

        // Create mock EtherscanService
        mockEtherscanService = {
            isContractVerified: jest.fn(),
            getContractSourceCode: jest.fn(),
        } as any

        // Replace the static etherscanService with our mock
        (DetectionService as any).etherscanService = mockEtherscanService
    })

    describe('detect', () => {
        const mockTrace: DetectionRequest['trace'] = {
            to: '0x1234567890123456789012345678901234567890',
            from: '0x0987654321098765432109876543210987654321',
            value: '0x1',
            gas: '0x5208',
            gasUsed: '0x5208',
            input: '0x',
            pre: {},
            post: {},
            calls: []
        }

        it('should detect suspicious contract interactions', async () => {
            const request = new DetectionRequest()
            request.trace = mockTrace
            const response = await DetectionService.detect(request)
            expect(response.detected).toBe(false)
        })

        it('should detect unusual value transfers', async () => {
            const request = new DetectionRequest()
            request.trace = {
                ...mockTrace,
                value: '0x2386f26fc10000' // 10 ETH
            }
            const response = await DetectionService.detect(request)
            expect(response.detected).toBe(true)
            expect(response.message).toContain('Critical value transfer')
        })

        it('should detect suspicious function calls', async () => {
            const request = new DetectionRequest()
            request.trace = {
                ...mockTrace,
                input: '0x12345678' // Unknown function signature
            }
            const response = await DetectionService.detect(request)
            expect(response.detected).toBe(true)
            expect(response.message).toContain('Unknown function call')
        })

        it('should detect gas price anomalies', async () => {
            const request = new DetectionRequest()
            request.trace = {
                ...mockTrace,
                gas: '0x1dcd6500' // 500 Gwei
            }
            const response = await DetectionService.detect(request)
            expect(response.detected).toBe(true)
            expect(response.message).toContain('Critical gas price')
        })

        it('should detect unverified contracts', async () => {
            mockEtherscanService.isContractVerified.mockResolvedValue(false)

            const request = new DetectionRequest()
            request.trace = mockTrace
            const response = await DetectionService.detect(request)
            expect(response.detected).toBe(true)
            expect(response.message).toContain('not verified on Etherscan')
        })

        it('should detect suspicious patterns in verified contracts', async () => {
            mockEtherscanService.isContractVerified.mockResolvedValue(true)
            mockEtherscanService.getContractSourceCode.mockResolvedValue(`
                contract Test {
                    function dangerous() external payable {
                        assembly {
                            // dangerous assembly code
                        }
                    }
                }
            `)

            const request = new DetectionRequest()
            request.trace = mockTrace
            const response = await DetectionService.detect(request)
            expect(response.detected).toBe(true)
            expect(response.message).toContain('Contains inline assembly')
        })

        it('should detect reentrancy patterns', async () => {
            mockEtherscanService.isContractVerified.mockResolvedValue(true)
            mockEtherscanService.getContractSourceCode.mockResolvedValue(`
                contract Test {
                    function withdraw() external {
                        msg.sender.call.value(balance)("");
                        balance = 0;
                    }
                }
            `)

            const request = new DetectionRequest()
            request.trace = mockTrace
            const response = await DetectionService.detect(request)
            expect(response.detected).toBe(true)
            expect(response.message).toContain('Potential reentrancy vulnerability')
        })

        it('should detect front-running patterns', async () => {
            mockEtherscanService.isContractVerified.mockResolvedValue(true)
            mockEtherscanService.getContractSourceCode.mockResolvedValue(`
                contract Test {
                    function process() external {
                        require(block.timestamp > deadline);
                    }
                }
            `)

            const request = new DetectionRequest()
            request.trace = mockTrace
            const response = await DetectionService.detect(request)
            expect(response.detected).toBe(true)
            expect(response.message).toContain('Potential front-running vulnerability')
        })

        it('should detect integer overflow patterns', async () => {
            mockEtherscanService.isContractVerified.mockResolvedValue(true)
            mockEtherscanService.getContractSourceCode.mockResolvedValue(`
                contract Test {
                    function add(uint256 a, uint256 b) external {
                        uint256 result = a + b;
                    }
                }
            `)

            const request = new DetectionRequest()
            request.trace = mockTrace
            const response = await DetectionService.detect(request)
            expect(response.detected).toBe(true)
            expect(response.message).toContain('Potential integer overflow/underflow')
        })

        it('should detect access control issues', async () => {
            mockEtherscanService.isContractVerified.mockResolvedValue(true)
            mockEtherscanService.getContractSourceCode.mockResolvedValue(`
                contract Test {
                    modifier onlyOwner() {
                        require(msg.sender == owner);
                        _;
                    }
                }
            `)

            const request = new DetectionRequest()
            request.trace = mockTrace
            const response = await DetectionService.detect(request)
            expect(response.detected).toBe(true)
            expect(response.message).toContain('Potential access control vulnerability')
        })

        it('should detect timestamp manipulation', async () => {
            mockEtherscanService.isContractVerified.mockResolvedValue(true)
            mockEtherscanService.getContractSourceCode.mockResolvedValue(`
                contract Test {
                    function process() external {
                        require(block.timestamp > deadline);
                    }
                }
            `)

            const request = new DetectionRequest()
            request.trace = mockTrace
            const response = await DetectionService.detect(request)
            expect(response.detected).toBe(true)
            expect(response.message).toContain('Potential timestamp manipulation')
        })

        it('should detect unchecked external calls', async () => {
            mockEtherscanService.isContractVerified.mockResolvedValue(true)
            mockEtherscanService.getContractSourceCode.mockResolvedValue(`
                contract Test {
                    function transfer(address to) external {
                        to.call.value(amount)("");
                    }
                }
            `)

            const request = new DetectionRequest()
            request.trace = mockTrace
            const response = await DetectionService.detect(request)
            expect(response.detected).toBe(true)
            expect(response.message).toContain('Potential unchecked external call')
        })

        it('should detect delegatecall injection', async () => {
            mockEtherscanService.isContractVerified.mockResolvedValue(true)
            mockEtherscanService.getContractSourceCode.mockResolvedValue(`
                contract Test {
                    function execute(address target) external {
                        assembly {
                            let ptr := mload(0x40)
                            calldatacopy(ptr, 0, calldatasize())
                            let success := delegatecall(gas(), target, ptr, calldatasize(), 0, 0)
                        }
                    }
                }
            `)

            const request = new DetectionRequest()
            request.trace = mockTrace
            const response = await DetectionService.detect(request)
            expect(response.detected).toBe(true)
            expect(response.message).toContain('Potential delegatecall injection')
        })

        it('should handle Etherscan API errors gracefully', async () => {
            mockEtherscanService.isContractVerified.mockRejectedValue(new Error('API Error'))

            const request = new DetectionRequest()
            request.trace = mockTrace
            const response = await DetectionService.detect(request)
            expect(response.detected).toBe(false)
            expect(response.message).toBeUndefined()
        })
    })
}) 