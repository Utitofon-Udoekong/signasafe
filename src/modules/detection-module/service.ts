import { DetectionRequest, DetectionResponse } from './dtos'
import { EtherscanService } from './services/etherscan'

/**
 * PhishingDetectorService
 * 
 * Implements detection logic for phishing attempts in EVM transactions.
 * Analyzes transactions for:
 * 1. Suspicious contract interactions
 * 2. Unusual value transfers
 * 3. Suspicious function calls
 * 4. Gas price anomalies
 * 5. Contract verification status
 * 6. Transaction timing patterns
 * 7. Contract behavior analysis
 */
export class DetectionService {
    private static readonly etherscanService = new EtherscanService(
        process.env.ETHERSCAN_API_KEY || '',
        process.env.NETWORK_TYPE as 'mainnet' | 'testnet' || 'mainnet'
    )

    // Gas price thresholds (in Gwei)
    private static readonly GAS_PRICE_THRESHOLDS = {
        SUSPICIOUS: BigInt('100'), // 100 Gwei
        CRITICAL: BigInt('500'),   // 500 Gwei
    }

    // Value transfer thresholds (in Wei)
    private static readonly VALUE_THRESHOLDS = {
        SUSPICIOUS: BigInt('1000000000000000000'), // 1 ETH
        CRITICAL: BigInt('10000000000000000000'),  // 10 ETH
    }

    // Common legitimate function signatures
    private static readonly LEGITIMATE_FUNCTIONS = new Set([
        '0x7c025200', // deposit()
        '0x2e1a7d4d', // withdraw(uint256)
        '0x3ccfd60b', // withdrawAll()
        '0x095ea7b3', // approve(address,uint256)
        '0xa9059cbb', // transfer(address,uint256)
        '0x23b872dd', // transferFrom(address,address,uint256)
    ])

    /**
     * Analyzes a transaction for potential phishing attempts
     */
    public static async detect(request: DetectionRequest): Promise<DetectionResponse> {
        const trace = request.trace
        let isPhishing = false
        let message = ''
        const detectionDetails: string[] = []

        // Check for suspicious contract interactions
        const contractInteractionResult = this.isSuspiciousContractInteraction(trace)
        if (contractInteractionResult.isSuspicious) {
            isPhishing = true
            detectionDetails.push(contractInteractionResult.details)
        }

        // Check for unusual value transfers
        const valueTransferResult = this.hasUnusualValueTransfer(trace)
        if (valueTransferResult.isSuspicious) {
            isPhishing = true
            detectionDetails.push(valueTransferResult.details)
        }

        // Check for suspicious function calls
        const functionCallResult = this.hasSuspiciousFunctionCalls(trace)
        if (functionCallResult.isSuspicious) {
            isPhishing = true
            detectionDetails.push(functionCallResult.details)
        }

        // Check for gas price anomalies
        const gasPriceResult = this.hasGasPriceAnomaly(trace)
        if (gasPriceResult.isSuspicious) {
            isPhishing = true
            detectionDetails.push(gasPriceResult.details)
        }

        // Check for contract verification status
        const verificationResult = await this.isContractVerified(trace)
        if (verificationResult.isSuspicious) {
            isPhishing = true
            detectionDetails.push(verificationResult.details)
        }

        // Check for transaction timing patterns
        const timingResult = this.hasSuspiciousTiming(trace)
        if (timingResult.isSuspicious) {
            isPhishing = true
            detectionDetails.push(timingResult.details)
        }

        // Check for suspicious contract behavior
        const behaviorResult = this.hasSuspiciousBehavior(trace)
        if (behaviorResult.isSuspicious) {
            isPhishing = true
            detectionDetails.push(behaviorResult.details)
        }

        // Combine all detection details into a single message
        message = detectionDetails.join(' | ')

        return new DetectionResponse({
            request,
            detectionInfo: {
                detected: isPhishing,
                message: isPhishing ? message : undefined,
            },
        })
    }

    /**
     * Checks if the transaction involves suspicious contract interactions
     */
    private static isSuspiciousContractInteraction(trace: DetectionRequest['trace']): { isSuspicious: boolean; details: string } {
        // Check if the transaction is interacting with a contract
        if (!trace.to || trace.to === '0x0000000000000000000000000000000000000000') {
            return { isSuspicious: false, details: '' }
        }

        // Check if the contract has code
        const contractState = trace.post[trace.to]
        if (!contractState || !contractState.code || contractState.code === '0x') {
            return { isSuspicious: false, details: '' }
        }

        // Check for suspicious patterns in contract interaction
        const suspiciousPatterns = this.analyzeContractPatterns(contractState)
        if (suspiciousPatterns.length > 0) {
            return {
                isSuspicious: true,
                details: `Suspicious contract patterns detected: ${suspiciousPatterns.join(', ')}`
            }
        }

        return { isSuspicious: false, details: '' }
    }

    /**
     * Analyzes contract code for suspicious patterns
     */
    private static analyzeContractPatterns(contractState: DetectionRequest['trace']['post'][string]): string[] {
        const patterns: string[] = []
        const code = contractState.code || ''

        // Check for dangerous patterns in contract code
        if (code.includes('selfdestruct')) {
            patterns.push('Contains selfdestruct')
        }
        if (code.includes('delegatecall')) {
            patterns.push('Contains delegatecall')
        }
        if (code.includes('assembly')) {
            patterns.push('Contains inline assembly')
        }
        if (code.includes('call.value')) {
            patterns.push('Contains call.value')
        }
        if (code.includes('suicide')) {
            patterns.push('Contains suicide')
        }
        if (code.includes('extcodesize')) {
            patterns.push('Contains extcodesize')
        }
        if (code.includes('extcodecopy')) {
            patterns.push('Contains extcodecopy')
        }
        if (code.includes('create2')) {
            patterns.push('Contains create2')
        }

        return patterns
    }

    /**
     * Checks for unusual value transfers in the transaction
     */
    private static hasUnusualValueTransfer(trace: DetectionRequest['trace']): { isSuspicious: boolean; details: string } {
        // Check if there's a value transfer
        if (!trace.value || trace.value === '0x0') {
            return { isSuspicious: false, details: '' }
        }

        // Convert value from hex to decimal
        const value = BigInt(trace.value)
        
        // Check value against thresholds
        if (value > this.VALUE_THRESHOLDS.CRITICAL) {
            return {
                isSuspicious: true,
                details: `Critical value transfer detected: ${value.toString()} Wei`
            }
        }
        if (value > this.VALUE_THRESHOLDS.SUSPICIOUS) {
            return {
                isSuspicious: true,
                details: `Suspicious value transfer detected: ${value.toString()} Wei`
            }
        }

        return { isSuspicious: false, details: '' }
    }

    /**
     * Checks for suspicious function calls in the transaction
     */
    private static hasSuspiciousFunctionCalls(trace: DetectionRequest['trace']): { isSuspicious: boolean; details: string } {
        const suspiciousCalls: string[] = []

        // Check the main transaction input
        if (trace.input) {
            const functionSignature = trace.input.slice(0, 10)
            // If the function is not in our legitimate functions list, it's suspicious
            if (!this.LEGITIMATE_FUNCTIONS.has(functionSignature)) {
                suspiciousCalls.push(`Unknown function call: ${functionSignature}`)
            }
        }

        // Check all internal calls
        if (trace.calls) {
            trace.calls.forEach((call, index) => {
                if (call.input) {
                    const functionSignature = call.input.slice(0, 10)
                    if (!this.LEGITIMATE_FUNCTIONS.has(functionSignature)) {
                        suspiciousCalls.push(`Unknown internal call ${index}: ${functionSignature}`)
                    }
                }
            })
        }

        if (suspiciousCalls.length > 0) {
            return {
                isSuspicious: true,
                details: `Suspicious function calls detected: ${suspiciousCalls.join(', ')}`
            }
        }

        return { isSuspicious: false, details: '' }
    }

    /**
     * Checks for gas price anomalies
     */
    private static hasGasPriceAnomaly(trace: DetectionRequest['trace']): { isSuspicious: boolean; details: string } {
        const gasPrice = BigInt(trace.gas)
        
        if (gasPrice > this.GAS_PRICE_THRESHOLDS.CRITICAL) {
            return {
                isSuspicious: true,
                details: `Critical gas price detected: ${gasPrice.toString()} Gwei`
            }
        }
        if (gasPrice > this.GAS_PRICE_THRESHOLDS.SUSPICIOUS) {
            return {
                isSuspicious: true,
                details: `Suspicious gas price detected: ${gasPrice.toString()} Gwei`
            }
        }

        return { isSuspicious: false, details: '' }
    }

    /**
     * Checks if the contract is verified on Etherscan
     */
    private static async isContractVerified(trace: DetectionRequest['trace']): Promise<{ isSuspicious: boolean; details: string }> {
        // Skip check if no contract address
        if (!trace.to || trace.to === '0x0000000000000000000000000000000000000000') {
            return { isSuspicious: false, details: '' }
        }

        try {
            const isVerified = await this.etherscanService.isContractVerified(trace.to)
            
            if (!isVerified) {
                return {
                    isSuspicious: true,
                    details: `Contract ${trace.to} is not verified on Etherscan`
                }
            }

            // If verified, get source code for additional analysis
            const sourceCode = await this.etherscanService.getContractSourceCode(trace.to)
            if (sourceCode) {
                // Additional checks on verified contracts
                const suspiciousPatterns = this.analyzeVerifiedContract(sourceCode)
                if (suspiciousPatterns.length > 0) {
                    return {
                        isSuspicious: true,
                        details: `Verified contract contains suspicious patterns: ${suspiciousPatterns.join(', ')}`
                    }
                }
            }

            return { isSuspicious: false, details: '' }
        } catch (error) {
            console.error('Error checking contract verification:', error)
            return {
                isSuspicious: false,
                details: 'Error checking contract verification status'
            }
        }
    }

    /**
     * Analyzes verified contract source code for suspicious patterns
     * 
     * This method performs a comprehensive analysis of the contract source code
     * by checking for various categories of suspicious patterns:
     * 
     * 1. Dangerous Opcodes and Functions: Checks for low-level operations that could be used maliciously
     * 2. Suspicious Solidity Features: Identifies use of potentially dangerous Solidity features
     * 3. Suspicious Function Patterns: Detects potentially dangerous function declarations
     * 4. Suspicious State Variables: Identifies potentially dangerous state variable declarations
     * 5. Suspicious Modifiers: Checks for potentially dangerous modifiers
     * 6. Suspicious Events: Identifies potentially dangerous event declarations
     * 7. Suspicious Libraries: Detects use of potentially dangerous libraries
     * 8. Suspicious Inheritance: Identifies potentially dangerous inheritance patterns
     * 
     * @param sourceCode The Solidity source code of the contract
     * @returns Array of strings describing detected suspicious patterns
     */
    private static analyzeVerifiedContract(sourceCode: string): string[] {
        const patterns: string[] = []
        const sourceCodeLower = sourceCode.toLowerCase()

        // 1. Dangerous Opcodes and Functions
        const dangerousOpcodes = [
            { pattern: 'assembly', description: 'Contains inline assembly' },
            { pattern: 'selfdestruct', description: 'Contains selfdestruct' },
            { pattern: 'delegatecall', description: 'Contains delegatecall' },
            { pattern: 'call.value', description: 'Contains call.value' },
            { pattern: 'suicide', description: 'Contains suicide' },
            { pattern: 'extcodesize', description: 'Contains extcodesize' },
            { pattern: 'extcodecopy', description: 'Contains extcodecopy' },
            { pattern: 'create2', description: 'Contains create2' },
            { pattern: 'sstore', description: 'Contains sstore' },
            { pattern: 'sload', description: 'Contains sload' },
            { pattern: 'mstore', description: 'Contains mstore' },
            { pattern: 'mload', description: 'Contains mload' },
            { pattern: 'calldatacopy', description: 'Contains calldatacopy' },
            { pattern: 'calldataload', description: 'Contains calldataload' }
        ]

        // 2. Suspicious Solidity Features
        const suspiciousFeatures = [
            { pattern: 'tx.origin', description: 'Uses tx.origin' },
            { pattern: 'block.timestamp', description: 'Uses block.timestamp' },
            { pattern: 'block.number', description: 'Uses block.number' },
            { pattern: 'block.difficulty', description: 'Uses block.difficulty' },
            { pattern: 'block.coinbase', description: 'Uses block.coinbase' },
            { pattern: 'block.gaslimit', description: 'Uses block.gaslimit' },
            { pattern: 'gasleft()', description: 'Uses gasleft()' },
            { pattern: 'blockhash', description: 'Uses blockhash' }
        ]

        // 3. Suspicious Function Patterns
        const suspiciousFunctions = [
            { pattern: 'function\\s+\\w+\\s*\\([^)]*\\)\\s*external\\s*payable', description: 'External payable function' },
            { pattern: 'function\\s+\\w+\\s*\\([^)]*\\)\\s*public\\s*payable', description: 'Public payable function' },
            { pattern: 'function\\s+\\w+\\s*\\([^)]*\\)\\s*external\\s*\\{', description: 'External function' },
            { pattern: 'function\\s+\\w+\\s*\\([^)]*\\)\\s*public\\s*\\{', description: 'Public function' },
            { pattern: 'function\\s+\\w+\\s*\\([^)]*\\)\\s*internal\\s*\\{', description: 'Internal function' },
            { pattern: 'function\\s+\\w+\\s*\\([^)]*\\)\\s*private\\s*\\{', description: 'Private function' }
        ]

        // 4. Suspicious State Variables
        const suspiciousStateVars = [
            { pattern: 'mapping\\s*\\([^)]*\\)\\s*public', description: 'Public mapping' },
            { pattern: 'mapping\\s*\\([^)]*\\)\\s*private', description: 'Private mapping' },
            { pattern: 'mapping\\s*\\([^)]*\\)\\s*internal', description: 'Internal mapping' },
            { pattern: 'address\\s+owner', description: 'Contains owner address' },
            { pattern: 'address\\s+admin', description: 'Contains admin address' },
            { pattern: 'bool\\s+initialized', description: 'Contains initialized flag' },
            { pattern: 'uint256\\s+balance', description: 'Contains balance variable' }
        ]

        // 5. Suspicious Modifiers
        const suspiciousModifiers = [
            { pattern: 'modifier\\s+onlyOwner', description: 'Contains onlyOwner modifier' },
            { pattern: 'modifier\\s+onlyAdmin', description: 'Contains onlyAdmin modifier' },
            { pattern: 'modifier\\s+whenNotPaused', description: 'Contains whenNotPaused modifier' },
            { pattern: 'modifier\\s+whenPaused', description: 'Contains whenPaused modifier' },
            { pattern: 'modifier\\s+nonReentrant', description: 'Contains nonReentrant modifier' }
        ]

        // 6. Suspicious Events
        const suspiciousEvents = [
            { pattern: 'event\\s+Transfer', description: 'Contains Transfer event' },
            { pattern: 'event\\s+Approval', description: 'Contains Approval event' },
            { pattern: 'event\\s+OwnershipTransferred', description: 'Contains OwnershipTransferred event' },
            { pattern: 'event\\s+AdminChanged', description: 'Contains AdminChanged event' }
        ]

        // 7. Suspicious Libraries
        const suspiciousLibraries = [
            { pattern: 'using\\s+SafeMath', description: 'Uses SafeMath library' },
            { pattern: 'using\\s+SafeERC20', description: 'Uses SafeERC20 library' },
            { pattern: 'using\\s+Address', description: 'Uses Address library' },
            { pattern: 'using\\s+Counters', description: 'Uses Counters library' }
        ]

        // 8. Suspicious Inheritance
        const suspiciousInheritance = [
            { pattern: 'is\\s+Ownable', description: 'Inherits from Ownable' },
            { pattern: 'is\\s+Pausable', description: 'Inherits from Pausable' },
            { pattern: 'is\\s+ReentrancyGuard', description: 'Inherits from ReentrancyGuard' },
            { pattern: 'is\\s+AccessControl', description: 'Inherits from AccessControl' }
        ]

        // Check all patterns
        const allPatterns = [
            ...dangerousOpcodes,
            ...suspiciousFeatures,
            ...suspiciousFunctions,
            ...suspiciousStateVars,
            ...suspiciousModifiers,
            ...suspiciousEvents,
            ...suspiciousLibraries,
            ...suspiciousInheritance
        ]

        for (const { pattern, description } of allPatterns) {
            if (sourceCodeLower.match(new RegExp(pattern, 'i'))) {
                patterns.push(description)
            }
        }

        // 9. Additional Complex Analysis
        const complexPatterns = this.analyzeComplexPatterns(sourceCode)
        patterns.push(...complexPatterns)

        return patterns
    }

    /**
     * Performs complex pattern analysis on the contract source code
     * 
     * This method implements advanced analysis techniques to detect complex
     * vulnerabilities that require more sophisticated pattern matching:
     * 
     * 1. Reentrancy: Checks for potential reentrancy vulnerabilities
     * 2. Front-running: Detects potential front-running attack vectors
     * 3. Integer Overflow/Underflow: Identifies potential integer overflow/underflow issues
     * 4. Access Control: Checks for potential access control vulnerabilities
     * 5. Timestamp Manipulation: Detects potential timestamp manipulation attacks
     * 6. Unchecked External Calls: Identifies potentially dangerous external calls
     * 7. Delegatecall Injection: Checks for potential delegatecall injection vulnerabilities
     * 
     * @param sourceCode The Solidity source code of the contract
     * @returns Array of strings describing detected complex vulnerabilities
     */
    private static analyzeComplexPatterns(sourceCode: string): string[] {
        const patterns: string[] = []
        const sourceCodeLower = sourceCode.toLowerCase()

        // 1. Check for potential reentrancy patterns
        if (this.hasReentrancyPattern(sourceCode)) {
            patterns.push('Potential reentrancy vulnerability detected')
        }

        // 2. Check for potential front-running patterns
        if (this.hasFrontRunningPattern(sourceCode)) {
            patterns.push('Potential front-running vulnerability detected')
        }

        // 3. Check for potential integer overflow/underflow
        if (this.hasIntegerOverflowPattern(sourceCode)) {
            patterns.push('Potential integer overflow/underflow vulnerability detected')
        }

        // 4. Check for potential access control issues
        if (this.hasAccessControlPattern(sourceCode)) {
            patterns.push('Potential access control vulnerability detected')
        }

        // 5. Check for potential timestamp manipulation
        if (this.hasTimestampManipulationPattern(sourceCode)) {
            patterns.push('Potential timestamp manipulation vulnerability detected')
        }

        // 6. Check for potential unchecked external calls
        if (this.hasUncheckedExternalCallPattern(sourceCode)) {
            patterns.push('Potential unchecked external call vulnerability detected')
        }

        // 7. Check for potential delegatecall injection
        if (this.hasDelegatecallInjectionPattern(sourceCode)) {
            patterns.push('Potential delegatecall injection vulnerability detected')
        }

        return patterns
    }

    /**
     * Checks for potential reentrancy patterns in the contract
     * 
     * This method analyzes the contract for potential reentrancy vulnerabilities
     * by checking for:
     * 1. External calls (call.value, .call, .send, .transfer)
     * 2. State modifications after external calls (sstore, mstore, arithmetic operations)
     * 
     * @param sourceCode The Solidity source code of the contract
     * @returns boolean indicating if reentrancy patterns are detected
     */
    private static hasReentrancyPattern(sourceCode: string): boolean {
        const reentrancyPatterns = [
            /call\.value\([^)]*\)/i,
            /\.call\([^)]*\)/i,
            /\.send\([^)]*\)/i,
            /\.transfer\([^)]*\)/i
        ]

        // Check if any of the patterns exist
        const hasExternalCall = reentrancyPatterns.some(pattern => pattern.test(sourceCode))

        // Check if there's state modification after external call
        if (hasExternalCall) {
            const stateModificationPatterns = [
                /sstore/i,
                /mstore/i,
                /\+=/i,
                /-=/i,
                /\*=/i,
                /\/=/i
            ]

            return stateModificationPatterns.some(pattern => pattern.test(sourceCode))
        }

        return false
    }

    /**
     * Checks for potential front-running patterns in the contract
     * 
     * This method analyzes the contract for potential front-running vulnerabilities
     * by checking for use of:
     * 1. block.timestamp
     * 2. block.number
     * 3. block.difficulty
     * 4. block.gaslimit
     * 5. block.coinbase
     * 6. blockhash
     * 
     * @param sourceCode The Solidity source code of the contract
     * @returns boolean indicating if front-running patterns are detected
     */
    private static hasFrontRunningPattern(sourceCode: string): boolean {
        const frontRunningPatterns = [
            /block\.timestamp/i,
            /block\.number/i,
            /block\.difficulty/i,
            /block\.gaslimit/i,
            /block\.coinbase/i,
            /blockhash/i
        ]

        return frontRunningPatterns.some(pattern => pattern.test(sourceCode))
    }

    /**
     * Checks for potential integer overflow/underflow patterns in the contract
     * 
     * This method analyzes the contract for potential integer overflow/underflow
     * vulnerabilities by checking for:
     * 1. Addition operations (+=, +)
     * 2. Subtraction operations (-=, -)
     * 3. Multiplication operations (*=, *)
     * 4. Division operations (/=, /)
     * 
     * @param sourceCode The Solidity source code of the contract
     * @returns boolean indicating if integer overflow/underflow patterns are detected
     */
    private static hasIntegerOverflowPattern(sourceCode: string): boolean {
        const overflowPatterns = [
            /\+=/i,
            /-=/i,
            /\*=/i,
            /\/=/i,
            /\+/i,
            /-/i,
            /\*/i,
            /\//i
        ]

        return overflowPatterns.some(pattern => pattern.test(sourceCode))
    }

    /**
     * Checks for potential access control issues in the contract
     * 
     * This method analyzes the contract for potential access control vulnerabilities
     * by checking for:
     * 1. msg.sender checks in require statements
     * 2. owner/admin checks in require statements
     * 3. onlyOwner/onlyAdmin modifiers
     * 
     * @param sourceCode The Solidity source code of the contract
     * @returns boolean indicating if access control issues are detected
     */
    private static hasAccessControlPattern(sourceCode: string): boolean {
        const accessControlPatterns = [
            /require\([^)]*msg\.sender/i,
            /require\([^)]*owner/i,
            /require\([^)]*admin/i,
            /modifier\s+onlyOwner/i,
            /modifier\s+onlyAdmin/i
        ]

        return accessControlPatterns.some(pattern => pattern.test(sourceCode))
    }

    /**
     * Checks for potential timestamp manipulation patterns in the contract
     * 
     * This method analyzes the contract for potential timestamp manipulation
     * vulnerabilities by checking for:
     * 1. block.timestamp usage
     * 2. now keyword usage
     * 3. timestamp checks in require statements
     * 
     * @param sourceCode The Solidity source code of the contract
     * @returns boolean indicating if timestamp manipulation patterns are detected
     */
    private static hasTimestampManipulationPattern(sourceCode: string): boolean {
        const timestampPatterns = [
            /block\.timestamp/i,
            /now/i,
            /require\([^)]*block\.timestamp/i,
            /require\([^)]*now/i
        ]

        return timestampPatterns.some(pattern => pattern.test(sourceCode))
    }

    /**
     * Checks for potential unchecked external calls in the contract
     * 
     * This method analyzes the contract for potential unchecked external call
     * vulnerabilities by checking for:
     * 1. call.value usage
     * 2. .call usage
     * 3. .send usage
     * 4. .transfer usage
     * 
     * @param sourceCode The Solidity source code of the contract
     * @returns boolean indicating if unchecked external calls are detected
     */
    private static hasUncheckedExternalCallPattern(sourceCode: string): boolean {
        const externalCallPatterns = [
            /call\.value\([^)]*\)/i,
            /\.call\([^)]*\)/i,
            /\.send\([^)]*\)/i,
            /\.transfer\([^)]*\)/i
        ]

        return externalCallPatterns.some(pattern => pattern.test(sourceCode))
    }

    /**
     * Checks for potential delegatecall injection patterns in the contract
     * 
     * This method analyzes the contract for potential delegatecall injection
     * vulnerabilities by checking for:
     * 1. delegatecall usage
     * 2. assembly usage
     * 3. mload/mstore usage
     * 4. calldatacopy/calldataload usage
     * 
     * @param sourceCode The Solidity source code of the contract
     * @returns boolean indicating if delegatecall injection patterns are detected
     */
    private static hasDelegatecallInjectionPattern(sourceCode: string): boolean {
        const delegatecallPatterns = [
            /delegatecall/i,
            /assembly/i,
            /mload/i,
            /mstore/i,
            /calldatacopy/i,
            /calldataload/i
        ]

        return delegatecallPatterns.some(pattern => pattern.test(sourceCode))
    }

    /**
     * Checks for suspicious transaction timing patterns
     */
    private static hasSuspiciousTiming(trace: DetectionRequest['trace']): { isSuspicious: boolean; details: string } {
        // This is a placeholder - in a real implementation, you would:
        // 1. Check transaction timestamp against known patterns
        // 2. Analyze transaction frequency
        // 3. Check for time-based attack patterns
        return { isSuspicious: false, details: '' }
    }

    /**
     * Checks for suspicious contract behavior
     */
    private static hasSuspiciousBehavior(trace: DetectionRequest['trace']): { isSuspicious: boolean; details: string } {
        const suspiciousBehaviors: string[] = []

        // Check for multiple similar function calls
        if (trace.calls && trace.calls.length > 5) {
            const functionCalls = new Map<string, number>()
            trace.calls.forEach(call => {
                if (call.input) {
                    const signature = call.input.slice(0, 10)
                    functionCalls.set(signature, (functionCalls.get(signature) || 0) + 1)
                }
            })

            // If any function is called more than 3 times, it's suspicious
            for (const [signature, count] of functionCalls.entries()) {
                if (count > 3) {
                    suspiciousBehaviors.push(`Repeated function calls detected: ${signature} (${count} times)`)
                }
            }
        }

        // Check for state changes
        const stateChanges = this.analyzeStateChanges(trace)
        if (stateChanges.length > 0) {
            suspiciousBehaviors.push(`Suspicious state changes: ${stateChanges.join(', ')}`)
        }

        if (suspiciousBehaviors.length > 0) {
            return {
                isSuspicious: true,
                details: `Suspicious contract behavior detected: ${suspiciousBehaviors.join(', ')}`
            }
        }

        return { isSuspicious: false, details: '' }
    }

    /**
     * Analyzes state changes in the transaction
     */
    private static analyzeStateChanges(trace: DetectionRequest['trace']): string[] {
        const changes: string[] = []

        // Compare pre and post states
        for (const [address, preState] of Object.entries(trace.pre)) {
            const postState = trace.post[address]
            if (!postState) continue

            // Check for balance changes
            if (preState.balance !== postState.balance) {
                changes.push(`Balance change for ${address}`)
            }

            // Check for nonce changes
            if (preState.nonce !== postState.nonce) {
                changes.push(`Nonce change for ${address}`)
            }

            // Check for code changes
            if (preState.code !== postState.code) {
                changes.push(`Code change for ${address}`)
            }
        }

        return changes
    }
}
