![TypeScript](https://img.shields.io/badge/typescript-%23007ACC.svg?style=for-the-badge&logo=typescript&logoColor=white)
![NodeJS](https://img.shields.io/badge/node.js-6DA55F?style=for-the-badge&logo=node.js&logoColor=white)
![Express.js](https://img.shields.io/badge/express.js-%23404d59.svg?style=for-the-badge&logo=express&logoColor=%2361DAFB)
![Jest](https://img.shields.io/badge/-jest-%23C21325?style=for-the-badge&logo=jest&logoColor=white)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![ESLint](https://img.shields.io/badge/ESLint-4B3263?style=for-the-badge&logo=eslint&logoColor=white)
![Yarn](https://img.shields.io/badge/yarn-%232C8EBB.svg?style=for-the-badge&logo=yarn&logoColor=white)

# Venn Phishing Custom Detector

A sophisticated phishing detection service for the Venn Network that helps protect users from malicious transactions originating from fake dApp interfaces.

## Features

- **Transaction Analysis**
  - Value transfer monitoring
  - Gas price anomaly detection
  - Function signature verification
  - Contract interaction analysis

- **Contract Verification**
  - Etherscan integration for contract verification
  - Source code analysis for verified contracts
  - Caching mechanism for API responses
  - Support for both mainnet and testnet

- **Vulnerability Detection**
  - Reentrancy attacks
  - Front-running attacks
  - Integer overflow/underflow
  - Access control vulnerabilities
  - Timestamp manipulation
  - Unchecked external calls
  - Delegatecall injection
  - Assembly code usage
  - Dangerous opcodes

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/venn-phishing-detector.git
cd venn-phishing-detector
```

2. Install dependencies:
```bash
npm install
```

3. Set up environment variables:
```bash
cp .env.example .env
```
Edit `.env` and add your Etherscan API key:
```
ETHERSCAN_API_KEY=your_api_key_here
NETWORK_TYPE=mainnet  # or testnet
```

## Usage

The detector can be used as part of the Venn Network's security infrastructure:

```typescript
import { DetectionService } from './modules/detection-module/service'
import { DetectionRequest } from './modules/detection-module/dtos'

const request = new DetectionRequest()
request.trace = {
    to: '0x...',
    from: '0x...',
    value: '0x...',
    gas: '0x...',
    gasUsed: '0x...',
    input: '0x...',
    pre: {},
    post: {},
    calls: []
}

const response = await DetectionService.detect(request)
console.log(response.detected, response.message)
```

## Detection Capabilities

### Transaction Analysis
- Monitors for unusual value transfers
- Detects suspicious gas prices
- Verifies function signatures
- Analyzes contract interactions

### Contract Verification
- Checks contract verification status on Etherscan
- Analyzes verified contract source code
- Implements caching for API responses
- Supports multiple networks

### Vulnerability Detection
- **Reentrancy**: Detects potential reentrancy attack patterns
- **Front-running**: Identifies front-running attack vectors
- **Integer Overflow/Underflow**: Checks for unsafe arithmetic operations
- **Access Control**: Identifies potential access control vulnerabilities
- **Timestamp Manipulation**: Detects timestamp-dependent code
- **External Calls**: Identifies unchecked external calls
- **Delegatecall Injection**: Detects potential delegatecall vulnerabilities
- **Assembly Code**: Identifies use of inline assembly
- **Dangerous Opcodes**: Detects use of potentially dangerous EVM opcodes

## Testing

Run the test suite:
```bash
npm test
```

The test suite includes:
- Unit tests for all detection features
- Mocked Etherscan service
- Tests for various vulnerability patterns
- Error handling tests

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Venn Network](https://venn.network/) for providing the platform
- [Etherscan](https://etherscan.io/) for their API
- All contributors who have helped improve this detector

## Table of Contents
- [Introduction](#venn-custom-detector-boilerplate)
- [Quick Start](#quick-start)
- [What's inside?](#-whats-inside)
- [Local development:](#️-local-development)
- [Deploy to production](#-deploy-to-production)

## ✨ Quick start
1. Clone or fork this repo and install dependencies using `yarn install` _(or `npm install`)_
2. Find the detection service under: `src/modules/detection-module/service.ts`

    ```ts
    import { DetectionResponse, DetectionRequest } from './dtos'

    /**
     * DetectionService
     *
     * Implements a `detect` method that receives an enriched view of an
     * EVM compatible transaction (i.e. `DetectionRequest`)
     * and returns a `DetectionResponse`
     *
     * API Reference:
     * https://github.com/ironblocks/venn-custom-detection/blob/master/docs/requests-responses.docs.md
     */
    export class DetectionService {
        /**
         * Update this implementation code to insepct the `DetectionRequest`
         * based on your custom business logic
         */
        public static detect(request: DetectionRequest): DetectionResponse {
            
            /**
             * For this "Hello World" style boilerplate
             * we're mocking detection results using
             * some random value
             */
            const detectionResult = Math.random() < 0.5;


            /**
             * Wrap our response in a `DetectionResponse` object
             */
            return new DetectionResponse({
                request,
                detectionInfo: {
                    detected: detectionResult,
                },
            });
        }
    }
    ```

3. Implement your own logic in the `detect` method
4. Run `yarn dev` _(or `npm run dev`)_
5. That's it! Your custom detector service is now ready to inspect transaction

## 📦 What's inside?
This boilerplate is built using `Express.js`, and written in `TypeScript` using `NodeJS`.  
You can use it as-is by adding your own security logic to it, or as a reference point when using a different programming language.

**Notes on the API**
1. Your detector will get a `DetectionRequest`, and is expected to respond with a `DetectionResponse`

See our [API Reference](https://github.com/ironblocks/venn-custom-detection/blob/master/docs/requests-responses.docs.md) for more information.

## 🛠️ Local Development

**Environment Setup**

Create a `.env` file with:

```bash
PORT=3000
HOST=localhost
LOG_LEVEL=debug
```

**Runing In Dev Mode**
```bash
yarn        # or npm install
yarn dev    # or npm run dev
```

## 🚀 Deploy To Production

**Manual Build**

```bash
yarn build      # or npm run build
yarn start      # or npm run start
```


**Using Docker**
```bash
docker build -f Dockerfile . -t my-custom-detector
```

