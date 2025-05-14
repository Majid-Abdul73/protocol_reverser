# Protocol Reverser

A Go-based network protocol analysis tool that captures, analyzes, and optionally obfuscates network traffic. This tool is designed for network protocol analysis and reverse engineering.

## Features

- **Packet Capture**: Captures network packets from specified network interfaces
- **Protocol Analysis**: Analyzes network protocols by detecting common patterns:
  - Header detection
  - Length field identification
  - Delimiter recognition
- **Traffic Obfuscation**: Includes capabilities to obfuscate network traffic:
  - AES encryption
  - Jitter data insertion
  - Packet chunking with markers
  - PKCS7 padding

## Prerequisites

- Go 1.24.3 or later
- Npcap (Windows) or libpcap (Linux/macOS)
- Administrator/root privileges for packet capture

## Installation

1. Install Npcap (Windows) or libpcap (Linux/macOS)
2. Clone the repository
3. Install dependencies:
```bash
go mod tidy

## Usage
### List Available Network Interfaces
bash
go run main.go -l


### Capture Packets
go run main.go -i "interface-name" -promisc=true -f "tcp port 80"


Parameters:

- -i : Network interface name
- -s : Snapshot length (default: 1024)
- -promisc : Enable promiscuous mode (default: true)
- -f : BPF filter string
- -l : List available interfaces
## Project Structure
- main.go : Main application entry point and packet capture logic
- analyzer/protocol_analyzer.go : Protocol analysis implementation
- obfuscator/obfuscator.go : Traffic obfuscation functionality
## License

MIT License

Copyright (c) 2024 Protocol Reverser

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Contributing
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request