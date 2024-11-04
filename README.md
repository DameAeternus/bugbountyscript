# Bug Bounty Automation Script

This script automates the bug bounty hunting process by discovering subdomains, collecting URLs, and scanning for various vulnerabilities like CORS, SQL injection, and XSS. It leverages several open-source tools to perform comprehensive reconnaissance and vulnerability scanning.

## Features

- **Subdomain Enumeration**: Uses tools like SubFinder and SubEnum.
- **URL Collection**: Collects URLs using `waybackurls` and processes them for further analysis.
- **Vulnerability Scanning**: Detects vulnerabilities such as XSS, SQLi, LFI, and CORS misconfigurations using tools like Nuclei, Dalfox, and SQLMap.
- **CORS Testing**: Automatically checks for CORS misconfigurations.
- **XSS and SQL Injection**: Uses `Dalfox` and `SQLMap` to identify XSS and SQL injection vulnerabilities.

## Prerequisites

Make sure you have Go installed and the necessary tools for the script to function properly.

### Install Go

1. Download and install Go by following the instructions here. For Linux, you can use the following commands:
    
    bash
    
    Copy code

    `sudo apt install golang-go`
    
3. Set up Go in your `~/.zshrc`:
    
    bash
    
    Copy code
    
    `echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc echo 'export GOPATH=$HOME/go' >> ~/.zshrc echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.zshrc source ~/.zshrc`
    
4. Verify Go installation:
    
    bash
    
    Copy code
    
    `go version`
    

### Install Necessary Tools

After Go is set up, you need to install several tools. Use the following commands to install each tool:

#### Subdomain Enumeration

bash

Copy code

`go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`

#### SubEnum (clone and install manually):

bash

Copy code

`git clone https://github.com/bing0o/SubEnum.git`
`cd SubEnum`
`chmod +x setup.sh`
`./setup.sh`

#### Httpx (for probing live subdomains):



sudo apt-install httpx-toolkit

#### Nuclei (for vulnerability scanning):

bash

Copy code

`go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`

Make sure to update nuclei templates with:

bash

Copy code

`nuclei -ut`

#### Dalfox (for XSS testing):

bash

Copy code

`go install github.com/hahwul/dalfox/v2@latest`

#### Gau (Get All URLs):

bash

Copy code

`go install github.com/lc/gau/v2/cmd/gau@latest`

#### Anew (for deduplication):

bash

Copy code

`go install github.com/tomnomnom/anew@latest`

#### Waybackurls (for archived URL collection):

bash

Copy code

`go install github.com/tomnomnom/waybackurls@latest`

#### SQLMap (for SQL injection testing):

bash

Copy code

`sudo apt install sqlmap`

#### Other Tools:

- **QSReplace**:
    
    bash
    
    Copy code
    
    `go install github.com/tomnomnom/qsreplace@latest`
    
- **Uro**:
    
    bash
    
    Copy code
    
    `go install github.com/s0md3v/uro@latest`
    

### Usage

1. Clone this repository:
    
    bash
    
    Copy code
    
    `git clone https://github.com/yourusername/bugbounty-script.git`
    
2. Navigate to the project directory:
    
    bash
    
    Copy code
    
    `cd bugbounty-script`
    
3. Make the script executable:
    
    bash
    
    Copy code
    
    `chmod +x bugbounty.py`
    
4. Run the script:
    
    bash
    
    Copy code
    
    `python3 bugbounty.py <target-domain>`
    

### Tools Summary

- **SubFinder**: For subdomain discovery.
- **SubEnum**: For advanced subdomain enumeration.
- **Httpx**: For probing live subdomains.
- **Nuclei**: For vulnerability scanning using pre-built templates.
- **Dalfox**: For XSS vulnerability detection.
- **Gau**: For retrieving archived URLs.
- **Anew**: For handling duplicate entries.
- **SQLMap**: For automated SQL injection testing.
