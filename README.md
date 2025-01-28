# security-port-scanner
performs a security assessment

Takes a target domain or IP as input
- Validates the input to ensure it's a valid domain or IP address
- Uses nmap to scan for open ports and detect service versions
- Queries the National Vulnerability Database (NVD) for known vulnerabilities
- Provides detailed output including port information and any found vulnerabilities

To use this script:

1. Save it to a file (e.g., SecurityScan.ps1)
2. Make sure you have nmap installed on your system
3. Run it with administrator privileges:

Copy.\SecurityScan.ps1 -Target example.com

Important notes:

- The script requires nmap to be installed
- It needs to be run with administrator privileges
- Make sure you have permission to scan the target system
- The script uses the NVD API, which has rate limits for unauthenticated users
