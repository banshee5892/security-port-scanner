# Requires -RunAsAdministrator
param(
    [Parameter(Mandatory=$true)]
    [string]$Target
)

function Test-ValidTarget {
    param([string]$Target)
    
    # Check if input is IP address
    if ($Target -match "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$") {
        try {
            $ipAddress = [System.Net.IPAddress]::Parse($Target)
            return $true
        }
        catch {
            return $false
        }
    }
    
    # Check if input is domain name
    if ($Target -match "^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$") {
        try {
            $null = [System.Net.Dns]::GetHostEntry($Target)
            return $true
        }
        catch {
            return $false
        }
    }
    
    return $false
}

function Get-OpenPorts {
    param([string]$Target)
    
    # Check if nmap is installed
    if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
        Write-Error "Nmap is not installed. Please install it first."
        return $null
    }
    
    try {
        # Run nmap with version detection
        $nmapOutput = nmap -sV $Target
        
        # Parse nmap output
        $ports = @()
        $currentPort = $null
        
        foreach ($line in $nmapOutput) {
            if ($line -match "^(\d+)/tcp\s+open\s+(\S+)\s*(.*)") {
                $currentPort = @{
                    Port = $matches[1]
                    Service = $matches[2]
                    Version = $matches[3].Trim()
                }
                $ports += $currentPort
            }
        }
        
        return $ports
    }
    catch {
        Write-Error "Error running nmap: $_"
        return $null
    }
}

function Get-VulnerabilityInfo {
    param(
        [string]$Service,
        [string]$Version
    )
    
    try {
        # Query the National Vulnerability Database API
        $baseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        $query = "?keywordSearch=$Service $Version"
        
        $response = Invoke-RestMethod -Uri ($baseUrl + $query) -Method Get
        
        $vulnerabilities = @()
        foreach ($cve in $response.vulnerabilities) {
            $vulnerabilities += @{
                CVE = $cve.cve.id
                Description = $cve.cve.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -ExpandProperty value
                Severity = $cve.cve.metrics.cvssMetricV31.cvssData.baseScore
            }
        }
        
        return $vulnerabilities
    }
    catch {
        Write-Error "Error querying vulnerability database: $_"
        return $null
    }
}

# Main script execution
Write-Host "Starting security scan..." -ForegroundColor Green

# Validate target
if (-not (Test-ValidTarget $Target)) {
    Write-Error "Invalid target specified. Please provide a valid IP address or domain name."
    exit 1
}

# Get open ports
Write-Host "Scanning for open ports..." -ForegroundColor Yellow
$openPorts = Get-OpenPorts $Target

if (-not $openPorts) {
    Write-Host "No open ports found or error occurred during scan." -ForegroundColor Red
    exit 1
}

# Check each port for vulnerabilities
foreach ($port in $openPorts) {
    Write-Host "`nAnalyzing port $($port.Port)..." -ForegroundColor Yellow
    Write-Host "Service: $($port.Service)"
    Write-Host "Version: $($port.Version)"
    
    if ($port.Version) {
        $vulnerabilities = Get-VulnerabilityInfo $port.Service $port.Version
        
        if ($vulnerabilities) {
            Write-Host "`nFound vulnerabilities:" -ForegroundColor Red
            foreach ($vuln in $vulnerabilities) {
                Write-Host "CVE: $($vuln.CVE)" -ForegroundColor Red
                Write-Host "Severity: $($vuln.Severity)"
                Write-Host "Description: $($vuln.Description)"
                Write-Host "-----------------"
            }
        }
        else {
            Write-Host "No known vulnerabilities found for this service version." -ForegroundColor Green
        }
    }
    else {
        Write-Host "Unable to determine version - skipping vulnerability check." -ForegroundColor Yellow
    }
}

Write-Host "`nScan complete!" -ForegroundColor Green
