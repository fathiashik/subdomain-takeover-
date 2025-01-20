# Subdomain Takeover Advanced Script

## Overview

This script checks for potential subdomain takeover vulnerabilities by analyzing DNS records of subdomains. It leverages modern domain discovery APIs and processes subdomains in parallel for faster execution.

## Features

- **Automated Subdomain Enumeration**: Fetches subdomains dynamically using SecurityTrails API.
- **Multiple DNS Record Checks**: Analyzes DNS records (e.g., CNAME) for takeover vulnerabilities.
- **Parallel Processing**: Enhances speed by processing subdomains in parallel.
- **Comprehensive Takeover Patterns**: Maintains an updated list of takeover-prone services.
- **Detailed Output**: Provides a clear report with disclaimers and suggestions.

## Usage

1. **Prepare Your Environment**
    - Ensure [Nmap](https://nmap.org/download.html) is installed on your system.
    - Obtain an API key from SecurityTrails.

2. **Save the Script**
    - Save the `subdomain-takeover-advanced-plus.nse` script file in your Nmap scripts directory (e.g., `/usr/share/nmap/scripts/` on Linux or macOS, `C:\Program Files (x86)\Nmap\scripts` on Windows).

3. **Update the Script**
    - Replace the placeholder text for the API key with your actual SecurityTrails API key:
      ```lua
      local api_key = "YOUR_SECURITYTRAILS_API_KEY"
      ```

4. **Run Nmap with the Script**
    - Open your terminal or command prompt.
    - Run the script using Nmap with the desired target domain(s):
      ```bash
      nmap --script=subdomain-takeover-advanced-plus -p 80,443 <target_domain>
      ```

5. **Analyze the Results**
    - Review the output provided by the script. It will indicate subdomains that might be vulnerable to takeover based on their DNS records.

### Example Output

```plaintext
|subdomain-takeover-advanced-plus:
|  www.example.com: Vulnerable (CNAME points to aws.amazon.com)
|  blog.example.com: Not Vulnerable
|  test.example.com: No DNS records found
