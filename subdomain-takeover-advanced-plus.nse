-- subdomain-takeover-advanced-plus.nse
-- This script checks for potential subdomain takeover vulnerabilities by analyzing DNS records of subdomains.

description = [[
Checks for potential subdomain takeover vulnerabilities in a given domain by analyzing DNS records of subdomains.
Automatically fetches subdomains using an external API and processes them in parallel for faster execution.
]]

---
-- @usage
-- nmap --script subdomain-takeover-advanced-plus -p 80,443 <domain>
--
-- @output
-- |subdomain-takeover-advanced-plus:
-- |  www.example.com: Vulnerable (CNAME points to aws.amazon.com)
-- |  blog.example.com: Not Vulnerable
--

author = "ASHIK ABDUL RASHEED"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}

require 'shortport'
require 'stdnse'
require 'dns'
require 'http'
require 'openssl'

-- List of known CNAME patterns for takeover
local takeover_patterns = {
  "aws", "heroku", "github.io", "bitbucket", "shopify", "pageserve.co", "ghost.io",
  "unbouncepages.com", "wordpress.com", "uninstalled.myshopify.com"
}

-- Fetch subdomains using SecurityTrails API (replace with your API key)
local function fetch_subdomains(domain)
  local api_key = "YOUR_SECURITYTRAILS_API_KEY"
  local response = http.get("https://api.securitytrails.com/v1/domain/" .. domain .. "/subdomains", {
    headers = {
      ["Authorization"] = "Bearer " .. api_key
    }
  })

  local subdomains = {}
  if response.status == 200 then
    local json_response = stdnse.from_json(response.body)
    subdomains = json_response.subdomains
  end

  return subdomains
end

portrule = shortport.port_or_service({80, 443}, {"http", "https"})

action = function(host, port)
    local out = {}
    local target_domain = host.targetname
    local subdomains = fetch_subdomains(target_domain)
    local co = stdnse.new_thread(dns.query, table.concat(subdomains, "." .. target_domain))

    for _, sub in ipairs(subdomains) do
        local fqdn = sub .. "." .. target_domain
        local dns_records = dns.query(fqdn, "ANY")
        
        if dns_records then
            for _, record in ipairs(dns_records) do
                for _, pattern in ipairs(takeover_patterns) do
                    if record.cname and record.cname:match(pattern) then
                        table.insert(out, string.format("%s: Vulnerable (CNAME points to %s)", fqdn, record.cname))
                    else
                        table.insert(out, string.format("%s: Not Vulnerable", fqdn))
                    end
                end
            end
        elseif #dns_records == 0 then
            table.insert(out, string.format("%s: No DNS records found", fqdn))
        end
    end
    
    if #out > 0 then
        table.insert(out, "Disclaimer: This script provides a basic analysis. Further validation and mitigations are advised.")
        return stdnse.format_output(false, out)
    end
    
    return "No Potential Takeovers Found\nDisclaimer: This script provides a basic analysis. Further validation and mitigations are advised."
end
