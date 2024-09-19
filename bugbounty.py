import os
import subprocess
import sys
import webbrowser

# Helper function to run shell commands and capture output
def run_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        print(f"Error running command: {command}\n{stderr.decode()}")
        sys.exit(1)
    return stdout.decode()

def google_dorking(domain):
    print("[*] Performing Google Dorking...")

    dorks = [
        f'site:*.{domain} inurl:"*admin | login" | inurl:.php | .asp',
        f'site:*.{domain} intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"',
        f'site:*.{domain} inurl:/geoserver/ows?service=wfs'
    ]

    for dork in dorks:
        print(f"[Dorking] {dork}")
        webbrowser.open(f"https://www.google.com/search?q={dork.replace(' ', '%20')}")


# Subdomain enumeration
def enumerate_subdomains(domain):
    print("[*] Enumerating subdomains...")
    with open('target.txt', 'w') as f:
        f.write(f"{domain}\n")

    # SubFinder
    run_command("subfinder -dL target.txt -all -recursive -o Subs01.txt")

    # SubEnum with various sources
    run_command("~/Desktop/SubEnum/subenum.sh -l target.txt -u wayback,crt,abuseipdb,bufferover,Findomain,Subfinder,Amass,Assetfinder -o Subs02.txt")

    # Combine and remove duplicates
    run_command("cat Subs*.txt | anew | tee AllSubs.txt")

# Probing alive subdomains
def probe_http():
    print("[*] Probing HTTP services on subdomains...")
    run_command("cat AllSubs.txt | httpx-toolkit -o AliveSubs.txt")

# URL collection and analysis
def analyze_urls():
    print("[*] Collecting and analyzing URLs...")
    run_command("cat AliveSubs.txt | waybackurls | tee urls.txt")
    run_command("cat urls.txt | grep '=' | tee param.txt")
    run_command("cat urls.txt | grep -iE '.js' | grep -ivE '.json' | sort -u | tee js.txt")

def nuclei_scanning():
    print("[*] Scanning with Nuclei...")

    # Adding all vulnerability, CVE, and exposure directories
    vulnerabilities = [
        "/home/kali/.local/nuclei-templates/headless/vulnerabilities",
        "/home/kali/.local/nuclei-templates/http/vulnerabilities",
        "/home/kali/.local/nuclei-templates/network/vulnerabilities",
        "/home/kali/.local/nuclei-templates/dast/vulnerabilities"
    ]
    
    cves = [
        "/home/kali/.local/nuclei-templates/code/cves",
        "/home/kali/.local/nuclei-templates/passive/cves",
        "/home/kali/.local/nuclei-templates/headless/cves",
        "/home/kali/.local/nuclei-templates/http/cves",
        "/home/kali/.local/nuclei-templates/network/cves",
        "/home/kali/.local/nuclei-templates/javascript/cves",
        "/home/kali/.local/nuclei-templates/dast/cves"
    ]
    
    exposures = [
        "/home/kali/.local/nuclei-templates/http/exposures",
        "/home/kali/.local/nuclei-templates/network/exposures"
    ]

    # Scanning alive subdomains with nuclei templates
    vuln_templates = ' '.join([f"-t {vuln}" for vuln in vulnerabilities])
    cve_templates = ' '.join([f"-t {cve}" for cve in cves])
    exposure_templates = ' '.join([f"-t {exposure}" for exposure in exposures])

    # Scanning for vulnerabilities
    run_command(f"nuclei -list AliveSubs.txt {vuln_templates} {cve_templates} {exposure_templates}")

# XSS automation
def xss_automation():
    print("[*] Automating XSS detection...")
    run_command("cat urls.txt | uro | gf xss > xss.txt")
    run_command("dalfox file xss.txt | tee XSSvulnerable.txt")

# LFI detection
def lfi_detection():
    print("[*] Detecting LFI vulnerabilities...")
    run_command("cat AliveSubs.txt | gau | uro | gf lfi | tee lfi.txt")
    run_command("nuclei -list target.txt -tags lfi")

def cors_testing(domain):
    print("[*] Testing for CORS vulnerabilities...")
    
    # Escaping curly braces for shell command execution
    command = (
        f"gau {domain} | while read url; "
        f"do target=$(curl -sIH 'Origin: https://evil.com' -X GET $url); "
        f"if echo $target | grep 'https://evil.com'; then echo '[Potential CORS Found] {{url}}'; "
        f"else echo 'Nothing on {{url}}'; fi; done"
    )
    
    run_command(command)

# SQL Injection testing
def sql_injection_testing(domain):
    print("[*] Testing for SQL Injection...")
    run_command(f"python3 ~/Desktop/sqlifinder/sqlifinder.py -d {domain}")
    run_command("sqlmap -m param.txt --batch --random-agent --level 1 | tee sqlmap.txt")

# Open Redirect detection
def open_redirect_detection():
    print("[*] Detecting Open Redirects...")
    run_command("cat urls.txt | grep -a -i =http | qsreplace 'evil.com' | while read host do;do curl -s -L $host -I| grep 'evil.com' && echo \"$host \033[0;31mVulnerable\n\" ;done")

# Main function
def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <target-domain>")
        sys.exit(1)

    domain = sys.argv[1]

    # Running all tasks sequentially
    google_dorking(domain)
    enumerate_subdomains(domain)
    probe_http()
    analyze_urls()
    nuclei_scanning()
    xss_automation()
    lfi_detection()
    cors_testing(domain)
    sql_injection_testing(domain)
    open_redirect_detection()

if __name__ == "__main__":
    main()
