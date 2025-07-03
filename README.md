# 🐞 Bug Bounty Toolkit
Recon is the first and one of the most important steps in bug bounty. It’s all about gathering information on the target—like subdomains, technologies, endpoints, and anything that might help later during testing. Good recon can reveal hidden assets or weak points that others might miss. I usually use tools like Subfinder, Amass, and Nmap, and also do some manual digging with Google dorks and wayback URLs. The better the recon, the better the chances of finding real bugs.

## Must Check links
- [BB checklist](https://nemocyberworld.github.io/BugBountyCheckList/)
- [Recon](https://freedium.cfd/https://medium.com/infosec-ninja/advanced-bug-bounty-recon-playbook-2025-3f1e7dbe3c97)

  ---

## SQL and Recon 
- [SQL kit](https://adce626.github.io/SQLi-Pentest-Toolkit/#dorks)

---

## Web Dorking & Recon

- [DorkGPT](https://www.dorkgpt.com/)
- [Dork Engine](https://dorkengine.github.io/)
- [Google Dork Cheatsheet by Lopseg](https://www.lopseg.com.br/google-dork)

---

## IP Block Bypass

If your IP/localhost is blocked:

- Use **[IPFuscator](https://github.com/vysecurity/IPFuscator)** to obfuscate IP requests.

---

## Web Exploitation Methodologies

- [HackTricks - Web Pentesting Methodology](https://book.hacktricks.wiki/en/pentesting-web/web-vulnerabilities-methodology.html)

---

## JWT Token Decoder

- [JWT.io](https://jwt.io/)

---

## Subdomain Enumeration

`sublist3r -d example.com > sublist3r.txt`

`amass enum -d example.com | cut -d ' ' -f1 > amass.txt`\

`amass enum -d example.com | grep '(FQDN)' | cut -d ' ' -f1 | sort -u > amass_fqdn.txt`

`assetfinder example.com > assetfinder.txt`

`subfinder -d example.com -o subfinder.txt`

`python3 /path/to/knockpy/knockpy.py example.com > knockpy.txt`

`dig example.com > dig.txt`

### Merge All:

`cat *.txt | sort | uniq > merged_subdomains.txt`


##Check Live Subdomains

### Using `httprobe`:

`cat merged_subdomains.txt | httprobe > live.txt`

`cat merged_subdomains.txt | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ' :443' > clean_live.txt`


## Endpoint Discovery

### Hakrawler:

`echo "https://example.com" | hakrawler -subs | tee -a endpoints.txt`

* [GoSpider](https://github.com/jaeles-project/gospider)
* [Katana](https://github.com/projectdiscovery/katana)
* [GoLinkFinder](https://github.com/0xsha/GoLinkFinder)

`GoLinkFinder -d https://example.com | grep api`

##Parameter Discovery

`paramspider -d example.com`

`arjun -u https://example.com`

# Alternative (if above tools fail):
(echo "example.com" | gau --subs; echo "example.com" | waybackurls) | grep '=' 

---

## Directory Bruteforcing

`ffuf -u http://targetsite.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt`

`gobuster dir -u http://targetsite.com/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50 -o gobuster_results.txt`

`python3 dirsearch.py -u http://targetsite.com/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50 -e php,html,txt -o dirsearch_results.txt`

### Recursive Bruteforce:

`ffuf -u http://targetsite.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -recursion`

---

## Wayback Machine URLs

`echo example.com | waybackurls > wayback_urls.txt`

`grep -E "\.php|\.html|\.js" wayback_urls.txt > wayback_results.txt`

`grep "?=" wayback_urls.txt | tee wayback_params.txt`

---

## JavaScript Analysis

`getJS --url https://example.com --output jsfiles.txt`

`jsparser -j jsfiles.txt -o endpoints_from_js.txt`

---

## Tech & CMS Fingerprinting

`whatweb https://example.com`

> 💡 You can also use the [Wappalyzer browser extension](https://www.wappalyzer.com/).

---

## ⚙️Vulnerability Scanning

### Nuclei:

`nuclei -u https://example.com -t ~/.nuclei-templates -o nuclei_results.txt`

`nuclei -u https://example.com -t cves/ -o cve_results.txt`

`nuclei -u https://example.com -t misconfigurations/ -o misconfig_results.txt`

cat urls.txt | nuclei -t technologies/ -o tech_results.txt`

### Invicti:

`invicti -u example.com -o invicti_results.html`

`invicti -u example.com --template "vulnerability_scan_template" -o invicti_custom_scan.html`

---

## 🐞SQL Injection Testing

### Silent:

`sqlmap -u "https://example.com/page.php?id=1" --batch`

### Aggressive:
`sqlmap -u "https://example.com/page.php?id=1" --batch --level=5 --risk=3 --tamper=space2comment,between --technique=BEUSTQ --dbs`


## 🧰 16. Other Vulnerability Scanners & Tools

| Tool                  | Description                     | Link                                                               |
| --------------------- | ------------------------------- | ------------------------------------------------------------------ |
| **Nikto**             | Web server scanner              | [GitHub](https://github.com/sullo/nikto)                           |
| **Arachni**           | Web scanner framework           | [GitHub](https://github.com/Arachni/arachni)                       |
| **w3af**              | Web attack/audit framework      | [GitHub](https://github.com/andresriancho/w3af)                    |
| **Wapiti**            | Blackbox web scanner            | [Site](http://wapiti.sourceforge.net)                              |
| **SecApps**           | In-browser testing suite        | \[Firefox Extension]                                               |
| **WPScan**            | WordPress vulnerability scanner | [wpscan.org](https://wpscan.org/)                                  |
| **Joomscan**          | Joomla scanner                  | [GitHub](https://github.com/rezasp/joomscan)                       |
| **SQLmate**           | SQLi scanner with dorking       | [GitHub](https://github.com/s0md3v/sqlmate)                        |
| **Retire.js**         | JS vulnerability detection      | [GitHub](https://github.com/RetireJS/retire.js)                    |
| **Osmedeus**          | Automated recon framework       | [GitHub](https://github.com/j3ssie/Osmedeus)                       |
| **Sn1per**            | Offensive recon tool            | [GitHub](https://github.com/1N3/Sn1per)                            |
| **Metasploit**        | Exploitation framework          | [GitHub](https://github.com/rapid7/metasploit-framework)           |
| **Jaeles**            | Web app automation scanner      | [GitHub](https://github.com/jaeles-project/jaeles)                 |
| **Backslash Scanner** | Injection vuln finder           | [GitHub](https://github.com/PortSwigger/backslash-powered-scanner) |
| **Cariddi**           | Crawl domains for secrets       | [GitHub](https://github.com/edoardottt/cariddi)                    |
| **Eagle**             | Plugin-based scanner            | [GitHub](https://github.com/BitTheByte/Eagle)                      |
| **ZAP (OWASP)**       | Top open-source scanner         | [GitHub](https://github.com/zaproxy/zaproxy)                       |
| **SSTImap**           | SSTI vuln scanner               | [GitHub](https://github.com/vladko312/SSTImap)                     |
| **Getsploit**         | Search/download exploits        | [GitHub](https://github.com/vulnersCom/getsploit)                  |
| **Findsploit**        | Instantly find exploits         | [GitHub](https://github.com/1N3/Findsploit)                        |
| **BlackWidow**        | OSINT + OWASP fuzzing           | [GitHub](https://github.com/1N3/BlackWidow)                        |

-
