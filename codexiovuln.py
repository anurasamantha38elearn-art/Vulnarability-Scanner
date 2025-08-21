#!/usr/bin/env python3

import os
import argparse
import requests
import socket
import ssl
import json
import csv
import sys
import random
import threading
import time
import re
import dns.resolver
from urllib.parse import urlparse, quote, unquote
from datetime import datetime
from bs4 import BeautifulSoup
import google.generativeai as genai

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except:
    pass


# API key should be set via environment variable
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

BANNER = """
\033[1;33m
                             ___====-_  _-====___
                      _--^^^#####//      \\#####^^^--_
                   _-^##########// (    ) \\##########^-_
                  -############//  |\^^/|  \\############-
                _/############//   (@::@)   \\############\_
               /#############((     \\//     ))#############\
              -###############\\    (oo)    //###############-
             -#################\\  / VV \  //#################-
            -###################\\/      \//###################-
          _#/|##########/\######(   /\   )######/\##########|\#_
          |/ |#/\#/\#/\/  \#/\##\  |  |  /##/\#/  \/\#/\#/\#| \|
          `  |/  V  V  `   V  \#\| |  | |/#/  V   '  V  V  \|  '
              `   `  `      `   / | |  | | \   '      '  '   '
                              (  | |  | |  )
                             __\ | |  | | /__
                           (vv C O D E X I O vv)

           ██████╗ ██████╗ ██████╗ ███████╗██╗  ██╗██╗ ██████╗
          ██╔════╝██╔═══██╗██╔══██╗██╔════╝╚██╗██╔╝██║██╔═══██╗
          ██║     ██║   ██║██║  ██║█████╗   ╚███╔╝ ██║██║   ██║
          ██║     ██║   ██║██║  ██║██╔══╝   ██╔██╗ ██║██║   ██║
          ╚██████╗╚██████╔╝██████╔╝███████╗██╔╝ ██╗██║╚██████╔╝
           ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝
              AI Powered Advanced Web Application Vulnerability Scanner

\033[1;32m   A N A L Y Z E R\033[0m          \033[1;33m|___/\033[0m

\033[1;36mAdvanced Web Application Vulnerability Scanner\033[0m
\033[1;31mCodexio Web New!\033[0m
\033[1;35mEnhanced with Google Gemini AI Vulnerability Analysis\033[0m
"""

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def display_banner():
    clear_screen()
    print(BANNER)

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

class AdvancedScanner:
    def __init__(self, target, output_format=None, output_file=None,
                 use_ssl=False, port=None, timeout=10, user_agent=None,
                 threads=5, delay=0, cookies=None, headers=None,
                 auth=None, proxy=None, follow_redirects=True,
                 scan_level=2, plugins=None, gemini_analysis=False,
                 debug=False):

        self.target = target
        self.output_format = output_format
        self.output_file = output_file
        self.use_ssl = use_ssl
        self.port = port
        self.timeout = timeout
        self.user_agent = user_agent or self.get_random_user_agent()
        self.threads = threads
        self.delay = delay
        self.cookies = cookies
        self.headers = headers or {}
        self.auth = auth
        self.proxy = proxy
        self.follow_redirects = follow_redirects
        self.scan_level = scan_level
        self.plugins = plugins or ["common_files", "common_dirs", "xss", "sqli", "rce"]
        self.gemini_analysis = gemini_analysis
        self.debug = debug

        # Security check for API key
        if self.gemini_analysis and not GEMINI_API_KEY:
            print("\033[1;31m[!] ERROR: GEMINI_API_KEY environment variable not set\033[0m")
            print("\033[1;33m[!] To use AI analysis, set your API key: export GEMINI_API_KEY='your_key_here'\033[0m")
            self.gemini_analysis = False

        self.results = []
        self.vulnerability_report = []
        self.session = requests.Session()
        self.session.verify = False
        self.session.max_redirects = 10 if follow_redirects else 0

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        if auth:
            self.session.auth = auth

        if not self.port:
            self.port = 443 if self.use_ssl else 80

        scheme = "https" if self.use_ssl else "http"
        self.base_url = f"{scheme}://{self.target}:{self.port}"

        self.checks = self.load_checks()

        self.vuln_signatures = self.load_vulnerability_signatures()

        self.test_headers = [
            "X-Forwarded-For",
            "X-Client-IP",
            "X-Remote-IP",
            "X-Originating-IP",
            "X-Remote-Addr",
            "X-Real-IP",
        ]

    def get_random_user_agent(self):
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        ]
        return random.choice(user_agents)

    def load_checks(self):
        checks = []

        common_files = [
            {"id": 1, "path": "/admin/", "description": "Admin directory"},
            {"id": 2, "path": "/phpinfo.php", "description": "PHPInfo file"},
            {"id": 3, "path": "/test/", "description": "Test directory"},
            {"id": 4, "path": "/backup/", "description": "Backup directory"},
            {"id": 5, "path": "/.git/", "description": "Git repository"},
            {"id": 6, "path": "/.env", "description": "Environment file"},
            {"id": 7, "path": "/wp-admin/", "description": "WordPress admin"},
            {"id": 8, "path": "/server-status", "description": "Server status"},
            {"id": 9, "path": "/.DS_Store", "description": "DS_Store file"},
            {"id": 10, "path": "/config.php", "description": "Configuration file"},
            {"id": 11, "path": "/robots.txt", "description": "Robots.txt file"},
            {"id": 12, "path": "/.htaccess", "description": "HTAccess file"},
            {"id": 13, "path": "/phpmyadmin/", "description": "phpMyAdmin"},
            {"id": 14, "path": "/mysql/", "description": "MySQL admin"},
            {"id": 15, "path": "/db/", "description": "Database directory"},
            {"id": 16, "path": "/backup.sql", "description": "Database backup"},
            {"id": 17, "path": "/upload/", "description": "Upload directory"},
            {"id": 18, "path": "/cgi-bin/", "description": "CGI bin directory"},
            {"id": 19, "path": "/admin/login.php", "description": "Admin login"},
            {"id": 20, "path": "/wp-login.php", "description": "WordPress login"},
        ]

        medium_checks = [
            {"id": 21, "path": "/.svn/", "description": "SVN repository"},
            {"id": 22, "path": "/.bash_history", "description": "Bash history"},
            {"id": 23, "path": "/.ssh/", "description": "SSH directory"},
            {"id": 24, "path": "/.ftpconfig", "description": "FTP configuration"},
            {"id": 25, "path": "/.well-known/", "description": "Well-known directory"},
            {"id": 26, "path": "/crossdomain.xml", "description": "Crossdomain policy"},
            {"id": 27, "path": "/clientaccesspolicy.xml", "description": "Client access policy"},
            {"id": 28, "path": "/.idea/", "description": "IDE configuration"},
            {"id": 29, "path": "/web.config", "description": "ASP.NET configuration"},
            {"id": 30, "path": "/appsettings.json", "description": "App configuration"},
        ]

        high_checks = [
            {"id": 31, "path": "/../../../../etc/passwd", "description": "Path traversal test"},
            {"id": 32, "path": "/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "description": "URL-encoded path traversal"},
            {"id": 33, "path": "/..\\..\\..\\..\\windows\\win.ini", "description": "Windows path traversal"},
            {"id": 34, "path": "/proc/self/environ", "description": "Proc environment"},
            {"id": 35, "path": "/includes/", "description": "Includes directory"},
            {"id": 36, "path": "/.git/config", "description": "Git configuration"},
            {"id": 37, "path": "/.env.bak", "description": "Environment backup"},
            {"id": 38, "path": "/wp-config.php", "description": "WordPress configuration"},
            {"id": 39, "path": "/wp-config.php.bak", "description": "WordPress config backup"},
            {"id": 40, "path": "/.htpasswd", "description": "Password file"},
        ]

        checks.extend(common_files)
        if self.scan_level >= 2:
            checks.extend(medium_checks)
        if self.scan_level >= 3:
            checks.extend(high_checks)

        return checks

    def load_vulnerability_signatures(self):
        return {
            "sql_errors": [
                "sql syntax.*mysql",
                "warning.*mysql",
                "mysql_fetch_array",
                "mysqli_fetch_array",
                "postgresql.*error",
                "ora-.*error",
                "microsoft.*odbc.*driver",
                "sqlserver.*driver",
                "syntax error.*sql",
                "unclosed quotation mark",
                "you have an error in your sql syntax",
            ],
            "xss_patterns": [
                "alert\\(",
                "script.*src=",
                "onerror=",
                "onload=",
                "onmouseover=",
                "javascript:",
                "eval\\(",
                "document\\.cookie",
            ],
            "rce_patterns": [
                "root:.*:0:0:",
                "\\bin\\bash",
                "\\bin\\sh",
                "etc/passwd",
                "etc/shadow",
                "command.*executed",
                "system\\(",
                "exec\\(",
                "passthru\\(",
                "shell_exec\\(",
            ]
        }

    def get_server_info(self):
        try:
            headers = {'User-Agent': self.user_agent}
            response = self.session.get(self.base_url, headers=headers, timeout=self.timeout)
            server = response.headers.get('Server', 'Unknown')
            powered_by = response.headers.get('X-Powered-By', 'Not specified')
            return f"Server: {server}, Powered By: {powered_by}"
        except Exception as e:
            return f"Server information not available: {str(e)}"

    def check_ssl(self):
        if not self.use_ssl:
            return "Not using SSL"

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    valid_from = cert.get('notBefore', 'Unknown')
                    valid_to = cert.get('notAfter', 'Unknown')
                    return f"SSL Certificate: Issuer: {issuer.get('organizationName', 'Unknown')}, " \
                           f"Subject: {subject.get('commonName', 'Unknown')}, " \
                           f"Valid From: {valid_from}, Valid To: {valid_to}"
        except Exception as e:
            return f"SSL Error: {str(e)}"

    def dns_enumerate(self):
        try:
            print("\033[1;33m[*] Starting DNS enumeration...\033[0m")

            subdomains = [
                "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
                "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
                "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
                "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
                "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
                "web", "media", "email", "images", "img", "www1", "intranet", "portal", "video",
                "server", "ftp", "monitor", "help", "api", "search", "site", "mssql", "remote",
                "files", "host", "image", "ssl", "proxy", "dns", "music", "chat", "upload",
                "download", "cdn", "firewall", "crm", "dns1", "dns2", "dns3", "dns4", "dns5"
            ]

            found_subdomains = []
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            for sub in subdomains:
                try:
                    domain = f"{sub}.{self.target}"
                    answers = resolver.resolve(domain, 'A')
                    for answer in answers:
                        found_subdomains.append(f"{domain} -> {answer.address}")
                        print(f"\033[1;32m[+] Found subdomain: {domain} -> {answer.address}\033[0m")
                except:
                    pass

            return found_subdomains
        except Exception as e:
            print(f"\033[1;31m[!] DNS enumeration error: {str(e)}\033[0m")
            return []

    def check_http_methods(self):
        try:
            methods = ["OPTIONS", "TRACE", "PUT", "DELETE", "CONNECT", "PATCH"]
            dangerous_methods = []

            for method in methods:
                try:
                    response = self.session.request(
                        method,
                        self.base_url,
                        timeout=self.timeout,
                        headers={'User-Agent': self.user_agent}
                    )
                    if response.status_code < 400:
                        dangerous_methods.append(method)
                        print(f"\033[1;33m[~] Potentially dangerous HTTP method allowed: {method}\033[0m")
                except:
                    pass

            return dangerous_methods
        except Exception as e:
            print(f"\033[1;31m[!] HTTP methods check error: {str(e)}\033[0m")
            return []

    def check_security_headers(self):
        try:
            headers_to_check = [
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "X-XSS-Protection",
                "Content-Security-Policy",
                "Referrer-Policy",
                "Feature-Policy",
                "Permissions-Policy"
            ]

            missing_headers = []
            response = self.session.get(self.base_url, timeout=self.timeout)

            for header in headers_to_check:
                if header not in response.headers:
                    missing_headers.append(header)
                    print(f"\033[1;33m[~] Missing security header: {header}\033[0m")

            return missing_headers
        except Exception as e:
            print(f"\033[1;31m[!] Security headers check error: {str(e)}\033[0m")
            return []

    def test_xss_vulnerabilities(self):
        try:
            test_payloads = [
                "<script>alert('XSS')</script>",
                "\"><script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "onload=alert('XSS')",
                "onerror=alert('XSS')"
            ]

            vulnerable_params = []
            response = self.session.get(self.base_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form')
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                inputs = form.find_all('input')

                form_params = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name:
                        value = input_tag.get('value', '') + random.choice(test_payloads)
                        form_params[name] = value

                try:
                    target_url = urlparse(self.base_url)
                    full_url = f"{target_url.scheme}://{target_url.netloc}{form_action}"

                    if form_method == 'post':
                        response = self.session.post(full_url, data=form_params, timeout=self.timeout)
                    else:
                        response = self.session.get(full_url, params=form_params, timeout=self.timeout)

                    for payload in test_payloads:
                        if payload in response.text:
                            vulnerable_params.append({
                                "form": form_action,
                                "payload": payload,
                                "method": form_method
                            })
                            print(f"\033[1;31m[!] Potential XSS vulnerability found in form: {form_action}\033[0m")
                            break
                except:
                    continue

            return vulnerable_params
        except Exception as e:
            print(f"\033[1;31m[!] XSS test error: {str(e)}\033[0m")
            return []

    def test_sql_injection(self):
        try:
            test_payloads = [
                "'",
                "';",
                "' OR '1'='1",
                "' OR 1=1--",
                "') OR ('1'='1",
                "admin'--",
                "1' ORDER BY 1--",
                "1' UNION SELECT 1,2,3--"
            ]

            vulnerable_params = []
            response = self.session.get(self.base_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form')
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                inputs = form.find_all('input')

                for payload in test_payloads:
                    form_params = {}
                    for input_tag in inputs:
                        name = input_tag.get('name')
                        if name:
                            form_params[name] = payload

                    try:
                        target_url = urlparse(self.base_url)
                        full_url = f"{target_url.scheme}://{target_url.netloc}{form_action}"

                        if form_method == 'post':
                            response = self.session.post(full_url, data=form_params, timeout=self.timeout)
                        else:
                            response = self.session.get(full_url, params=form_params, timeout=self.timeout)

                        for pattern in self.vuln_signatures["sql_errors"]:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                vulnerable_params.append({
                                    "form": form_action,
                                    "payload": payload,
                                    "method": form_method
                                })
                                print(f"\033[1;31m[!] Potential SQL injection vulnerability found in form: {form_action}\033[0m")
                                break
                    except:
                        continue

            return vulnerable_params
        except Exception as e:
            print(f"\033[1;31m[!] SQL injection test error: {str(e)}\033[0m")
            return []

    def check_for_vulnerabilities(self, url, response):
        vulnerabilities = []
        content = response.text.lower()

        for pattern in self.vuln_signatures["sql_errors"]:
            if re.search(pattern, content, re.IGNORECASE):
                vulnerabilities.append({"type": "SQL_ERROR", "pattern": pattern})

        for pattern in self.vuln_signatures["xss_patterns"]:
            if re.search(pattern, content, re.IGNORECASE):
                vulnerabilities.append({"type": "XSS_PATTERN", "pattern": pattern})

        for pattern in self.vuln_signatures["rce_patterns"]:
            if re.search(pattern, content, re.IGNORECASE):
                vulnerabilities.append({"type": "RCE_PATTERN", "pattern": pattern})

        return vulnerabilities

    def analyze_with_gemini(self, vulnerability_data):
        """Analyze vulnerabilities using Google Gemini API and generate solutions"""
        if not GEMINI_API_KEY:
            print("\033[1;33m[~] Google Gemini API key not found. Skipping AI analysis.\033[0m")
            return "AI analysis skipped - API key not configured"

        try:
            print(f"\033[1;35m[*] Sending request to Google Gemini API for {vulnerability_data.get('type')}...\033[0m")

            genai.configure(api_key=GEMINI_API_KEY)
            model = genai.GenerativeModel('gemini-pro')

            # Create a more detailed prompt for better solutions
            prompt = f"""
You are a web security expert. Analyze the following vulnerability and provide a detailed solution:

Vulnerability Type: {vulnerability_data.get('type', 'Unknown')}
URL: {vulnerability_data.get('url', 'Unknown')}
Description: {vulnerability_data.get('description', 'No description')}
Details: {vulnerability_data.get('details', 'No details')}
Severity: {vulnerability_data.get('severity', 'Unknown')}

Please provide:
1. A brief explanation of the vulnerability.
2. The potential impact if exploited.
3. Step-by-step remediation advice.
4. Code examples for fixing the issue (if applicable).
5. Preventive measures for the future.
6. Short-term solutions that can be implemented immediately.
7. Long-term security measures.

Format the response in clear sections.
"""

            response = model.generate_content(prompt)

            if self.debug:
                print(f"\033[1;36m[DEBUG] API Response: {response.text}\033[0m")

            return response.text

        except Exception as e:
            print(f"\033[1;31m[!] Google Gemini API error: {str(e)}\033[0m")
            return f"API Error: {str(e)}"

    def generate_vulnerability_report(self):
        """Generate comprehensive vulnerability report with AI analysis"""
        if not self.vulnerability_report:
            print("\033[1;33m[~] No vulnerabilities found to report\033[0m")
            return

        print("\n\033[1;35m" + "="*80 + "\033[0m")
        print("\033[1;35m                  VULNERABILITY ANALYSIS REPORT\033[0m")
        print("\033[1;35m" + "="*80 + "\033[0m")

        for i, vuln in enumerate(self.vulnerability_report, 1):
            print(f"\n\033[1;36m[{i}] {vuln['type']} Vulnerability - {vuln.get('severity', 'Unknown')}\033[0m")
            print(f"   URL: {vuln['url']}")
            print(f"   Description: {vuln['description']}")
            print(f"   Details: {vuln.get('details', 'No details')}")

            if self.gemini_analysis and vuln.get('ai_analysis'):
                if vuln['ai_analysis'].startswith("Error") or "failed" in vuln['ai_analysis'].lower():
                    print(f"\n\033[1;31m   AI Analysis Failed: {vuln['ai_analysis']}\033[0m")
                else:
                    print(f"\n\033[1;33m   AI Analysis and Solutions:\033[0m")
                    # Split analysis into manageable chunks
                    analysis_lines = vuln['ai_analysis'].split('\n')
                    for line in analysis_lines:
                        if line.strip():
                            print(f"   {line}")
            else:
                print(f"\n\033[1;33m   Manual Investigation Required\033[0m")
                print(f"   No AI analysis available for this vulnerability")

            print("\033[1;35m" + "-"*80 + "\033[0m")

    def run_checks(self):
        print(f"\n\033[1;33m[*] Scanning {self.target}:{self.port}\033[0m")
        print(f"\033[1;33m[*] {self.get_server_info()}\033[0m")
        print(f"\033[1;33m[*] {self.check_ssl()}\033[0m")
        print(f"\033[1;33m[*] Using {self.threads} threads with scan level {self.scan_level}\033[0m")

        if self.gemini_analysis:
            print("\033[1;35m[*] Google Gemini AI analysis enabled\033[0m")

        print("\033[1;33m[*] Starting comprehensive vulnerability assessment...\033[0m")

        # Test API connection first if AI analysis is enabled
        if self.gemini_analysis:
            test_result = self.analyze_with_gemini({
                "type": "TEST",
                "url": "http://test.com",
                "description": "Test connection",
                "details": "Testing API connectivity",
                "severity": "Info"
            })
            if "Error" in test_result or "timeout" in test_result.lower():
                print(f"\033[1;31m[!] API connection test failed: {test_result}\033[0m")
                print("\033[1;33m[!] Continuing scan without AI analysis\033[0m")
                self.gemini_analysis = False
            else:
                print("\033[1;32m[+] API connection test successful\033[0m")

        if "dns_enum" in self.plugins:
            self.dns_enumerate()

        if "http_methods" in self.plugins:
            self.check_http_methods()

        if "security_headers" in self.plugins:
            self.check_security_headers()

        if "xss" in self.plugins:
            xss_results = self.test_xss_vulnerabilities()
            for result in xss_results:
                self.vulnerability_report.append({
                    "type": "XSS",
                    "url": self.base_url + result["form"],
                    "description": f"Cross-Site Scripting vulnerability in form",
                    "details": f"Method: {result['method']}, Payload: {result['payload']}",
                    "severity": "High"
                })

        if "sqli" in self.plugins:
            sqli_results = self.test_sql_injection()
            for result in sqli_results:
                self.vulnerability_report.append({
                    "type": "SQL Injection",
                    "url": self.base_url + result["form"],
                    "description": "SQL injection vulnerability in form",
                    "details": f"Method: {result['method']}, Payload: {result['payload']}",
                    "severity": "Critical"
                })

        if "common_files" in self.plugins or "common_dirs" in self.plugins:
            print("\033[1;33m[*] Starting directory and file checks...\033[0m")
            for check in self.checks:
                url = self.base_url + check["path"]
                try:
                    headers = {'User-Agent': self.user_agent}
                    response = self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=False)

                    if response.status_code == 200:
                        vulns = self.check_for_vulnerabilities(url, response)

                        result = {
                            "id": check["id"],
                            "url": url,
                            "description": check["description"],
                            "status": response.status_code,
                            "size": len(response.content),
                            "vulnerabilities": vulns
                        }
                        self.results.append(result)

                        if vulns:
                            print(f"\033[1;31m[!] Found: {check['description']} at {url} with {len(vulns)} potential vulnerabilities\033[0m")

                            # Add to vulnerability report
                            for vuln in vulns:
                                self.vulnerability_report.append({
                                    "type": vuln["type"],
                                    "url": url,
                                    "description": check["description"],
                                    "details": f"Pattern matched: {vuln['pattern']}",
                                    "severity": "High" if vuln["type"] in ["SQL_ERROR", "RCE_PATTERN"] else "Medium"
                                })
                        else:
                            print(f"\033[1;32m[+] Found: {check['description']} at {url}\033[0m")

                    elif response.status_code in [301, 302, 307, 308]:
                        result = {
                            "id": check["id"],
                            "url": url,
                            "description": f"{check['description']} (Redirects to {response.headers.get('Location', 'Unknown')})",
                            "status": response.status_code,
                            "size": len(response.content),
                            "vulnerabilities": []
                        }
                        self.results.append(result)
                        print(f"\033[1;33m[~] Redirect: {check['description']} at {url}\033[0m")

                    if self.delay > 0:
                        time.sleep(self.delay)

                except requests.exceptions.RequestException as e:
                    print(f"\033[1;31m[!] Error checking {url}: {str(e)}\033[0m")

        # Perform AI analysis if enabled
        if self.gemini_analysis and self.vulnerability_report:
            print("\n\033[1;35m[*] Starting AI-powered vulnerability analysis with Google Gemini...\033[0m")
            for i, vuln in enumerate(self.vulnerability_report):
                if vuln['severity'] in ['High', 'Critical', 'Medium']:
                    print(f"\033[1;35m[*] Analyzing {vuln['type']} vulnerability ({i+1}/{len(self.vulnerability_report)})...\033[0m")
                    analysis = self.analyze_with_gemini(vuln)
                    if analysis and "Error" not in analysis:
                        vuln['ai_analysis'] = analysis
                    else:
                        vuln['ai_analysis'] = "Analysis failed - " + analysis
                    # Better rate limiting
                    time.sleep(2 if i % 5 == 0 else 0.5)

        print(f"\033[1;33m[*] Scan completed. Found {len(self.results)} potential issues.\033[0m")
        print(f"\033[1;31m[*] Found {len(self.vulnerability_report)} vulnerabilities.\033[0m")

        # Generate vulnerability report
        self.generate_vulnerability_report()

    def save_results(self):
        if not self.output_file:
            return

        try:
            if self.output_format == "txt":
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    f.write(f"Advanced Security Scan Report for {self.target}\n")
                    f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Scan Level: {self.scan_level}\n")
                    f.write("="*70 + "\n\n")

                    for result in self.results:
                        f.write(f"[{result['id']}] {result['description']}\n")
                        f.write(f"URL: {result['url']}\n")
                        f.write(f"Status: {result['status']}, Size: {result['size']} bytes\n")

                        if result['vulnerabilities']:
                            f.write("Potential Vulnerabilities:\n")
                            for vuln in result['vulnerabilities']:
                                f.write(f"  - {vuln['type']}: {vuln['pattern']}\n")

                        f.write("\n")

                    # Add vulnerability report section
                    if self.vulnerability_report:
                        f.write("\n" + "="*70 + "\n")
                        f.write("VULNERABILITY ANALYSIS REPORT\n")
                        f.write("="*70 + "\n\n")

                        for i, vuln in enumerate(self.vulnerability_report, 1):
                            f.write(f"[{i}] {vuln['type']} Vulnerability - {vuln.get('severity', 'Unknown')}\n")
                            f.write(f"URL: {vuln['url']}\n")
                            f.write(f"Description: {vuln['description']}\n")
                            f.write(f"Details: {vuln.get('details', 'No details')}\n")

                            if vuln.get('ai_analysis'):
                                f.write(f"\nAI Analysis and Solutions:\n{vuln['ai_analysis']}\n")

                            f.write("\n" + "-"*50 + "\n\n")

            elif self.output_format == "json":
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    report_data = {
                        "target": self.target,
                        "timestamp": datetime.now().isoformat(),
                        "scan_level": self.scan_level,
                        "results": self.results,
                        "vulnerabilities": self.vulnerability_report
                    }
                    json.dump(report_data, f, indent=2, ensure_ascii=False)

            elif self.output_format == "csv":
                with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['ID', 'URL', 'Description', 'Status', 'Size', 'Vulnerabilities'])
                    for result in self.results:
                        vuln_str = "; ".join([f"{v['type']}:{v['pattern']}" for v in result['vulnerabilities']])
                        writer.writerow([
                            result['id'],
                            result['url'],
                            result['description'],
                            result['status'],
                            result['size'],
                            vuln_str
                        ])

                    # Add vulnerability report section
                    if self.vulnerability_report:
                        writer.writerow([])
                        writer.writerow(['VULNERABILITY REPORT'])
                        writer.writerow(['Type', 'URL', 'Description', 'Severity', 'Details', 'AI_Solutions'])
                        for vuln in self.vulnerability_report:
                            writer.writerow([
                                vuln['type'],
                                vuln['url'],
                                vuln['description'],
                                vuln.get('severity', ''),
                                vuln.get('details', ''),
                                vuln.get('ai_analysis', 'No AI analysis')
                            ])

            print(f"\033[1;32m[*] Results saved to {self.output_file} in {self.output_format} format\033[0m")

        except Exception as e:
            print(f"\033[1;31m[!] Error saving results: {str(e)}\033[0m")

def main():
    display_banner()

    parser = argparse.ArgumentParser(description="Advanced Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", help="Target URL to scan (e.g., http://example.com)")
    parser.add_argument("-H", "--host", help="Target host to scan")
    parser.add_argument("-p", "--port", type=int, help="Port to scan (default: 80 or 443)")
    parser.add_argument("-s", "--ssl", action="store_true", help="Use SSL/TLS")
    parser.add_argument("-o", "--output", help="Output file name")
    parser.add_argument("-f", "--format", choices=["txt", "json", "csv"],
                       help="Output format (default: txt)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                       help="Timeout in seconds (default: 10)")
    parser.add_argument("-a", "--user-agent", help="Custom User-Agent string")
    parser.add_argument("-T", "--threads", type=int, default=5,
                       help="Number of threads (default: 5)")
    parser.add_argument("-d", "--delay", type=float, default=0,
                       help="Delay between requests in seconds (default: 0)")
    parser.add_argument("--cookies", help="Cookies to use (format: key1=value1;key2=value2)")
    parser.add_argument("--headers", help="Additional headers (format: key1:value1;key2:value2)")
    parser.add_argument("--auth", help="HTTP authentication (format: username:password)")
    parser.add_argument("--proxy", help="Proxy server (format: http://proxy:port)")
    parser.add_argument("--no-redirects", action="store_true", help="Do not follow redirects")
    parser.add_argument("--level", type=int, choices=[1, 2, 3], default=2,
                       help="Scan intensity level: 1=Low, 2=Medium, 3=High (default: 2)")
    parser.add_argument("--plugins", help="Comma-separated list of plugins to enable")
    parser.add_argument("--ai-analysis", action="store_true",
                       help="Enable AI-powered vulnerability analysis with Google Gemini")
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug mode for detailed output")

    if len(sys.argv) == 1:
        parser.print_help()
        print("\n\033[1;36mInteractive mode:\033[0m")
        url = input("\n\033[1;37mEnter the target URL (e.g., http://example.com) or 'q' to quit: \033[0m")

        if url.lower() == 'q':
            print("\n\033[1;31mExiting Advanced Web Analyzer...\033[0m")
            return

        if not is_valid_url(url):
            print("\033[1;31mInvalid URL format. Please include http:// or https://\033[0m")
            return

        parsed_url = urlparse(url)
        host = parsed_url.netloc
        use_ssl = parsed_url.scheme == 'https'
        port = parsed_url.port if parsed_url.port else (443 if use_ssl else 80)

        output = input("\n\033[1;37mEnter output file name (or press Enter to skip): \033[0m")
        if output:
            format_choice = input("\n\033[1;37mEnter output format (txt, json, csv) [txt]: \033[0m") or "txt"
        else:
            format_choice = None

        level_choice = input("\n\033[1;37mEnter scan level (1-3) [2]: \033[0m") or "2"
        try:
            level_choice = int(level_choice)
            if level_choice not in [1, 2, 3]:
                level_choice = 2
        except:
            level_choice = 2

        ai_analysis = input("\n\033[1;37mEnable AI analysis with Google Gemini? (y/n) [n]: \033[0m").lower() == 'y'
        debug_mode = input("\n\033[1;37mEnable debug mode? (y/n) [n]: \033[0m").lower() == 'y'

        scanner = AdvancedScanner(
            target=host,
            output_format=format_choice,
            output_file=output,
            use_ssl=use_ssl,
            port=port,
            timeout=10,
            scan_level=level_choice,
            gemini_analysis=ai_analysis,
            debug=debug_mode
        )
    else:
        args = parser.parse_args()

        if args.url:
            if not is_valid_url(args.url):
                print("\033[1;31mInvalid URL format. Please include http:// or https://\033[0m")
                return
            parsed_url = urlparse(args.url)
            host = parsed_url.netloc
            use_ssl = parsed_url.scheme == 'https'
            port = parsed_url.port if parsed_url.port else (443 if use_ssl else 80)
        elif args.host:
            host = args.host
            use_ssl = args.ssl
            port = args.port
        else:
            print("\033[1;31mYou must specify either a URL with -u/--url or a host with -H/--host\033[0m")
            return

        if not port:
            port = 443 if use_ssl else 80

        if args.output and not args.format:
            args.format = "txt"

        cookies = {}
        if args.cookies:
            for cookie in args.cookies.split(';'):
                if '=' in cookie:
                    key, value = cookie.split('=', 1)
                    cookies[key.strip()] = value.strip()

        headers = {}
        if args.headers:
            for header in args.headers.split(';'):
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()

        auth = None
        if args.auth:
            if ':' in args.auth:
                username, password = args.auth.split(':', 1)
                auth = (username.strip(), password.strip())

        plugins = None
        if args.plugins:
            plugins = [p.strip() for p in args.plugins.split(',')]

        scanner = AdvancedScanner(
            target=host,
            output_format=args.format,
            output_file=args.output,
            use_ssl=use_ssl,
            port=port,
            timeout=args.timeout,
            user_agent=args.user_agent,
            threads=args.threads,
            delay=args.delay,
            cookies=cookies,
            headers=headers,
            auth=auth,
            proxy=args.proxy,
            follow_redirects=not args.no_redirects,
            scan_level=args.level,
            plugins=plugins,
            gemini_analysis=args.ai_analysis,
            debug=args.debug
        )

    try:
        scanner.run_checks()
        if scanner.output_file:
            scanner.save_results()
    except KeyboardInterrupt:
        print("\n\033[1;31m[!] Scan interrupted by user\033[0m")
        sys.exit(1)
    except Exception as e:
        print(f"\033[1;31m[!] Error: {str(e)}\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    main()
