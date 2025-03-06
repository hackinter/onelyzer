import asyncio
import aiohttp
import requests
import socket
import re
import whois
import dns.resolver
import ssl
import subprocess
import logging
import os
import time
import csv
import sqlite3
import pdfkit
from datetime import datetime
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from rich.console import Console
from rich.table import Table

# Logging Setup
logging.basicConfig(filename="advanced_website_analysis.log", level=logging.INFO, 
                    format="%(asctime)s - %(levelname)s - %(message)s")

console = Console()

# HTTP Headers
headers = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/100.0.0.0 Safari/537.36")
}

# ---------------- Utility Functions ----------------

def measure_response_time(url):
    """HTTP রিকোয়েস্টের Response Time (in ms) পরিমাপ করে"""
    try:
        start = time.time()
        r = requests.get(url, headers=headers, timeout=10)
        end = time.time()
        response_time = round((end - start) * 1000, 2)
        return response_time, r
    except Exception as e:
        logging.error(f"Response time measurement failed: {e}")
        return None, None

def measure_dns_time(domain):
    """DNS রিজলিউশন সময় (in ms) পরিমাপ করে"""
    try:
        start = time.time()
        socket.gethostbyname(domain)
        end = time.time()
        return round((end - start) * 1000, 2)
    except Exception as e:
        logging.error(f"DNS resolution time measurement failed for {domain}: {e}")
        return "Unknown"

def get_ip(url):
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ip = socket.gethostbyname(domain)
        logging.info(f"IP for {domain}: {ip}")
        return ip
    except socket.gaierror:
        logging.error(f"IP resolution failed for {domain}")
        return "Unknown"

def get_whois_data(url):
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        w = whois.whois(domain)
        registrar = w.registrar if w.registrar else "Unknown"
        logging.info(f"WHOIS for {domain}: {registrar}")
        return registrar
    except Exception as e:
        logging.error(f"WHOIS lookup failed for {domain}: {e}")
        return "Unknown"

def get_dns_records(domain):
    records = {}
    try:
        records["A"] = [str(ip) for ip in dns.resolver.resolve(domain, 'A')]
    except Exception as e:
        logging.error(f"DNS A record error for {domain}: {e}")
        records["A"] = "Not Found"
    try:
        records["MX"] = [str(mx) for mx in dns.resolver.resolve(domain, 'MX')]
    except Exception as e:
        logging.error(f"DNS MX record error for {domain}: {e}")
        records["MX"] = "Not Found"
    try:
        records["TXT"] = [str(txt) for txt in dns.resolver.resolve(domain, 'TXT')]
    except Exception as e:
        logging.error(f"DNS TXT record error for {domain}: {e}")
        records["TXT"] = "Not Found"
    return records

def check_ssl_certificate(url):
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    context = ssl.create_default_context()
    try:
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_remaining = (expiry_date - datetime.now()).days
        subject = dict(x[0] for x in cert['subject'])
        common_name = subject.get("commonName", "Unknown")
        logging.info(f"SSL for {domain}: {common_name}, expires {expiry_date} ({days_remaining} days left)")
        return {"Issuer": cert['issuer'][0][0][1],
                "Expiry Date": expiry_date.strftime('%Y-%m-%d'),
                "Days Remaining": days_remaining,
                "Common Name": common_name}
    except Exception as e:
        logging.error(f"SSL check failed for {domain}: {e}")
        return {"Issuer": "Unknown", "Expiry Date": "Unknown", "Days Remaining": "Unknown", "Common Name": "Unknown"}

def enumerate_subdomains(domain):
    subdomains = []
    common = ["www", "mail", "ftp", "admin", "test", "dev"]
    for sub in common:
        full = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full)
            subdomains.append(full)
            logging.info(f"Subdomain: {full}")
        except socket.gaierror:
            continue
    return subdomains

def check_robots_txt(url):
    robots_url = f"{url.rstrip('/')}/robots.txt"
    try:
        resp = requests.get(robots_url, headers=headers, timeout=10)
        if resp.status_code == 200:
            logging.info("robots.txt found")
            return resp.text.strip()
        else:
            logging.info("robots.txt not found")
            return "Not Found"
    except requests.exceptions.RequestException as e:
        logging.error(f"robots.txt error: {e}")
        return "Not Found"

def detect_social_media_links(soup):
    social = {
        "Facebook": "facebook.com",
        "Twitter": "twitter.com",
        "LinkedIn": "linkedin.com",
        "Instagram": "instagram.com",
        "YouTube": "youtube.com"
    }
    detected = {}
    for platform, pattern in social.items():
        links = soup.find_all("a", href=re.compile(pattern))
        if links:
            detected[platform] = ", ".join(link.get("href") for link in links)
            logging.info(f"{platform} links found")
    return detected

def check_directory_listing(url):
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if "Index of /" in resp.text:
            logging.info("Directory listing enabled")
            return True
        return False
    except Exception as e:
        logging.error(f"Directory listing error: {e}")
        return False

def run_sqlmap(url):
    try:
        cmd = ["sqlmap", "-u", url, "--batch", "--crawl=1"]
        logging.info(f"Running sqlmap: {' '.join(cmd)}")
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
        output = result.stdout + result.stderr
        logging.info(f"sqlmap output (first 200 chars): {output[:200]}")
        if "vulnerable" in output.lower() or "is vulnerable" in output.lower():
            return "SQL Injection Vulnerability Detected via sqlmap"
        else:
            return "SQL Injection Vulnerability Not Detected via sqlmap"
    except Exception as e:
        logging.error(f"sqlmap error for {url}: {e}")
        return "sqlmap Error"

def check_vulnerabilities(url):
    vulns = []
    payloads = {
        "SQLi": "' OR '1'='1",
        "XSS": "<script>alert('xss')</script>",
        "XXE": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
        "LFI": "../../../../../../etc/passwd",
        "SSRF": "http://127.0.0.1:80",
        "RCE": ";echo RCE_TEST;",
        "OpenRedirect": "http://example.com"
    }
    def has_error(text, keywords):
        for word in keywords:
            if word in text.lower():
                return True
        return False
    sql_errors = ["sql syntax", "mysql", "database error", "sql error"]

    if "?" in url:
        base, params = url.split("?", 1)
        param_list = params.split("&")
    else:
        base = url
        param_list = ["test"]

    for vuln_type, payload in payloads.items():
        for param in param_list:
            key = param.split("=")[0] if "=" in param else param
            test_url = f"{base}?{key}={payload}"
            try:
                resp = requests.get(test_url, headers=headers, timeout=10)
                text = resp.text
                if vuln_type == "SQLi" and has_error(text, sql_errors):
                    vulns.append("SQL Injection (Heuristic)")
                    logging.info(f"SQLi heuristic detected using payload: {payload}")
                elif vuln_type == "XSS" and payload in text:
                    vulns.append("Cross-Site Scripting (XSS)")
                    logging.info("XSS detected")
                elif vuln_type == "XXE" and "root:" in text:
                    vulns.append("XML External Entity (XXE)")
                    logging.info("XXE detected")
                elif vuln_type == "LFI" and "root:" in text:
                    vulns.append("Local File Inclusion (LFI)")
                    logging.info("LFI detected")
                elif vuln_type == "SSRF" and "html" in text.lower():
                    vulns.append("Server-Side Request Forgery (SSRF)")
                    logging.info("SSRF detected")
                elif vuln_type == "RCE" and "RCE_TEST" in text:
                    vulns.append("Remote Code Execution (RCE)")
                    logging.info("RCE detected")
                elif vuln_type == "OpenRedirect" and "http://example.com" in text:
                    vulns.append("Open Redirect Vulnerability")
                    logging.info("Open Redirect detected")
            except Exception as e:
                logging.error(f"{vuln_type} check error: {e}")
                continue

    sqlmap_result = run_sqlmap(url)
    vulns.append(sqlmap_result)
    if check_directory_listing(url):
        vulns.append("Directory Listing Enabled")
        logging.info("Directory Listing detected")
    
    vulns.append("Other OWASP Top Ten vulnerabilities (e.g., Broken Authentication, Security Misconfiguration) - Not Implemented")
    vulns.append("Broken Access Control (BAC) - Not Checked")
    vulns.append("Insecure Direct Object Reference (IDOR) - Not Checked")
    
    return vulns

# ---------------- New Advanced Checks ----------------

async def check_broken_link(session, link):
    try:
        async with session.head(link, timeout=5, headers=headers) as resp:
            if resp.status >= 400:
                return link
    except Exception:
        return link
    return None

async def check_broken_links(soup, base_url):
    """হোমপেজের কিছু লিংক পরীক্ষা করে ব্রোকেন লিংক সনাক্ত করে (সীমিত সংখ্যা)"""
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if not href.startswith("http"):
            href = requests.compat.urljoin(base_url, href)
        links.append(href)
    broken = []
    async with aiohttp.ClientSession() as session:
        tasks = [check_broken_link(session, link) for link in links[:5]]
        results = await asyncio.gather(*tasks)
        for res in results:
            if res:
                broken.append(res)
    return broken if broken else ["None Detected"]

def check_favicon(soup, base_url):
    """ফেভিকন সনাক্ত করে"""
    icon_link = soup.find("link", rel=lambda x: x and "icon" in x.lower())
    if icon_link and icon_link.has_attr("href"):
        favicon = icon_link["href"]
        if not favicon.startswith("http"):
            favicon = requests.compat.urljoin(base_url, favicon)
        logging.info(f"Favicon found: {favicon}")
        return favicon
    default_favicon = f"{base_url.rstrip('/')}/favicon.ico"
    try:
        r = requests.get(default_favicon, headers=headers, timeout=5)
        if r.status_code == 200:
            logging.info(f"Default favicon found: {default_favicon}")
            return default_favicon
    except Exception as e:
        logging.error(f"Favicon check error: {e}")
    return "Not Detected"

def check_http_version(resp):
    """HTTP Version নির্ধারণ করে"""
    try:
        ver = resp.raw.version
        if ver == 11:
            return "HTTP/1.1"
        elif ver == 10:
            return "HTTP/1.0"
        elif ver == 20:
            return "HTTP/2"
        else:
            return f"HTTP/{ver}"
    except Exception as e:
        logging.error(f"HTTP version check error: {e}")
        return "Unknown"

def check_meta_tags(soup):
    """Viewport ও Robots Meta ট্যাগ চেক করে"""
    meta_tags = {}
    viewport = soup.find("meta", attrs={"name": "viewport"})
    meta_tags["Viewport"] = viewport["content"] if viewport and viewport.has_attr("content") else "Not Detected"
    meta_robots = soup.find("meta", attrs={"name": "robots"})
    meta_tags["Robots Meta"] = meta_robots["content"] if meta_robots and meta_robots.has_attr("content") else "Not Detected"
    return meta_tags

def check_cookie_security(resp):
    """Set-Cookie হেডারে নিরাপত্তা ফ্ল্যাগ (Secure, HttpOnly, SameSite) চেক করে"""
    cookies = resp.headers.get("Set-Cookie", "")
    secure = "Secure" in cookies
    httponly = "HttpOnly" in cookies
    samesite = "SameSite" in cookies
    return {
        "Secure": "Yes" if secure else "No",
        "HttpOnly": "Yes" if httponly else "No",
        "SameSite": "Yes" if samesite else "No"
    }

def run_lighthouse(url):
    """Google Lighthouse এর মাধ্যমে পারফরমেন্স ও অ্যাক্সেসিবিলিটি চেক (কম্যান্ড লাইন টুল)"""
    try:
        cmd = ["lighthouse", url, "--quiet", "--chrome-flags='--headless'", "--output=json", "--output-path=lhreport.json"]
        subprocess.run(" ".join(cmd), shell=True, timeout=120)
        with open("lhreport.json", "r", encoding="utf-8") as f:
            data = f.read()
        logging.info("Lighthouse report generated")
        return data  # JSON string, প্রয়োজনে পার্স করা যেতে পারে
    except Exception as e:
        logging.error(f"Lighthouse check error: {e}")
        return "Not Available"

def capture_screenshot(url, domain):
    """হেডলেস ব্রাউজারের মাধ্যমে স্ক্রিনশট গ্রহণ করে"""
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-gpu")
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_window_size(1920, 1080)
        driver.get(url)
        screenshot_path = f"{domain}_screenshot.png"
        driver.save_screenshot(screenshot_path)
        driver.quit()
        logging.info(f"Screenshot saved as {screenshot_path}")
        return screenshot_path
    except Exception as e:
        logging.error(f"Screenshot capture error: {e}")
        return "Not Captured"

# ---------------- Database Integration (SQLite) ----------------

def save_to_database(report_data):
    conn = sqlite3.connect("website_analysis.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS analysis
                 (url TEXT, ip TEXT, whois TEXT, ssl_expiry TEXT, response_time TEXT,
                  dns_time TEXT, http_version TEXT, tech_stack TEXT, vulnerabilities TEXT,
                  report_date TEXT)''')
    c.execute('''INSERT INTO analysis VALUES (?,?,?,?,?,?,?,?,?,?)''', (
        report_data.get("url"),
        report_data.get("ip_address"),
        report_data.get("whois_registrar"),
        report_data.get("ssl_expiry"),
        report_data.get("response_time_ms"),
        report_data.get("dns_time"),
        report_data.get("http_version"),
        ", ".join(report_data.get("tech_stack", [])),
        ", ".join(report_data.get("vulnerabilities", [])),
        report_data.get("report_generated")
    ))
    conn.commit()
    conn.close()
    logging.info("Report saved to database.")

# ---------------- Export Functions ----------------

def export_csv(report_data, domain):
    csv_filename = f"{domain}.csv"
    try:
        with open(csv_filename, "w", newline='', encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            for key, value in report_data.items():
                writer.writerow([key, value])
        logging.info(f"CSV report saved as {csv_filename}")
    except Exception as e:
        logging.error(f"CSV export error: {e}")

def export_pdf(html_filename, domain):
    pdf_filename = f"{domain}.pdf"
    try:
        pdfkit.from_file(html_filename, pdf_filename)
        logging.info(f"PDF report saved as {pdf_filename}")
    except Exception as e:
        logging.error(f"PDF export error: {e}")

# ---------------- HTML & CSS Report Generation ----------------

def generate_section(title, rows):
    section_html = f"<h2>{title}</h2>\n"
    section_html += '<table>\n<thead><tr><th>Feature</th><th>Detected</th></tr></thead>\n<tbody>\n'
    for feature, detected in rows:
        section_html += f"<tr><td>{feature}</td><td>{detected}</td></tr>\n"
    section_html += "</tbody>\n</table>\n"
    return section_html

def get_css_content():
    """CSS কন্টেন্ট রিটার্ন করে, যাতে HTML এর হেডে ইনলাইন স্টাইল হিসেবে যোগ করা যায়"""
    css_content = """
/* Professional & Futuristic Style Report */
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    margin: 20px;
    background-color: #f4f7f9;
    color: #333;
}
h1, h2 {
    text-align: center;
    color: #003366;
}
h1 {
    font-size: 2.8em;
    margin-bottom: 0.2em;
}
h2 {
    font-size: 1.8em;
    margin: 30px 0 10px 0;
    border-bottom: 2px solid #003366;
    padding-bottom: 5px;
}
p {
    text-align: center;
    color: #666;
}
table {
    width: 90%;
    margin: 20px auto;
    border-collapse: collapse;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    background-color: #fff;
    border-radius: 5px;
    overflow: hidden;
}
table th, table td {
    border: 1px solid #ddd;
    padding: 12px 15px;
    text-align: left;
}
table th {
    background-color: #00509e;
    color: #fff;
}
table tr:nth-child(even) {
    background-color: #f2f2f2;
}
hr {
    border: 0;
    height: 1px;
    background: #ccc;
    margin: 20px 0;
}
a {
    color: #00509e;
    text-decoration: none;
}
a:hover {
    text-decoration: underline;
}
.chart-container {
    width: 80%;
    margin: auto;
}
"""
    return css_content

def create_css_file():
    """অপশনাল: আলাদা CSS ফাইল তৈরির জন্য"""
    css_filename = "style.css"
    if not os.path.exists(css_filename):
        with open(css_filename, "w", encoding="utf-8") as f:
            f.write(get_css_content())
        logging.info(f"CSS file created: {css_filename}")

# ---------------- Main Analysis and Report Generation ----------------

def analyze_website(url):
    try:
        response_time, resp = measure_response_time(url)
        if not resp:
            console.print(f"[red]Failed to connect to {url}[/red]")
            return

        soup = BeautifulSoup(resp.text, "html.parser")
        source_code = resp.text
        server_header = resp.headers.get("Server", "Unknown")
        powered_by = resp.headers.get("X-Powered-By", "Unknown")
        ip_address = get_ip(url)
        whois_info = get_whois_data(url)
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        dns_records = get_dns_records(domain)
        ssl_info = check_ssl_certificate(url)
        subdomains = enumerate_subdomains(domain)
        robots_txt = check_robots_txt(url)
        vulns = check_vulnerabilities(url)
        social_media = detect_social_media_links(soup)
        cookie_security = check_cookie_security(resp)
        
        # Technology Stack Detection (পরিচিত প্যাটার্ন দ্বারা)
        tech_stack = []
        langs = {"PHP": "php", "Python": "flask|django", "Ruby": "rails",
                 "Node.js": "express", "ASP.NET": "asp.net", "Java": "java", "Go": "go"}
        for lang, pattern in langs.items():
            if re.search(pattern, source_code, re.IGNORECASE):
                tech_stack.append(lang)
        cms_list = {"WordPress": "wp-content", "Joomla": "joomla", "Drupal": "drupal",
                    "Magento": "magento", "Shopify": "cdn.shopify.com", "Ghost": "ghost.org", "Squarespace": "squarespace.com"}
        for cms, keyword in cms_list.items():
            if keyword in source_code.lower():
                tech_stack.append(cms)
        js_libraries = {"ReactJS": "react", "VueJS": "vue", "AngularJS": "angular",
                        "jQuery": "jquery", "Bootstrap": "bootstrap", "Backbone.js": "backbone", "Ember.js": "ember"}
        for lib, keyword in js_libraries.items():
            if keyword in source_code.lower():
                tech_stack.append(lib)
        tech_stack = list(set(tech_stack))
        
        # Additional Tools Detection
        analytics_tools = []
        analytics = {"Google Analytics": "google-analytics.com", "Facebook Pixel": "connect.facebook.net/en_US/fbevents.js",
                     "Hotjar": "hotjar.com", "Tag Manager": "tagmanager.google.com"}
        for tool, keyword in analytics.items():
            if keyword in source_code.lower():
                analytics_tools.append(tool)
        marketing_tools = []
        marketing = {"MailChimp": "mailchimp.com", "HubSpot": "hubspot.com", "Klaviyo": "klaviyo.com",
                     "ActiveCampaign": "activecampaign.com"}
        for tool, keyword in marketing.items():
            if keyword in source_code.lower():
                marketing_tools.append(tool)
        payment_processors = []
        payments = {"PayPal": "paypal.com", "Stripe": "stripe.com", "Square": "square.com", "Razorpay": "razorpay.com"}
        for proc, keyword in payments.items():
            if keyword in source_code.lower():
                payment_processors.append(proc)
        crm_systems = []
        crms = {"Salesforce": "salesforce.com", "Zoho": "zoho.com", "HubSpot CRM": "hubspot.com"}
        for crm, keyword in crms.items():
            if keyword in source_code.lower():
                crm_systems.append(crm)
        cdn_providers = []
        cdns = {"Cloudflare": "cloudflare", "Akamai": "akamai", "Amazon CloudFront": "cloudfront",
                 "Fastly": "fastly", "StackPath": "stackpath"}
        for cdn, keyword in cdns.items():
            if keyword in source_code.lower():
                cdn_providers.append(cdn)
        
        # Advanced Checks
        meta_tags = check_meta_tags(soup)
        favicon = check_favicon(soup, url)
        http_version = check_http_version(resp)
        dns_time = measure_dns_time(domain)
        # asyncio event loop for broken links
        broken_links = asyncio.run(check_broken_links(soup, url))
        mobile_friendly = "Yes" if meta_tags.get("Viewport", "Not Detected") != "Not Detected" else "No"
        lh_report = run_lighthouse(url)
        screenshot_path = capture_screenshot(url, domain)
        
        # Security Headers Check
        headers_check = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "X-Frame-Options",
            "X-XSS-Protection": "X-XSS-Protection",
            "X-Content-Type-Options": "X-Content-Type-Options",
            "Referrer-Policy": "Referrer-Policy",
            "Permissions-Policy": "Permissions-Policy",
            "X-Content-Security-Policy": "X-Content-Security-Policy"
        }
        sec_headers = {}
        for header, label in headers_check.items():
            sec_headers[label] = "Yes" if header in resp.headers else "No"
        
        recommendations = []
        if "Directory Listing Enabled" in vulns:
            recommendations.append("Disable directory listing to prevent unauthorized access.")
        if any(value == "No" for value in sec_headers.values()):
            recommendations.append("Add missing security headers (e.g., CSP, X-Frame-Options) to enhance security.")
        if not vulns or all("Not Detected" in vuln for vuln in vulns):
            recommendations.append("No major vulnerabilities detected. Continue regular monitoring.")
        if not recommendations:
            recommendations.append("Review website configuration for further improvements.")
        
        # ------------- Terminal Executive Summary -------------
        risk_color = "green" if len(vulns) < 3 else "yellow" if len(vulns) < 6 else "red"
        summary_table = Table(title="Executive Summary", show_lines=True)
        summary_table.add_column("Feature", style="bold yellow", no_wrap=True)
        summary_table.add_column("Detected", style="green")
        summary_table.add_row("URL", url)
        summary_table.add_row("IP Address", ip_address)
        summary_table.add_row("WHOIS Registrar", whois_info)
        summary_table.add_row("SSL Expiry", ssl_info["Expiry Date"])
        summary_table.add_row("Response Time (ms)", str(response_time) if response_time else "N/A")
        summary_table.add_row("DNS Resolution Time (ms)", str(dns_time))
        summary_table.add_row("HTTP Version", http_version)
        summary_table.add_row("Tech Stack", ", ".join(tech_stack) if tech_stack else "None Detected")
        summary_table.add_row("Vulnerabilities", f"[{risk_color}]{len(vulns)} items[/{risk_color}]")
        console.print(summary_table)
        
        # ------------- HTML Detailed Report -------------
        sections = []
        # Basic Information Section
        basic_info = [
            ("URL", url),
            ("Server", server_header),
            ("Powered By", powered_by),
            ("IP Address", ip_address),
            ("WHOIS Registrar", whois_info),
            ("Response Time (ms)", str(response_time) if response_time else "N/A"),
            ("DNS Resolution Time (ms)", str(dns_time))
        ]
        sections.append(generate_section("Basic Information", basic_info))
        
        # DNS Records Section
        dns_info = []
        if dns_records["A"] != "Not Found":
            dns_info.append(("DNS A Record", ", ".join(dns_records["A"])))
        if dns_records["MX"] != "Not Found":
            dns_info.append(("DNS MX Record", ", ".join(dns_records["MX"])))
        if dns_records["TXT"] != "Not Found":
            dns_info.append(("DNS TXT Record", ", ".join(dns_records["TXT"])))
        sections.append(generate_section("DNS Records", dns_info))
        
        # SSL/TLS Certificate Section
        ssl_rows = [
            ("SSL Issuer", ssl_info["Issuer"]),
            ("SSL Common Name", ssl_info["Common Name"]),
            ("SSL Expiry Date", ssl_info["Expiry Date"]),
            ("SSL Days Remaining", str(ssl_info["Days Remaining"]))
        ]
        sections.append(generate_section("SSL/TLS Certificate", ssl_rows))
        
        # Performance Metrics Section
        perf_metrics = [
            ("Response Time (ms)", str(response_time) if response_time else "N/A"),
            ("DNS Resolution Time (ms)", str(dns_time)),
            ("HTTP Version", http_version)
        ]
        sections.append(generate_section("Performance Metrics", perf_metrics))
        
        # Subdomains & Robots.txt Section
        sections.append(generate_section("Subdomains", [("Subdomains", ", ".join(subdomains) if subdomains else "None Detected")]))
        sections.append(generate_section("Robots.txt", [("Content", robots_txt)]))
        
        # Security Headers & Cookie Security Section
        sec_header_rows = [(label, status) for label, status in sec_headers.items()]
        sections.append(generate_section("Security Headers", sec_header_rows))
        cookie_sec = [(key, val) for key, val in cookie_security.items()]
        sections.append(generate_section("Cookie Security", cookie_sec))
        
        # Technology Stack & Additional Tools Section
        sections.append(generate_section("Technology Stack", [("Technologies Detected", ", ".join(tech_stack) if tech_stack else "None Detected")]))
        additional = [
            ("SEO & Analytics", ", ".join(analytics_tools) if analytics_tools else "None Detected"),
            ("Marketing Tools", ", ".join(marketing_tools) if marketing_tools else "None Detected"),
            ("Payment Processors", ", ".join(payment_processors) if payment_processors else "None Detected"),
            ("CRM Systems", ", ".join(crm_systems) if crm_systems else "None Detected"),
            ("CDN Provider(s)", ", ".join(cdn_providers) if cdn_providers else "None Detected")
        ]
        sections.append(generate_section("Additional Tools", additional))
        
        # Social Media Links Section
        social_rows = [(platform, links) for platform, links in social_media.items()]
        if social_rows:
            sections.append(generate_section("Social Media Links", social_rows))
        
        # Advanced Checks Section
        advanced_checks = [
            ("Favicon", favicon),
            ("Viewport Meta", meta_tags.get("Viewport", "Not Detected")),
            ("Robots Meta", meta_tags.get("Robots Meta", "Not Detected")),
            ("Mobile Friendly", mobile_friendly),
            ("Broken Links (Sample)", "<br>".join(broken_links))
        ]
        sections.append(generate_section("Advanced Checks", advanced_checks))
        
        # Lighthouse Report Section (Raw JSON output)
        sections.append(generate_section("Lighthouse Report", [("Report", lh_report)]))
        
        # Vulnerability Scanning Section
        sections.append(generate_section("Vulnerability Scanning", [("Vulnerabilities Detected", "<br>".join(vulns))]))
        
        # Security Recommendations Section
        sections.append(generate_section("Security Recommendations", [("Recommendations", "<br>".join(recommendations))]))
        
        # Screenshot Section
        sections.append(generate_section("Website Screenshot", [("Screenshot Path", screenshot_path)]))
        
        # Chart Section (ইন্টারেক্টিভ চার্ট - Chart.js)
        chart_section = """
<div class="chart-container">
<canvas id="vulnChart"></canvas>
</div>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
const ctx = document.getElementById('vulnChart').getContext('2d');
const vulnChart = new Chart(ctx, {
    type: 'pie',
    data: {
        labels: ['Vulnerabilities Detected', 'Other Checks'],
        datasets: [{
            data: [""" + str(len(vulns)) + """, 10],
            backgroundColor: ['#FF6384', '#36A2EB']
        }]
    },
    options: {
        responsive: true,
        plugins: {
            legend: { position: 'top' },
            title: { display: true, text: 'Vulnerability Overview' }
        }
    }
});
</script>
"""
        sections.append(chart_section)
        
        # Report Header
        report_header = f"""
<h1>Advanced Website Analysis Report: {url}</h1>
<p>Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<hr>
"""
        # Get CSS content and embed it in the HTML head
        css_inline = get_css_content()
        full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Advanced Website Analysis Report: {url}</title>
    <style>
    {css_inline}
    </style>
</head>
<body>
{report_header}
{''.join(sections)}
</body>
</html>
"""
        html_filename = f"{domain}.html"
        with open(html_filename, "w", encoding="utf-8") as f:
            f.write(full_html)
        logging.info(f"HTML report saved as {html_filename}")
        console.print(f"[bold green]Detailed HTML report saved as {html_filename}[/bold green]")
        
        # Optional: Create separate CSS file if needed
        create_css_file()
        
        # Prepare report data for export & database
        report_data = {
            "url": url,
            "ip_address": ip_address,
            "whois_registrar": whois_info,
            "ssl_expiry": ssl_info["Expiry Date"],
            "response_time_ms": response_time,
            "dns_time": dns_time,
            "http_version": http_version,
            "tech_stack": tech_stack,
            "vulnerabilities": vulns,
            "report_generated": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        # Export CSV & PDF
        export_csv(report_data, domain)
        export_pdf(html_filename, domain)
        # Save to Database
        save_to_database(report_data)
        
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during analysis: {e}")
        console.print(f"[red]Error: {e}[/red]")

# ---------------- Example Usage ----------------
if __name__ == "__main__":
    target_url = input("Enter website URL: ")
    analyze_website(target_url)
