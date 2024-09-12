import requests
from bs4 import BeautifulSoup
import argparse
import os
from colorama import Fore, Style, init

init(autoreset=True)

def crawl(url, visited=None):
    if visited is None:
        visited = set()
    links = set()
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"{Fore.BLUE}[INFO] {Fore.RESET}Crawling URL: {url}")
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                absolute_link = requests.compat.urljoin(url, link['href'])
                if absolute_link not in visited and url in absolute_link:
                    visited.add(absolute_link)
                    links.add(absolute_link)
        else:
            print(f"{Fore.YELLOW}[WARNING] {Fore.RESET}URL {url} returned status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"{Fore.RED}[ERROR] {Fore.RESET}Error crawling {url}: {e}")
    return links

def load_payloads(file):
    with open(file, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f]

def scan_xss(url, payloads, params, method):
    vulnerable = False
    for param in params:
        for payload in payloads:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    response = requests.get(test_url)
                elif method == 'POST':
                    response = requests.post(url, data={param: payload})
                else:
                    print(f"{Fore.RED}[ERROR] {Fore.RESET}Unsupported method: {method}")
                    return vulnerable

                if response.status_code == 200 and payload in response.text:
                    print(f"{Fore.RED}{Style.BRIGHT}[VULNERABILITY] XSS vulnerability found on {url} with payload: {payload} in parameter: {param}")
                    save_vulnerability(url, payload, param)
                    vulnerable = True
            except requests.RequestException:
                print(f"{Fore.RED}[ERROR] {Fore.RESET}Error testing XSS on {url} with method {method}")
    return vulnerable

def scan_sql(url, payloads, params, method):
    vulnerable = False
    for param in params:
        for payload in payloads:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    response = requests.get(test_url)
                elif method == 'POST':
                    response = requests.post(url, data={param: payload})
                else:
                    print(f"{Fore.RED}[ERROR] {Fore.RESET}Unsupported method: {method}")
                    return vulnerable

                if response.status_code == 200 and ('mysql' in response.text.lower() or 'syntax' in response.text.lower()):
                    print(f"{Fore.RED}{Style.BRIGHT}[VULNERABILITY] SQL Injection vulnerability found on {url} with payload: {payload} in parameter: {param}")
                    save_vulnerability(url, payload, param)
                    vulnerable = True
            except requests.RequestException:
                print(f"{Fore.RED}[ERROR] {Fore.RESET}Error testing SQL Injection on {url} with method {method}")
    return vulnerable

def save_html_report(vulnerable_links, output_file):
    with open(output_file, 'w') as f:
        f.write("<html><body><h1>Vulnerability Report</h1>")
        for link, vuln_type in vulnerable_links.items():
            f.write(f"<p>{Fore.RED}<strong>{vuln_type} vulnerability found on:</strong> <a href='{link}'>{link}</a></p>")
        f.write("</body></html>")
    print(f"{Fore.BLUE}[INFO] {Fore.RESET}HTML report saved to {output_file}")

def save_vulnerability(url, payload, param):
    with open('vuln.txt', 'a') as f:
        f.write(f"url: {url}\n")
        f.write(f"payload: {payload}\n")
        f.write(f"paramvalue: {param}\n")
        f.write("\n")
    print(f"{Fore.BLUE}[INFO] {Fore.RESET}Vulnerability saved to vuln.txt")

def clrscr():
    if os.name == "posix":
        os.system('clear')
    else:
        os.system('cls')

def author():
    clrscr()
    banner = r"""
     ____._____.___.__________    _____  ____  ___
    |    |\__  |   |\______   \  /  _  \ \   \/  /
    |    | /   |   | |       _/ /  /_\  \ \     /   
/\__|    | \____   | |    |   \/    |    \/     \   
\________| / ______| |____|_  /\____|__  /___/\  \  
           \/               \/         \/      \_/
    """
    print(banner)

def main():
    author()
    parser = argparse.ArgumentParser(description='XSS and SQL Injection Vulnerability Scanner')
    parser.add_argument('--basic-crawl', required=True, help='URL to crawl and scan')
    parser.add_argument('--plugins', required=True, help='Choose plugins: xss, sqldet or both')
    parser.add_argument('--method', default='GET', choices=['GET', 'POST'], help='HTTP method to use for scanning')
    parser.add_argument('--html-output', default='report.html', help='Save output to HTML file')
    args = parser.parse_args()

    url = args.basic_crawl
    plugins = args.plugins.split(',')
    method = args.method
    output_file = args.html_output

    visited = set()
    payloads_xss = load_payloads('assets/xss.txt') if 'xss' in plugins else []
    payloads_sql = load_payloads('assets/sqldet.txt') if 'sqldet' in plugins else []

    links_to_scan = crawl(url, visited)
    vulnerable_links = {}

    params = set()
    for link in links_to_scan:
        try:
            response = requests.get(link)
            if response.status_code == 200:
                print(f"{Fore.BLUE}[INFO]{Fore.RESET} Processing URL: {link}")
                soup = BeautifulSoup(response.text, 'html.parser')
                for form in soup.find_all('form'):
                    for input_tag in form.find_all('input', attrs={'name': True}):
                        params.add(input_tag['name'])
            else:
                print(f"{Fore.YELLOW}[WARNING] {Fore.RESET}URL {link} returned status code: {response.status_code}")
        except requests.RequestException as e:
            print(f"{Fore.RED}[ERROR] {Fore.RESET}Error processing {link}: {e}")

    for link in links_to_scan:
        if 'xss' in plugins and scan_xss(link, payloads_xss, params, method):
            vulnerable_links[link] = 'XSS'
        if 'sqldet' in plugins and scan_sql(link, payloads_sql, params, method):
            vulnerable_links[link] = 'SQL Injection'

    if vulnerable_links:
        save_html_report(vulnerable_links, output_file)
    else:
        print(f"{Fore.BLUE}[INFO] {Fore.RESET}No vulnerabilities found.")

if __name__ == "__main__":
    main()