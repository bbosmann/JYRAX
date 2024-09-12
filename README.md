# SQL & XSS Vulnerability Scanner

A powerful and easy-to-use Python-based vulnerability scanner designed to detect SQL Injection and Cross-Site Scripting (XSS) vulnerabilities on web applications.

## Features

- **URL Crawling**: Automatically crawls a given URL and its internal links.
- **XSS Detection**: Scans web pages for potential XSS vulnerabilities using a list of payloads.
- **SQL Injection Detection**: Tests for SQL Injection vulnerabilities by sending malicious payloads to URL parameters.
- **Form Scanning**: Detects and tests form input fields for XSS and SQL vulnerabilities.
- **Method Control**: Supports testing using both `GET` and `POST` methods for more thorough scanning.
- **Plugins System**: Choose between XSS, SQL Injection, or both for flexible scanning.
- **Reports**: Saves detailed reports of vulnerabilities found in both text and HTML format.
- **Error Handling**: Handles exceptions and continues scanning without crashing.
- **Console Logs**: Colored console output for easy log tracking using `colorama`.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/AstaGanz/JYRAX
    cd JYRAX
    ```

2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

To run the scanner, use the following command:

```bash
python detector.py --basic-crawl <URL> --plugins <xss,sqldet> --method <GET/POST> [--html-output <file.html>]
```
# Preview
![Screenshot 2024-09-12 211413](https://github.com/user-attachments/assets/c42f64a5-ad3b-4d9d-9df3-70b8bb8313a5)
# Donate 
bc1q02s3jtvn2leawecgpqf8573cfy25hff2y0egmj (BTC)
