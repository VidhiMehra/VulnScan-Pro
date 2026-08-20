# VulnScan Pro

A Python Flask-based web security assessment tool that scans websites for common vulnerabilities and security misconfigurations.

## Features

* Security header analysis
* SSL/TLS certificate checks
* Server information exposure detection
* Cookie security checks
* CORS misconfiguration detection
* Common port scanning
* Sensitive path detection
* Severity-based vulnerability classification
* Overall risk score and risk level
* Web-based dashboard for scan results

## Tech Stack

* Python
* Flask
* Requests
* HTML
* CSS
* JavaScript

## Security Checks

VulnScan Pro checks for common security issues including:

* Missing security headers such as CSP, HSTS and X-Frame-Options
* Exposed server and technology information
* SSL certificate expiry and connection errors
* Missing Secure, HttpOnly and SameSite cookie attributes
* Wildcard CORS configuration
* Common open ports
* Exposed sensitive paths such as `.env`, `.git` and configuration files

## Installation

Clone the repository:

```bash
git clone(https://github.com/VidhiMehra/VulnScan-Pro)
cd VulnScan-Pro
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Start the Flask application:

```bash
python app.py
```

Open the application in your browser:

```text
http://127.0.0.1:5003
```

Enter a target URL and click **Scan Now** to perform the security assessment.

## Project Structure

```text
VulnScan-Pro/
│
├── app.py
├── scanner.py
├── requirements.txt
├── README.md
├── .gitignore
└── templates/
    └── index.html
```

## Disclaimer

This tool is intended for educational purposes and authorized security testing only.

Only scan websites and systems that you own or have explicit permission to test.

## Author

Vidhi Mehra
