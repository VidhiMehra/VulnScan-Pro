import requests
import socket
import ssl
import urllib3
from datetime import datetime
urllib3.disable_warnings()

SECURITY_HEADERS = {
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Missing clickjacking protection — site can be embedded in iframes"
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "description": "Missing MIME type sniffing protection"
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "No CSP — allows XSS attacks and malicious script injection"
    },
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "No HSTS — users can be downgraded to HTTP"
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "Missing XSS filter header"
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "No referrer policy — sensitive URLs may leak"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "No permissions policy set"
    }
}

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 5432: "PostgreSQL", 6379: "Redis"
}

SENSITIVE_PATHS = [
    "/admin", "/admin/login", "/.env",
    "/config.php", "/wp-admin", "/wp-login.php",
    "/.git", "/backup", "/db.sql",
    "/phpinfo.php", "/server-status", "/robots.txt",
    "/.htaccess", "/config.yaml", "/secrets.json"
]

def check_headers(url, response):
    results = []
    headers = response.headers

    for header, info in SECURITY_HEADERS.items():
        if header not in headers:
            results.append({
                "check": f"Missing {header}",
                "severity": info["severity"],
                "status": "FAIL",
                "detail": info["description"]
            })
        else:
            results.append({
                "check": f"{header} present",
                "severity": "INFO",
                "status": "PASS",
                "detail": f"Value: {headers[header][:60]}"
            })
    return results

def check_server_info(response):
    results = []
    headers = response.headers

    if "Server" in headers:
        results.append({
            "check": "Server header exposed",
            "severity": "MEDIUM",
            "status": "FAIL",
            "detail": f"Server reveals: {headers['Server']} — attackers can target known vulnerabilities"
        })
    else:
        results.append({
            "check": "Server header hidden",
            "severity": "INFO",
            "status": "PASS",
            "detail": "Server info not exposed"
        })

    if "X-Powered-By" in headers:
        results.append({
            "check": "X-Powered-By exposed",
            "severity": "MEDIUM",
            "status": "FAIL",
            "detail": f"Reveals tech stack: {headers['X-Powered-By']}"
        })

    return results

def check_ssl(hostname):
    results = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        # Check expiry
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_date = datetime.strptime(
                expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.utcnow()).days
            if days_left < 0:
                results.append({
                    "check": "SSL Certificate EXPIRED",
                    "severity": "CRITICAL",
                    "status": "FAIL",
                    "detail": f"Certificate expired {abs(days_left)} days ago!"
                })
            elif days_left < 30:
                results.append({
                    "check": "SSL Certificate expiring soon",
                    "severity": "HIGH",
                    "status": "FAIL",
                    "detail": f"Only {days_left} days until expiry"
                })
            else:
                results.append({
                    "check": "SSL Certificate valid",
                    "severity": "INFO",
                    "status": "PASS",
                    "detail": f"Expires in {days_left} days ({expire_date.date()})"
                })

        # Check issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        results.append({
            "check": "SSL Issuer",
            "severity": "INFO",
            "status": "PASS",
            "detail": f"Issued by: {issuer.get('organizationName', 'Unknown')}"
        })

    except ssl.SSLError as e:
        results.append({
            "check": "SSL Error",
            "severity": "CRITICAL",
            "status": "FAIL",
            "detail": f"SSL handshake failed: {str(e)}"
        })
    except Exception as e:
        results.append({
            "check": "SSL Check",
            "severity": "INFO",
            "status": "SKIP",
            "detail": f"Could not check SSL: {str(e)}"
        })
    return results

def check_cookies(response):
    results = []
    cookies = response.cookies
    if not cookies:
        results.append({
            "check": "No cookies found",
            "severity": "INFO",
            "status": "PASS",
            "detail": "No cookies set on this response"
        })
        return results

    for cookie in cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("missing HttpOnly flag")
        if not cookie.has_nonstandard_attr("SameSite"):
            issues.append("missing SameSite flag")

        if issues:
            results.append({
                "check": f"Cookie '{cookie.name}' insecure",
                "severity": "MEDIUM",
                "status": "FAIL",
                "detail": f"Issues: {', '.join(issues)}"
            })
        else:
            results.append({
                "check": f"Cookie '{cookie.name}' secure",
                "severity": "INFO",
                "status": "PASS",
                "detail": "All security flags present"
            })
    return results

def check_ports(hostname):
    results = []
    open_ports = []
    dangerous = [21, 23, 445, 3389, 27017, 6379]

    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((hostname, port))
            if result == 0:
                open_ports.append(port)
                severity = "HIGH" if port in dangerous else "LOW"
                results.append({
                    "check": f"Port {port} ({service}) OPEN",
                    "severity": severity,
                    "status": "WARN" if port in dangerous else "INFO",
                    "detail": f"Port {port} is open" + (
                        " — dangerous service exposed!" if port in dangerous else "")
                })
            sock.close()
        except:
            pass

    if not open_ports:
        results.append({
            "check": "Port scan complete",
            "severity": "INFO",
            "status": "PASS",
            "detail": "No common ports exposed"
        })
    return results

def check_sensitive_paths(base_url):
    results = []
    found = []

    for path in SENSITIVE_PATHS:
        try:
            res = requests.get(
                base_url + path,
                timeout=3,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if res.status_code == 200:
                found.append(path)
                severity = "CRITICAL" if path in [
                    "/.env", "/.git", "/db.sql",
                    "/config.php", "/secrets.json"
                ] else "HIGH"
                results.append({
                    "check": f"Exposed path: {path}",
                    "severity": severity,
                    "status": "FAIL",
                    "detail": f"Returned 200 OK — publicly accessible!"
                })
            elif res.status_code == 403:
                results.append({
                    "check": f"Forbidden path: {path}",
                    "severity": "LOW",
                    "status": "WARN",
                    "detail": "Path exists but access denied (403)"
                })
        except:
            pass

    if not found:
        results.append({
            "check": "No sensitive paths exposed",
            "severity": "INFO",
            "status": "PASS",
            "detail": f"Checked {len(SENSITIVE_PATHS)} common paths"
        })
    return results

def check_cors(response):
    results = []
    cors = response.headers.get("Access-Control-Allow-Origin", "")
    if cors == "*":
        results.append({
            "check": "CORS misconfigured — wildcard origin",
            "severity": "HIGH",
            "status": "FAIL",
            "detail": "Any website can make requests to this server"
        })
    elif cors:
        results.append({
            "check": "CORS configured",
            "severity": "INFO",
            "status": "PASS",
            "detail": f"Allowed origin: {cors}"
        })
    return results

def run_scan(target):
    if not target.startswith("http"):
        target = "https://" + target

    hostname = target.replace("https://", "").replace(
        "http://", "").split("/")[0]

    results = {
        "target": target,
        "hostname": hostname,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "categories": {},
        "summary": {
            "critical": 0, "high": 0,
            "medium": 0, "low": 0, "pass": 0
        }
    }

    try:
        response = requests.get(
            target, timeout=10, verify=False,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=True
        )
    except Exception as e:
        return {"error": f"Could not connect to {target}: {str(e)}"}

    # Run all checks
    results["categories"]["Security Headers"] = check_headers(
        target, response)
    results["categories"]["Server Information"] = check_server_info(
        response)
    results["categories"]["SSL/TLS"] = check_ssl(hostname)
    results["categories"]["Cookies"] = check_cookies(response)
    results["categories"]["CORS"] = check_cors(response)
    results["categories"]["Port Scan"] = check_ports(hostname)
    results["categories"]["Sensitive Paths"] = check_sensitive_paths(
        target)

    # Count severities
    for category, checks in results["categories"].items():
        for check in checks:
            sev = check["severity"].upper()
            if sev == "CRITICAL":
                results["summary"]["critical"] += 1
            elif sev == "HIGH":
                results["summary"]["high"] += 1
            elif sev == "MEDIUM":
                results["summary"]["medium"] += 1
            elif sev == "LOW":
                results["summary"]["low"] += 1
            if check["status"] == "PASS":
                results["summary"]["pass"] += 1

    # Overall risk score
    # Overall risk score (informational number)
    score = (
        results["summary"]["critical"] * 25 +
        results["summary"]["high"] * 10 +
        results["summary"]["medium"] * 4 +
        results["summary"]["low"] * 1
    )
    results["risk_score"] = min(100, score)

    # Risk level (driven by severity, not just accumulated score)
    if results["summary"]["critical"] > 0:
        results["risk_level"] = "CRITICAL"
    elif results["summary"]["high"] >= 3:
        results["risk_level"] = "HIGH"
    elif results["summary"]["high"] > 0 or results["summary"]["medium"] >= 3:
        results["risk_level"] = "MEDIUM"
    else:
        results["risk_level"] = "LOW"

    return results
