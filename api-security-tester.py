import requests
import argparse
import time

class APISecurityTester:
    def __init__(self, base_url):
        self.base_url = base_url

    def test_sql_injection(self, endpoint, param):
        payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*"]
        for payload in payloads:
            url = f"{self.base_url}{endpoint}?{param}={payload}"
            response = requests.get(url)
            if "error" in response.text.lower() or "syntax" in response.text.lower():
                print(f"[!] SQL Injection vulnerability detected: {url}")
                return True
        print("[+] No SQL Injection vulnerability detected.")
        return False

    def test_xss(self, endpoint, param):
        payloads = ["<script>alert('XSS')</script>", "<img src='javascript:alert(\"XSS\")'>"]
        for payload in payloads:
            url = f"{self.base_url}{endpoint}?{param}={payload}"
            response = requests.get(url)
            if payload in response.text:
                print(f"[!] XSS vulnerability detected: {url}")
                return True
        print("[+] No XSS vulnerability detected.")
        return False

    def test_authentication(self, endpoint, auth_header):
        headers = {"Authorization": auth_header}
        response = requests.get(f"{self.base_url}{endpoint}", headers=headers)
        if response.status_code == 200:
            print("[+] Authentication successful.")
            return True
        else:
            print("[!] Authentication failed.")
            return False

    def test_rate_limiting(self, endpoint):
        for i in range(100):
            response = requests.get(f"{self.base_url}{endpoint}")
            if response.status_code == 429:
                print("[+] Rate limiting detected.")
                return True
            time.sleep(0.1)
        print("[!] No rate limiting detected.")
        return False

    def run_tests(self, endpoint, param, auth_header):
        print("Starting API Security Tests...")
        self.test_sql_injection(endpoint, param)
        self.test_xss(endpoint, param)
        self.test_authentication(endpoint, auth_header)
        self.test_rate_limiting(endpoint)
        print("API Security Tests completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Security Testing Tool")
    parser.add_argument("--base_url", required=True, help="Base URL of the API")
    parser.add_argument("--endpoint", required=True, help="Endpoint to test")
    parser.add_argument("--param", required=True, help="Parameter to test for SQL Injection and XSS")
    parser.add_argument("--auth_header", required=True, help="Authorization header for authentication test")
    
    args = parser.parse_args()
    
    tester = APISecurityTester(args.base_url)
    tester.run_tests(args.endpoint, args.param, args.auth_header)
