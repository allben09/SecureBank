#!/usr/bin/env python3
# ========== CYBERSECURITY: Automated Audit Script ==========
import subprocess
import requests
import json
import time
from typing import Dict, List
import threading
from concurrent.futures import ThreadPoolExecutor
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityAudit:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.results = {
            'vulnerabilities': [],
            'scan_time': datetime.now().isoformat(),
            'target': target_url
        }
    
    # ========== WEB SECURITY: XSS Testing ==========
    def test_xss(self, endpoint: str) -> List[Dict]:
        """Test for XSS vulnerabilities"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')",
            "<svg/onload=alert(1)>",
            "'';!--\"<XSS>=&{()}"
        ]
        
        vulnerabilities = []
        for payload in payloads:
            try:
                response = requests.get(
                    f"{self.target_url}{endpoint}?q={payload}",
                    timeout=5
                )
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'XSS',
                        'payload': payload,
                        'url': response.url,
                        'severity': 'High'
                    })
            except:
                continue
        return vulnerabilities
    
    # ========== APP SECURITY: SQL Injection Testing ==========
    def test_sqli(self, endpoint: str) -> List[Dict]:
        """Test for SQL Injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "' UNION SELECT NULL--",
            "' AND SLEEP(5)--",
            "' OR 1=1; DROP TABLE users--"
        ]
        
        vulnerabilities = []
        for payload in payloads:
            try:
                start = time.time()
                response = requests.get(
                    f"{self.target_url}{endpoint}?id={payload}",
                    timeout=10
                )
                elapsed = time.time() - start
                
                # Check for time-based injection
                if elapsed > 4:
                    vulnerabilities.append({
                        'type': 'SQL Injection (Time-based)',
                        'payload': payload,
                        'severity': 'Critical'
                    })
                
                # Check for error-based injection
                if any(keyword in response.text.lower() for keyword in ['sql', 'mysql', 'syntax']):
                    vulnerabilities.append({
                        'type': 'SQL Injection (Error-based)',
                        'payload': payload,
                        'severity': 'Critical'
                    })
            except:
                continue
        return vulnerabilities
    
    # ========== INTERNET SECURITY: SSL/TLS Testing ==========
    def test_tls(self) -> List[Dict]:
        """Test SSL/TLS configuration"""
        vulnerabilities = []
        
        # Check for weak protocols
        weak_protocols = ['SSLv3', 'TLSv1.0', 'TLSv1.1']
        for protocol in weak_protocols:
            try:
                # Use openssl to test
                cmd = f"openssl s_client -connect {self.target_url.replace('https://', '')} -{protocol.lower()}"
                result = subprocess.run(cmd, shell=True, timeout=5, capture_output=True)
                if 'CONNECTED' in result.stdout.decode():
                    vulnerabilities.append({
                        'type': 'Weak SSL/TLS Protocol',
                        'details': f'{protocol} is supported',
                        'severity': 'High'
                    })
            except:
                pass
        
        # Check for HSTS
        try:
            response = requests.get(self.target_url)
            if 'strict-transport-security' not in response.headers:
                vulnerabilities.append({
                    'type': 'Missing HSTS Header',
                    'severity': 'Medium'
                })
        except:
            pass
        
        return vulnerabilities
    
    # ========== CYBERSECURITY: Full Scan ==========
    def run_full_scan(self):
        """Run all security tests"""
        endpoints = ['/api/auth/login', '/api/transactions', '/search', '/login']
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            # Run XSS tests
            xss_futures = [executor.submit(self.test_xss, endpoint) for endpoint in endpoints]
            for future in xss_futures:
                self.results['vulnerabilities'].extend(future.result())
            
            # Run SQLi tests
            sqli_futures = [executor.submit(self.test_sqli, endpoint) for endpoint in endpoints]
            for future in sqli_futures:
                self.results['vulnerabilities'].extend(future.result())
            
            # Run TLS tests
            tls_future = executor.submit(self.test_tls)
            self.results['vulnerabilities'].extend(tls_future.result())
        
        # Generate report
        self.generate_report()
        
    def generate_report(self):
        """Generate security report"""
        report = {
            'summary': {
                'total_vulnerabilities': len(self.results['vulnerabilities']),
                'critical': sum(1 for v in self.results['vulnerabilities'] if v.get('severity') == 'Critical'),
                'high': sum(1 for v in self.results['vulnerabilities'] if v.get('severity') == 'High'),
                'medium': sum(1 for v in self.results['vulnerabilities'] if v.get('severity') == 'Medium'),
            },
            'details': self.results['vulnerabilities'],
            'recommendations': [
                'Implement input validation and sanitization',
                'Use parameterized queries for database operations',
                'Enable HSTS and disable weak TLS protocols',
                'Implement Content Security Policy (CSP)',
                'Regular security training for developers'
            ]
        }
        
        # Save report
        with open(f'reports/security_audit_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"📊 Security report generated: {len(report['details'])} vulnerabilities found")
        
        # Print summary
        print("\n" + "="*50)
        print("🔒 SECURITY AUDIT SUMMARY")
        print("="*50)
        print(f"Total Vulnerabilities: {report['summary']['total_vulnerabilities']}")
        print(f"  Critical: {report['summary']['critical']}")
        print(f"  High:     {report['summary']['high']}")
        print(f"  Medium:   {report['summary']['medium']}")
        print("\n📝 Recommendations:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"  {i}. {rec}")
        print("="*50)

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://localhost:3000"
    auditor = SecurityAudit(target)
    auditor.run_full_scan()
