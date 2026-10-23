import sys
import json
import urllib3
import requests
from typing import Dict, Any, List

# Suppress insecure HTTPS warnings if self-signed certificates are encountered
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Key security headers and their security functions
RECOMMENDED_HEADERS = {
    'Strict-Transport-Security': {
        'weight': 20,
        'description': 'Enforces HTTPS encrypted connections (HSTS)',
        'recommendation': 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains"'
    },
    'Content-Security-Policy': {
        'weight': 25,
        'description': 'Mitigates XSS, clickjacking, and code injection attacks',
        'recommendation': "Add 'Content-Security-Policy: default-src \"self\";'"
    },
    'X-Frame-Options': {
        'weight': 15,
        'description': 'Protects against clickjacking attacks',
        'recommendation': 'Add "X-Frame-Options: DENY" or "SAMEORIGIN"'
    },
    'X-Content-Type-Options': {
        'weight': 15,
        'description': 'Prevents MIME-type sniffing vulnerabilities',
        'recommendation': 'Add "X-Content-Type-Options: nosniff"'
    },
    'Referrer-Policy': {
        'weight': 10,
        'description': 'Controls leakage of sensitive referrer information',
        'recommendation': 'Add "Referrer-Policy: strict-origin-when-cross-origin"'
    },
    'Permissions-Policy': {
        'weight': 15,
        'description': 'Restricts browser features and APIs (camera, geolocation)',
        'recommendation': 'Add "Permissions-Policy: camera=(), microphone=()"'
    }
}


def audit_cors(response_headers: Dict[str, str], test_origin: str) -> Dict[str, Any]:
    """
    Evaluates Access-Control-* CORS headers for permissive or dangerous configurations.
    """
    cors_origin = response_headers.get('Access-Control-Allow-Origin') or response_headers.get('access-control-allow-origin')
    cors_credentials = response_headers.get('Access-Control-Allow-Credentials') or response_headers.get('access-control-allow-credentials')
    
    result = {
        'status': 'SECURE',
        'origin_allowed': cors_origin,
        'credentials_allowed': cors_credentials,
        'details': []
    }

    if not cors_origin:
        result['status'] = 'RESTRICTED'
        result['details'].append("No Access-Control-Allow-Origin header detected (Default Same-Origin Policy enforced).")
    elif cors_origin == '*':
        result['status'] = 'WARNING'
        result['details'].append("Wildcard '*' origin detected: Any website can make cross-origin reads.")
    elif cors_origin == test_origin:
        result['status'] = 'CRITICAL'
        result['details'].append(f"Origin Reflection Detected: Server dynamically allowed untrusted origin '{test_origin}'.")
        if str(cors_credentials).lower() == 'true':
            result['details'].append("CRITICAL RISK: Access-Control-Allow-Credentials is set to TRUE with reflected origin!")

    return result


def audit_headers(response_headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Checks target response headers against recommended security headers and computes a security score.
    """
    # Normalize headers to lowercase for reliable matching
    normalized_headers = {k.lower(): v for k, v in response_headers.items()}

    passed = []
    missing = []
    score = 0

    for header_name, info in RECOMMENDED_HEADERS.items():
        lower_name = header_name.lower()
        if lower_name in normalized_headers:
            score += info['weight']
            passed.append({
                'header': header_name,
                'value': normalized_headers[lower_name],
                'description': info['description']
            })
        else:
            missing.append({
                'header': header_name,
                'description': info['description'],
                'recommendation': info['recommendation']
            })

    return {
        'score': score,
        'passed': passed,
        'missing': missing
    }


def scan_target(target_url: str):
    """
    Performs HTTP audit against the specified URL target.
    """
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    print(f"\n{'='*60}")
    print(f"  WEB SECURITY & CORS AUDITOR")
    print(f"  Target: {target_url}")
    print(f"{'='*60}\n")

    attacker_origin = "https://evil-attacker.com"
    custom_headers = {
        'User-Agent': 'SecAudit-Scanner/1.0',
        'Origin': attacker_origin
    }

    try:
        response = requests.get(
            target_url,
            headers=custom_headers,
            timeout=10,
            verify=False,
            allow_redirects=True
        )

        print(f"[+] HTTP Status Code: {response.status_code}")
        print(f"[+] Final Redirect URL: {response.url}\n")

        # 1. Audit Headers
        header_results = audit_headers(response.headers)
        print(f"--- SECURITY HEADERS ANALYSIS (Score: {header_results['score']}/100) ---")
        
        print("\n[✓] PASSED HEADERS:")
        if header_results['passed']:
            for item in header_results['passed']:
                print(f"  • {item['header']}: {item['value']}")
        else:
            print("  (None found)")

        print("\n[✗] MISSING OR WEAK HEADERS:")
        if header_results['missing']:
            for item in header_results['missing']:
                print(f"  • {item['header']}")
                print(f"    - Purpose: {item['description']}")
                print(f"    - Fix:     {item['recommendation']}")
        else:
            print("  (All standard security headers are set!)")

        # 2. Audit CORS Policy
        print("\n--- CORS POLICY ANALYSIS ---")
        cors_results = audit_cors(response.headers, attacker_origin)
        print(f"[-] Status: {cors_results['status']}")
        print(f"[-] Allowed Origin: {cors_results['origin_allowed'] or 'Not Specified'}")
        print(f"[-] Credentials Flag: {cors_results['credentials_allowed'] or 'Not Specified'}")
        
        for detail in cors_results['details']:
            print(f"  ↳ {detail}")

        print(f"\n{'='*60}\n")

    except requests.exceptions.RequestException as e:
        print(f"[!] Scan Error: Failed to reach target target '{target_url}'.")
        print(f"    Details: {e}\n")


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
    scan_target(target)