# WebScanner
Automated Web Scanner


Project Description

Automated Web Scanner is a Python-based tool that checks selected HTTP security headers and examines selected Cross-Origin Resource Sharing (CORS) response headers.

The program calculates a security-header score out of 100, lists detected and missing headers, provides recommendations, and displays CORS analysis in the terminal.

Features

- Checks six recommended HTTP security headers.
- Calculates a weighted security-header score out of 100.
- Lists detected security headers and their values.
- Identifies missing headers and provides recommendations.
- Examines "Access-Control-Allow-Origin".
- Examines "Access-Control-Allow-Credentials".
- Displays the HTTP response status and final redirect URL.
- Handles HTTP request exceptions.

Technologies Used

- Python 3
- Requests
- urllib3
- Visual Studio Code

Project Files

- "Muthumani_AutomatedWebScanner.py" — Main scanner program.
- "requirements.txt" — Required Python packages.
- "Muthumani_AutomatedWebScannerReport.docx" — Project report.
- "README.md" — Project documentation.

Installation

Install Python 3 and open a terminal in the project folder.

Install the required dependencies:

pip install -r requirements.txt

How to Run

Run the scanner with a target URL:

python Muthumani_AutomatedWebScanner.py https://example.com

If no URL is provided, the program uses "https://example.com" by default.

Replace the example URL with a website you own or are explicitly authorized to test.

Security Headers Checked

Header| Purpose| Weight
Strict-Transport-Security| Helps enforce HTTPS| 20
Content-Security-Policy| Restricts permitted content sources| 25
X-Frame-Options| Helps prevent clickjacking| 15
X-Content-Type-Options| Helps prevent MIME-type sniffing| 15
Referrer-Policy| Controls referrer information| 10
Permissions-Policy| Restricts selected browser features| 15

The score is calculated by adding the weights of the headers found in the response.

CORS Analysis

The program sends a test Origin header:

"https://evil-attacker.com"

It examines the response's "Access-Control-Allow-Origin" and "Access-Control-Allow-Credentials" headers.

The scanner reports selected configurations for further investigation. Its CORS results are preliminary indicators and do not independently prove a vulnerability.

Dataset

No separate dataset is required. The program analyzes HTTP response headers retrieved from the specified website.

Limitations

- Checks only predefined security headers.
- Does not perform a complete vulnerability assessment.
- Does not independently confirm data exposure through CORS.
- Uses a basic scoring system based on header presence.
- Disables HTTPS certificate verification in the current implementation.

Ethical Use

Use this scanner only on websites you own or have explicit permission to assess. Follow applicable laws and the website owner's policies.

Future Enhancements

- Improve CORS validation.
- Enable HTTPS certificate verification.
- Export scan results to JSON or HTML reports.
- Add additional security checks.
- Develop a graphical user interface.
- Improve error handling and security scoring.
