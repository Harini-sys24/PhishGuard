# PhishGuard - Java OOPS Project

## Requirements
- JDK 8 or later
- Terminal / Command Prompt

## Compile
Open a terminal in the `PhishGuard` folder and run:

    javac -d out src/*.java

## Run

    java -cp out Main

## Batch scanning
Create a text file such as `data/urls.txt`, with one URL per line.
Choose option 3 and enter `data/urls.txt`.

## Project features
- URL analysis and suspicious indicator extraction
- Email/SMS keyword analysis and embedded URL extraction
- Rule-based risk scoring (0-100)
- LOW / MEDIUM / HIGH classification
- Batch scanning with ExecutorService
- Scan history and text reports
- SHA-256 URL/message fingerprints
- HMAC-SHA256 history integrity verification

## Important limitations
This is an educational rule-based prototype, not a guarantee that a URL is safe or malicious.
It does not contact websites or query threat-intelligence services. A low score does not prove
that a website is safe.

The HMAC key is stored locally in `config/secret.key` for demonstration. A production system
would need stronger key protection and a trusted way to protect the authentication code too.
Do not use this prototype to make security-critical decisions.
