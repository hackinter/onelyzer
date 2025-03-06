<div align="center">
  <a href="https://github.com/github/hackathons">
    <img src="https://github.com/github/hackathons/blob/main/.github/images/GitHub%20Hackathons%20Logo.png" width="100">
  </a>
</div>


# Onelyzer
<div align="center">
  <a href="https://github.com/hackinter/onelyzer/releases">
    <img src="https://img.shields.io/badge/Version-1.0.0-blue.svg" alt="Version"> 
  </a>
  <a href="https://github.com/hackinter">
    <img src="https://img.shields.io/badge/GITHUB-HACKINTER-red.svg" alt="GitHub">
  </a>
</div>


**Onelyzer** is an advanced security testing tool designed for analyzing the security of websites by detecting common vulnerabilities such as XSS, SQL Injection, and more. It provides a comprehensive overview of various security parameters, including server response times, tech stack, and SSL certificate validity, making it an essential tool for ethical hackers and penetration testers.

## Features

- 🛠️ **Automated Vulnerability Detection**: Detects various security vulnerabilities like XSS, SQL Injection, etc.
- 🌐 **Complete Website Analysis**: Provides detailed information about the target website, including IP address, WHOIS registrar, SSL certificate expiration, tech stack, response times, and more.
- 📊 **Performance Metrics**: Measures server response time and DNS resolution time for better performance insights.
- 📝 **HTML Report Generation**: Saves the analysis results in a well-structured HTML file, which can be reviewed and shared.
- 🔒 **Ethical Hacking Focus**: Designed for ethical use only, ensuring authorized testing of web applications.

## Requirements

- **Python 3.x**
- `requests` library (install using `pip install requests`)

## Installation

1. **Clone the Repository**:
   Clone the repository to your local machine by running:

   ```bash
   git clone https://github.com/hackinter/onelyzer.git
   cd onelyzer
   ```

2. **Install Dependencies**:
   Install the necessary Python dependencies:

   ```bash
   pip install requests
   ```

## Usage

### Running the Tool

1. **Launch the Script**:
   To start the tool, run the following command:

   ```bash
   python3 onelyzer_pro.py
   ```

2. **Input the Target Website**:
   You will be prompted to enter the website URL that you want to analyze:

   ```bash
   Enter website URL: https://github.com/
   ```

3. **Analyze the Results**:
   After the scan is complete, the tool will display the following key information:

   - **IP Address**: The target website's IP address.
   - **WHOIS Registrar**: The domain registrar information for the website.
   - **SSL Expiry**: The expiration date of the SSL certificate.
   - **Response Time**: The server's response time in milliseconds.
   - **DNS Resolution Time**: The time it takes to resolve the domain via DNS.
   - **HTTP Version**: The HTTP version used by the server.
   - **Tech Stack**: The technologies (e.g., ReactJS, Java, Go) used by the website.
   - **Detected Vulnerabilities**: The number of security vulnerabilities detected on the site.

4. **Result Saving (HTML Format)**:
   After completing the analysis, the results will be saved in a **detailed HTML report** that you can open in any browser. The HTML file will be named based on the domain being tested, such as:

   ```
   Detailed HTML report saved as github.com.html
   ```

   You can view this file in your browser to get a structured overview of the vulnerabilities, performance metrics, and other findings.

### Example Output

Here’s a sample of the data that the tool will display in your terminal:

```
                    Executive Summary
┏━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Feature                  ┃ Detected                    ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ URL                      │ https://github.com/         │
├──────────────────────────┼─────────────────────────────┤
│ IP Address               │ 20.205.243.166              │
├──────────────────────────┼─────────────────────────────┤
│ WHOIS Registrar          │ MarkMonitor, Inc.           │
├──────────────────────────┼─────────────────────────────┤
│ SSL Expiry               │ 2026-02-05                  │
├──────────────────────────┼─────────────────────────────┤
│ Response Time (ms)       │ 274.82                      │
├──────────────────────────┼─────────────────────────────┤
│ DNS Resolution Time (ms) │ 4.63                        │
├──────────────────────────┼─────────────────────────────┤
│ HTTP Version             │ HTTP/1.1                    │
├──────────────────────────┼─────────────────────────────┤
│ Tech Stack               │ ReactJS, Java, Ember.js, Go │
├──────────────────────────┼─────────────────────────────┤
│ Vulnerabilities          │ 5 items                     │
└──────────────────────────┴─────────────────────────────┘
```

- **Result Report**:
  - The detailed analysis report will be saved as an **HTML file** (e.g., `github.com.html`) for easy viewing in your browser. This HTML file includes the executive summary, vulnerability details, and other technical findings.

### Error Handling

- **Lighthouse Not Found**: If you encounter an error like `/bin/sh: 1: lighthouse: not found, ' it indicates that the `lighthouse` tool is missing. You can install it via npm to use performance and SEO analysis features:

  ```bash
  npm install -g lighthouse
  ```

## Important Notes

- ⚠️ **Ethical Use**: Ensure you have explicit permission to test the website. Unauthorized testing may be illegal and could result in serious consequences.
- 🛡️ **Payloads**: Ensure you use the latest and most relevant payloads for accurate vulnerability testing.
- 🕹️ **Network Traffic**: Repeated requests to a website might trigger security measures like rate limiting or blocking. Always ensure you're testing within reasonable limits to avoid being flagged as a malicious actor.
- 📜 **Legal Compliance**: Use this tool only for authorized penetration testing. Always comply with ethical hacking guidelines and legal regulations.

## Contributing

We welcome contributions to **Onelyzer**! If you'd like to contribute:

1. Fork the repository.
2. Create a new branch for your feature or fix.
3. Submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/hackinter/onelyzer/blob/main/LICENSE) file for more details.

## Contact

For any questions or feedback, feel free to reach out:

<p align="center">
  <a href="https://twitter.com/_anonix_z">
    <img alt="Twitter" width="30px" src="https://cdn.jsdelivr.net/npm/simple-icons@v3/icons/twitter.svg"/>
  </a>
  <a href="https://linkedin.com/in/no_acca">
    <img alt="LinkedIn" width="30px" src="https://cdn.jsdelivr.net/npm/simple-icons@v3/icons/linkedin.svg"/>
  </a>
  <a href="https://github.com/hackinter">
    <img alt="GitHub" width="30px" src="https://cdn.jsdelivr.net/npm/simple-icons@v3/icons/github.svg"/>
  </a>
  <a href="https://t.me/HACKINERS">
    <img alt="Telegram" width="30px" src="https://cdn.jsdelivr.net/npm/simple-icons@v3/icons/telegram.svg"/>
  </a>
  <a href="https://instagram.com/sudorootme/">
    <img alt="Instagram" width="30px" src="https://cdn.jsdelivr.net/npm/simple-icons@v3/icons/instagram.svg"/>
  </a>
  <a href="https://www.facebook.com/sudorootme/">
    <img alt="Facebook" width="30px" src="https://cdn.jsdelivr.net/npm/simple-icons@v3/icons/facebook.svg"/>
  </a>
  <a href="https://www.youtube.com/no_yt/">
    <img alt="YouTube" width="30px" src="https://cdn.jsdelivr.net/npm/simple-icons@v3/icons/youtube.svg"/>
  </a>
  <a href="mailto:ceh.ec.counselor147@gmail.com">
    <img alt="Email" width="30px" src="https://cdn.jsdelivr.net/npm/simple-icons@v3/icons/gmail.svg"/>
  </a>
</p>


