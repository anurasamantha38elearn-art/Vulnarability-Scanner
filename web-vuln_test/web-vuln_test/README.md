# CODEXIO Web Vulnerability Scanner

A comprehensive web application vulnerability scanner that combines automated security testing with AI-powered vulnerability analysis and solutions.

## 🚀 Features

### **Frontend (PHP + HTML + JavaScript)**
- Modern, responsive web interface
- Real-time scan progress tracking
- Interactive vulnerability display
- PDF report generation
- Bootstrap-based UI design

### **Backend (Python)**
- **Advanced Vulnerability Detection:**
  - SQL Injection testing
  - Cross-Site Scripting (XSS) detection
  - Directory traversal vulnerability checks
  - Security header analysis
  - HTTP method testing
  - Common file/directory enumeration
  - SSL/TLS certificate validation

- **AI-Powered Analysis:**
  - Google Gemini AI integration
  - Automated vulnerability assessment
  - Detailed remediation solutions
  - Code examples for fixes
  - Preventive security measures

- **Comprehensive Reporting:**
  - Multiple output formats (JSON, TXT, CSV)
  - Detailed vulnerability descriptions
  - Severity classification
  - AI-generated solutions
  - Scan metadata and timestamps

## 🛠️ Installation

### Prerequisites
- **XAMPP** (Apache + PHP)
- **Python 3.7+**
- **Google Gemini API Key** (for AI analysis)

### Setup Steps

1. **Clone/Download the project** to your XAMPP htdocs folder
2. **Run the setup script:**
   ```bash
   setup.bat
   ```
   This will:
   - Check Python installation
   - Install required dependencies
   - Verify setup completion

3. **Configure API Key:**
   - Edit `Backend/codexiovuln.py`
   - Replace the API key on line 32:
     ```python
     os.environ['GEMINI_API_KEY'] = 'YOUR_API_KEY_HERE'
     ```
   - Or set as environment variable: `GEMINI_API_KEY=your_key_here`

4. **Start XAMPP:**
   - Start Apache service
   - Navigate to `http://localhost/web-vuln_test`

## 📖 Usage

### **Basic Scanning**
1. Enter target URL in the input field
2. Click "Scan" button
3. Wait for scan completion
4. View results in the right panel

### **Understanding Results**
- **Left Panel:** Scan summary and progress
- **Right Panel:** Detailed vulnerability report with AI solutions

### **PDF Report Generation**
1. Complete a scan
2. Click "Generate PDF Report" button
3. Download comprehensive security report

## 🔧 Configuration

### **Scan Levels**
- **Level 1 (Low):** Basic checks, minimal impact
- **Level 2 (Medium):** Standard checks, moderate coverage
- **Level 3 (High):** Comprehensive checks, maximum coverage

### **Python Backend Options**
```bash
python Backend/codexiovuln.py --help
```

Key options:
- `--url`: Target URL to scan
- `--level`: Scan intensity (1-3)
- `--ai-analysis`: Enable AI analysis
- `--format`: Output format (json, txt, csv)
- `--timeout`: Request timeout in seconds
- `--threads`: Number of concurrent threads

## 🏗️ Architecture

```
Frontend (PHP) ←→ Backend (Python)
     ↓                    ↓
  User Interface    Vulnerability Scanner
     ↓                    ↓
  PDF Generation    AI Analysis Engine
     ↓                    ↓
  Results Display   Security Reports
```

### **Data Flow**
1. User submits URL via PHP form
2. PHP executes Python scanner with parameters
3. Python performs comprehensive security tests
4. AI analysis generates solutions for found vulnerabilities
5. Results returned to PHP as JSON
6. Frontend displays results and enables PDF export

## 🚨 Security Features

### **Vulnerability Detection**
- **SQL Injection:** Tests for database vulnerabilities
- **XSS:** Cross-site scripting detection
- **Path Traversal:** Directory traversal prevention
- **Security Headers:** Missing security header identification
- **HTTP Methods:** Dangerous method detection
- **File Enumeration:** Sensitive file discovery

### **AI-Powered Solutions**
- **Automated Analysis:** Instant vulnerability assessment
- **Remediation Steps:** Step-by-step fix instructions
- **Code Examples:** Practical implementation guidance
- **Prevention Tips:** Long-term security strategies

## 📊 Output Formats

### **JSON Output**
```json
{
  "target": "example.com",
  "timestamp": "2025-01-01T12:00:00",
  "scan_level": 2,
  "results": [...],
  "vulnerabilities": [...]
}
```

### **PDF Report**
- Executive summary
- Detailed vulnerability analysis
- AI-generated solutions
- Risk assessment
- Remediation timeline

## 🔍 Troubleshooting

### **Common Issues**

1. **Python Not Found:**
   - Ensure Python is installed and in PATH
   - Run `setup.bat` to verify installation

2. **Dependencies Missing:**
   - Run `pip install -r Backend/requirements.txt`
   - Check Python version compatibility

3. **API Key Issues:**
   - Verify Google Gemini API key is valid
   - Check API quota and limits

4. **Scan Failures:**
   - Verify target URL accessibility
   - Check firewall/network settings
   - Review scan parameters

### **Debug Mode**
Enable debug mode for detailed output:
```bash
python Backend/codexiovuln.py --url example.com --debug
```

## 📝 API Reference

### **Google Gemini Integration**
- **Model:** gemini-1.5-flash
- **Purpose:** Vulnerability analysis and solution generation
- **Rate Limiting:** Built-in delays to respect API limits
- **Error Handling:** Graceful fallback for API failures

### **HTTP Request Handling**
- **User Agents:** Randomized to avoid detection
- **Timeouts:** Configurable request timeouts
- **Redirects:** Configurable redirect following
- **SSL Verification:** Optional SSL certificate validation

## 🤝 Contributing

### **Development Setup**
1. Fork the repository
2. Create feature branch
3. Implement changes
4. Test thoroughly
5. Submit pull request

### **Code Standards**
- Follow PEP 8 for Python code
- Use meaningful variable names
- Add comprehensive comments
- Include error handling

## 📄 License

This project is proprietary software. All rights reserved by CODEXIO™.

## ⚠️ Disclaimer

**This tool is for educational and authorized security testing purposes only.**
- Only scan systems you own or have explicit permission to test
- Respect rate limits and scanning policies
- Follow responsible disclosure practices
- Comply with applicable laws and regulations

## 📞 Support

For technical support or questions:
- Check the troubleshooting section
- Review error logs
- Verify configuration settings
- Ensure all dependencies are installed

---

**CODEXIO™ - Advanced Web Security Solutions**
