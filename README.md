# VAPT Agents - Vulnerability Assessment & Penetration Testing with AI

A powerful AI-driven vulnerability assessment and penetration testing framework built using CrewAI. This project leverages multiple specialized AI agents to perform comprehensive security assessments, from network reconnaissance to detailed vulnerability reporting.

## 🚀 Overview

VAPT Agents automates the vulnerability assessment process through three specialized AI agents:

- **Reconnaissance Specialist**: Network discovery and host enumeration
- **Comprehensive Vulnerability Scanner**: Deep vulnerability detection using multiple tools
- **Report Generator**: Professional security assessment reporting

## 🏗️ Architecture

```
VAPT-Agents/
├── agents.py          # AI agent definitions and configurations
├── tasks.py           # Task definitions for each assessment phase
├── tools.py           # Security scanning tool implementations
├── crew.py            # CrewAI orchestration and execution logic
├── requirement.txt    # Python dependencies
└── README.md          # This file
```

## 🛠️ Features

### Current Capabilities
- **Network Reconnaissance**: Host discovery, port scanning, OS detection
- **Vulnerability Scanning**: Multiple tool integration (Nmap NSE, Nessus*, OpenVAS*)
- **Intelligent Reporting**: Automated report generation with OWASP ASVS mapping
- **Multi-Agent Coordination**: Seamless workflow between specialized agents
- **Structured Output Management**: Export results in JSON, HTML, CSV, XML, TXT, YAML
- **Command-line Interface**: Manage, convert, and export scan results via `output_cli.py`
- **Demo & File I/O**: Demonstration of output and file operations via `output_demo.py`

*Note: Nessus and OpenVAS integrations are currently placeholder implementations*

### Security Tools Integrated
- **Nmap**: Network discovery and reconnaissance
- **Nmap NSE Scripts**: Advanced vulnerability detection
- **Nessus**: Professional vulnerability scanner (placeholder)
- **OpenVAS**: Open-source vulnerability scanner (placeholder)

## 📋 Prerequisites

### System Requirements
- Python 3.8 or higher
- Nmap installed and accessible via command line
- Administrative privileges for network scanning

### Optional Tools
- Nessus (for professional vulnerability scanning)
- OpenVAS/GVM (for open-source vulnerability scanning)

---

## 🔧 Installation

1. **Clone the repository**:
```bash
git clone <repository-url>
cd vapt-agents
```

2. **Install Python dependencies**:
```bash
pip install -r requirements.txt
```

3. **Install Nmap**:
   - **Windows**: Download from [nmap.org](https://nmap.org/download.html)
   - **Linux**: `sudo apt-get install nmap` (Ubuntu/Debian) or `sudo yum install nmap` (RHEL/CentOS)
   - **macOS**: `brew install nmap`

4. **Verify installation**:
```bash
nmap --version
python -c "import crewai; print('CrewAI installed successfully')"
```

## 🚀 Usage

### Basic Usage

Run the vulnerability assessment with an interactive prompt:

```bash
python crew.py
```

When prompted, enter the target IP address or hostname:
```
Enter the target IP or hostname: 192.168.1.1
```

### Programmatic Usage

```python
from crew import execute_vuln_scan

# Scan a single target
target = "192.168.1.100"
result = execute_vuln_scan(target)
print(result)
```

### Example Output

The assessment will proceed through three phases:

1. **Reconnaissance Phase**: Network discovery and enumeration
2. **Vulnerability Scanning Phase**: Deep security analysis
3. **Report Generation Phase**: Comprehensive security report

## 📊 Report Structure

Generated reports include:

- **Executive Summary**: High-level security posture overview
- **Detailed Findings**: Individual vulnerabilities with risk ratings
- **Exploitation Details**: Technical details and proof-of-concept
- **OWASP ASVS Mapping**: Compliance framework alignment
- **Remediation Guidance**: Actionable security recommendations

## ⚙️ Configuration


### Agent Configuration

Modify `agents.py` to customize agent behavior:

```python
vuln_scan_agent = Agent(
    role="Reconnaissance Specialist",
    goal="Run reconnaissance on target and record findings",
    # Customize agent parameters
    verbose=True,
    allow_delegation=True,
    memory=True
)
```

### Tool Configuration

Customize scan parameters in `tools.py`:

```python
# Modify Nmap scan parameters
cmd = ["nmap", "-A", "-T4", target]  # Aggressive scan with timing template 4
```

### Configuration & Validation

- All configuration is managed via `config.py` and can be updated at runtime or via environment variables.
- Input validation and error handling are robust, using `TargetValidator` and `ConfigValidator` in `validation.py`.
- Forbidden targets (e.g., `.gov`, `.mil`, banks, hospitals) are blocked by default.
- Results and metadata are stored in `scan_results/scan_metadata.db` (SQLite database).

---

## 🔒 Security Considerations

### Legal and Ethical Use

⚠️ **IMPORTANT**: This tool is intended for authorized security testing only.

- **Only scan systems you own or have explicit permission to test**
- **Obtain proper authorization before conducting any security assessments**
- **Comply with all applicable laws and regulations**
- **Respect network resources and avoid causing service disruptions**


### Basic Usage

Run the vulnerability assessment with an interactive prompt:

```bash
python crew.py
```

When prompted, enter the target IP address or hostname:
```
Enter the target IP or hostname: 192.168.1.1
```

### Programmatic Usage

```python
from crew import execute_vuln_scan

# Scan a single target
    backstory="Expert in custom security domain",
result = execute_vuln_scan(target)
print(result)
```

### Example Output

The assessment will proceed through three phases:

1. **Reconnaissance Phase**: Network discovery and enumeration
2. **Vulnerability Scanning Phase**: Deep security analysis
3. **Report Generation Phase**: Comprehensive security report

---

## 🖨️ Output Management & CLI

- Scan results can be exported in multiple formats: JSON, HTML, CSV, XML, TXT, YAML.
- Use the CLI tool for managing and converting results:
    ```bash
    python output_cli.py list                # List recent scans
    python output_cli.py show <scan_id>      # Show scan details
    python output_cli.py convert <scan_id> html   # Convert to HTML
    python output_cli.py export --target <target> --formats json html csv
    python output_cli.py stats               # Show statistics
    ```
- See `output_demo.py` for a demonstration of all output features, file I/O, and agent result pipelines.

---

## 🧑‍💻 Example Usage

- See `example_usage.py` for programmatic examples, including:
    - Basic scan
    - Comprehensive scan
    - Batch scan (multiple targets)
    - Configuration management
    - Error handling and validation

---
    tools=["custom_tool"],
    verbose=True
)
```

## 🐛 Troubleshooting

### Common Issues

1. **Nmap not found**: Ensure Nmap is installed and in system PATH
2. **Permission denied**: Run with appropriate privileges for network scanning
3. **Timeout errors**: Adjust timeout values in tool implementations
4. **Import errors**: Verify all dependencies are installed correctly

### Debug Mode

Enable verbose logging by setting `verbose=True` in agent configurations:

```python
vuln_scan_agent = Agent(
    # ... other parameters
    verbose=True  # Enable detailed logging
)
```
### Validation & Error Handling

This project includes robust input validation and error handling to ensure safe and reliable operation:

- **Input Validation**: All scan targets (IP addresses, domains) are validated using the `TargetValidator` class in `validation.py`. This prevents accidental scanning of private, government, or restricted networks.
- **Custom Exceptions**: The codebase defines custom exceptions (`ValidationError`, `NetworkError`, `ScanTimeoutError`) for clear error reporting and troubleshooting.
- **Logging**: All validation and scan operations are logged to `vapt_agents.log` for auditability and debugging.

**Example: Validating a Target**

## 🚧 Known Limitations


### Current Limitations

1. **Placeholder Integrations**: Nessus and OpenVAS tools require actual implementation
2. **Limited Error Handling**: Basic error handling implemented
3. **No Authentication**: Tools don't support authenticated scanning
4. **Basic Reporting**: Report generation needs enhancement
5. **Single Target**: No support for multiple targets or subnet scanning
6. **No Web Dashboard**: Only CLI and file-based outputs are available

### Planned Enhancements

- [ ] Full Nessus API integration
- [ ] OpenVAS/GVM integration
- [ ] Web application scanning (Burp Suite, OWASP ZAP)
- [ ] Database security assessment
- [ ] Enhanced reporting with risk scoring
- [ ] Multi-target support
- [ ] Configuration file support
- [ ] Web dashboard interface

---

## 🧪 Demo

- Run `python output_demo.py` to see output formatting, file I/O, and agent pipeline features in action.
- Output files are saved in `demo_results/` and `file_demo_outputs/`.

---

## 🤝 Contributing

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make changes and test thoroughly
4. Submit a pull request with detailed description

### Code Style

- Follow PEP 8 Python style guidelines
- Add docstrings to all functions and classes
- Include type hints where appropriate
- Write descriptive commit messages

### Security Guidelines

- Never include credentials in code
- Validate all user inputs
- Follow secure coding practices
- Test with authorized targets only

## 📄 License

This project is intended for educational and authorized security testing purposes only. Users are responsible for compliance with applicable laws and regulations.

## 🆘 Support

### Getting Help

1. **Documentation**: Check this README and code comments
2. **Issues**: Create GitHub issues for bugs or feature requests
3. **Security**: Report security vulnerabilities privately

### Resources

- [CrewAI Documentation](https://docs.crewai.com/)
- [Nmap Documentation](https://nmap.org/docs.html)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [Vulnerability Assessment Best Practices](https://owasp.org/www-community/Vulnerability_Scanning_Tools)

## 📚 References

- **CrewAI Framework**: Multi-agent AI orchestration
- **OWASP ASVS**: Application Security Verification Standard
- **NIST Cybersecurity Framework**: Security assessment guidelines
- **PTES**: Penetration Testing Execution Standard

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Users must obtain proper authorization before scanning any systems. Unauthorized scanning may be illegal and unethical.
