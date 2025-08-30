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

## 🔧 Installation

1. **Clone the repository**:
```bash
git clone <repository-url>
cd vapt-agents
```

2. **Install Python dependencies**:
```bash
pip install -r requirement.txt
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

## 🔒 Security Considerations

### Legal and Ethical Use

⚠️ **IMPORTANT**: This tool is intended for authorized security testing only.

- **Only scan systems you own or have explicit permission to test**
- **Obtain proper authorization before conducting any security assessments**
- **Comply with all applicable laws and regulations**
- **Respect network resources and avoid causing service disruptions**

### Best Practices

1. **Scope Validation**: Always verify target authorization
2. **Rate Limiting**: Use appropriate scan timing to avoid detection
3. **Data Protection**: Secure scan results and reports
4. **Responsible Disclosure**: Follow proper vulnerability disclosure practices

## 🔧 Advanced Configuration

### Custom Tool Integration

Add new security tools by extending the `BaseTool` class:

```python
class CustomScanTool(BaseTool):
    name = "custom_scanner"
    description = "Custom vulnerability scanner implementation"
    
    def run(self, target: str) -> str:
        # Implement your custom tool logic
        pass
```

### Agent Customization

Modify agent behavior by updating goals and backstories:

```python
custom_agent = Agent(
    role="Custom Security Specialist",
    goal="Perform specialized security assessment",
    backstory="Expert in custom security domain",
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

### Planned Enhancements

- [ ] Full Nessus API integration
- [ ] OpenVAS/GVM integration
- [ ] Web application scanning (Burp Suite, OWASP ZAP)
- [ ] Database security assessment
- [ ] Enhanced reporting with risk scoring
- [ ] Multi-target support
- [ ] Configuration file support
- [ ] Web dashboard interface

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
