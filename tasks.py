from crewai import Task
from agents import vuln_scan_agent, vuln_comprehensive_scanner_agent, report_generator_agent
from agents import nessus_tool, nmap_tool, openvas_tool, nmap_nse_tool, report_writer_tool
# Task for Reconnaissance Specialist agent
reconnaissance_task = Task(
    description=(
        "Perform network reconnaissance on the specified target. "
        "Identify live hosts, enumerate open ports, detect operating system versions, "
        "and gather service banners. Document all findings clearly for use in subsequent vulnerability scanning."
    ),
    expected_output=(
        "A detailed list of discovered hosts, open ports, detected OS versions, "
        "and service banners for each target. The output should be structured and ready for further analysis."
    ),
    agent=vuln_scan_agent,
    tools=[nmap_tool],
    async_execution=False
)

# Task for Comprehensive Vulnerability Scanner agent
comprehensive_vuln_scan_task = Task(
    description=(
        "Using the reconnaissance findings, perform in-depth vulnerability scanning on the identified hosts and services. "
        "Utilize multiple scanning tools such as Nessus, OpenVAS, and Nmap NSE scripts to detect known vulnerabilities, "
        "misconfigurations, and outdated software. Correlate and prioritize findings for remediation."
    ),
    expected_output=(
        "A comprehensive list of vulnerabilities discovered across all scanned hosts and services, "
        "including severity ratings, affected systems, and recommended remediation steps. "
        "Findings should be organized and prioritized for further reporting."
    ),
    agent=vuln_comprehensive_scanner_agent,
    tools=[nessus_tool, openvas_tool, nmap_nse_tool ],
    async_execution=False
)

report_generation_task = Task(
    description=(
        "Compile the results from the vulnerability scanning process into a comprehensive report. "
        "Document each vulnerability with details such as risk ratings, exploitation steps, and remediation guidance. "
        "Map findings to relevant OWASP ASVS categories and ensure the report is clear, actionable, and suitable for both technical and non-technical stakeholders."
    ),
    expected_output=(
        "A well-structured vulnerability assessment report containing: "
        "1) Executive summary, 2) Detailed vulnerability findings with risk ratings and remediation steps, "
        "3) Exploitation details, 4) Mapping to OWASP ASVS categories, and 5) Recommendations for remediation. "
        "The report should be clear, actionable, and formatted for both technical and non-technical audiences."
    ),
    agent=report_generator_agent,
    tools=[report_writer_tool],
    async_execution=False
)
