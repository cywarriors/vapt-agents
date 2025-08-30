from crewai import Agent, Task, Crew, LLM
from tools import NmapReconTool, NessusScanTool, OpenVASScanTool, NmapNSETool, ReportWriterTool
from dotenv import load_dotenv

# Instantiate tools with proper configuration
nmap_tool = NmapReconTool(timeout=300, timing_template="T3")
nessus_tool = NessusScanTool(timeout=1800)
openvas_tool = OpenVASScanTool(timeout=1800)
nmap_nse_tool = NmapNSETool(timeout=600)
report_writer_tool = ReportWriterTool(output_format="text", include_executive_summary=True)

#Load environment variables
load_dotenv()
#Instantiate LLM
llm = LLM(
    model="gemini/gemini-2.0-flash",
    temperature=0.1
)


##Create a agents like Reconnaissance Specialist, Comprehensive Vulnerability Scanner and Report Generator for Vulnerability Scanning

#Create Reconnaissance Specialist agent for Vulnerability Scanning
vuln_scan_agent = Agent(
    role="Reconnaissance Specialist",
    goal="""
        - Run Reconnaissance on the target{target}
        - Record OS versions, open ports, and banner information
    """,
    backstory=(
        "An expert in network reconnaissance, skilled in using tools like nmap to map out network topologies, "
        "identify live hosts, discover open ports, and gather detailed service and OS information for vulnerability assessment."
    ),
    tools=[nmap_tool],
    verbose=True,
    allow_delegation=True,
    memory=True,
    llm=llm

)

#Create Comprehensive Vulnerability Scanner agent for Vulnerability Scanning
vuln_comprehensive_scanner_agent = Agent(
    role="Comprehensive Vulnerability Scanner",
    goal="""
        - Take reconnaissance findings and perform in-depth vulnerability scanning
        - Detect known vulnerabilities in network services, misconfigurations, and outdated firmware
        - Utilize multiple scanning tools for thorough coverage
        - Correlate and prioritize findings for remediation
    """,
    backstory=(
        "A seasoned vulnerability analyst, adept at leveraging advanced scanning tools such as Nessus, Qualys, OpenVAS, and Nmap NSE scripts. "
        "This agent builds upon reconnaissance data to uncover deep-seated flaws, misconfigurations, and exposures in networked systems, "
        "ensuring a comprehensive security assessment."
    ),
    tools=[nessus_tool, openvas_tool, nmap_nse_tool],
    verbose=True,
    allow_delegation=True,
    memory=True,
    llm=llm
)

#Create Report Generator agent for Vulnerability Scanning
report_generator_agent = Agent(
    role="Report Generator",
    goal="""
        - Compile vulnerability assessment findings into a comprehensive report
        - Document vulnerability details, risk ratings, exploitation steps, and remediation guidance
        - Map each finding to relevant OWASP ASVS categories
        - Ensure the report is clear, actionable, and suitable for both technical and non-technical stakeholders
    """,
    backstory=(
        "A meticulous security analyst specializing in transforming raw vulnerability data into structured, insightful reports. "
        "Expert in risk communication, remediation planning, and aligning findings with industry standards such as OWASP ASVS. "
        "Ensures that every report provides actionable guidance and clear mapping to security requirements."
    ),
    tools=[report_writer_tool],
    verbose=True,
    allow_delegation=False,
    memory=True,
    llm=llm
)
