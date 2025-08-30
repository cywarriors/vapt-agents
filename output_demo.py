#!/usr/bin/env python3
"""
Demonstration script for VAPT Agents Output Management features.
Shows all the new output capabilities including structured formats,
file I/O, and intermediate result storage.
"""

import uuid
import time
from datetime import datetime, timezone
from pathlib import Path

from output_manager import (
    ScanResult, ScanMetadata, Vulnerability, SeverityLevel,
    OutputFormat, ResultStorage, OutputFormatter, AgentResultPipeline,
    result_storage, output_formatter, result_pipeline
)

def create_sample_vulnerabilities():
    """Create sample vulnerabilities for demonstration."""
    vulnerabilities = [
        Vulnerability(
            id=str(uuid.uuid4()),
            name="Open SSH Port with Weak Configuration",
            severity=SeverityLevel.MEDIUM,
            cvss_score=5.3,
            description="SSH service running with weak encryption algorithms",
            affected_service="ssh",
            port=22,
            protocol="tcp",
            evidence="SSH-2.0-OpenSSH_7.4 detected with weak ciphers enabled",
            recommendation="Update SSH configuration to disable weak ciphers and enable strong authentication",
            owasp_category="A02:2021 – Cryptographic Failures"
        ),
        Vulnerability(
            id=str(uuid.uuid4()),
            name="HTTP Service Information Disclosure",
            severity=SeverityLevel.LOW,
            description="Web server reveals version information in headers",
            affected_service="http",
            port=80,
            protocol="tcp",
            evidence="Server: Apache/2.4.41 (Ubuntu)",
            recommendation="Configure web server to hide version information",
            owasp_category="A01:2021 – Broken Access Control"
        ),
        Vulnerability(
            id=str(uuid.uuid4()),
            name="Potential SQL Injection",
            severity=SeverityLevel.HIGH,
            cvss_score=8.1,
            cve_id="CVE-2023-12345",
            description="Application appears vulnerable to SQL injection attacks",
            affected_service="webapp",
            port=443,
            protocol="tcp",
            evidence="Error message revealing database structure",
            recommendation="Implement parameterized queries and input validation",
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            owasp_category="A03:2021 – Injection"
        )
    ]
    return vulnerabilities

def create_sample_scan_result(agent_name: str, tool_name: str, target: str = "demo.example.com"):
    """Create a sample scan result for demonstration."""
    scan_id = str(uuid.uuid4())
    
    metadata = ScanMetadata(
        scan_id=scan_id,
        target=target,
        target_type="hostname",
        scan_type="comprehensive",
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        duration=45.7,
        agent_name=agent_name,
        tool_name=tool_name,
        success=True
    )
    
    vulnerabilities = create_sample_vulnerabilities()
    
    raw_output = f"""Nmap scan report for {target}
Host is up (0.045s latency).
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
443/tcp  open  https      Apache httpd 2.4.41 ((Ubuntu))
3306/tcp open  mysql      MySQL 5.7.33

Nmap done: 1 IP address (1 host up) scanned in 45.67 seconds"""
    
    structured_data = {
        "ports": [
            {"port": 22, "service": "ssh", "version": "OpenSSH 7.4"},
            {"port": 80, "service": "http", "version": "Apache 2.4.41"},
            {"port": 443, "service": "https", "version": "Apache 2.4.41"},
            {"port": 3306, "service": "mysql", "version": "MySQL 5.7.33"}
        ],
        "os_detection": "Linux 4.15",
        "scan_stats": {"hosts_up": 1, "total_time": 45.67}
    }
    
    return ScanResult(
        metadata=metadata,
        vulnerabilities=vulnerabilities,
        raw_output=raw_output,
        structured_data=structured_data
    )

def demo_output_formats():
    """Demonstrate various output formats."""
    print("🎨 Output Format Demonstration")
    print("=" * 50)
    
    # Create sample scan result
    scan_result = create_sample_scan_result("demo_agent", "nmap", "demo.example.com")
    
    # Demonstrate all output formats
    formats = [
        (OutputFormat.JSON, "JSON format - structured data interchange"),
        (OutputFormat.XML, "XML format - enterprise integration"),
        (OutputFormat.HTML, "HTML format - human-readable reports"),
        (OutputFormat.CSV, "CSV format - vulnerability analysis"),
        (OutputFormat.TXT, "Plain text format - simple reporting"),
        (OutputFormat.YAML, "YAML format - configuration-friendly")
    ]
    
    results_dir = Path("demo_results")
    results_dir.mkdir(exist_ok=True)
    
    for format_type, description in formats:
        print(f"\n📄 {description}")
        print("-" * 40)
        
        try:
            formatted_output = output_formatter.format(scan_result, format_type)
            
            # Save to file
            filename = f"demo_scan.{format_type.value}"
            filepath = results_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(formatted_output)
            
            print(f"✅ Saved: {filepath}")
            
            # Show preview for some formats
            if format_type in [OutputFormat.JSON, OutputFormat.TXT]:
                preview = formatted_output[:300] + "..." if len(formatted_output) > 300 else formatted_output
                print(f"Preview:\n{preview}")
                
        except Exception as e:
            print(f"❌ Error generating {format_type.value}: {e}")

def demo_result_storage():
    """Demonstrate result storage and retrieval."""
    print("\n💾 Result Storage Demonstration")
    print("=" * 50)
    
    # Create multiple sample scan results
    scan_results = [
        create_sample_scan_result("reconnaissance_agent", "nmap", "target1.example.com"),
        create_sample_scan_result("vulnerability_scanner", "nessus", "target2.example.com"),
        create_sample_scan_result("web_scanner", "burp", "target3.example.com")
    ]
    
    stored_ids = []
    
    # Store results
    print("📥 Storing scan results...")
    for i, scan_result in enumerate(scan_results, 1):
        try:
            file_path = result_storage.store_result(scan_result, OutputFormat.JSON)
            stored_ids.append(scan_result.metadata.scan_id)
            print(f"  {i}. Stored {scan_result.metadata.scan_id[:8]}... -> {Path(file_path).name}")
        except Exception as e:
            print(f"  {i}. ❌ Failed to store: {e}")
    
    # Retrieve and display
    print(f"\n📤 Retrieving stored results...")
    for scan_id in stored_ids:
        retrieved = result_storage.retrieve_result(scan_id)
        if retrieved:
            print(f"  ✅ Retrieved {scan_id[:8]}... - {retrieved.metadata.target}")
            print(f"     Agent: {retrieved.metadata.agent_name}, Vulns: {len(retrieved.vulnerabilities)}")
        else:
            print(f"  ❌ Failed to retrieve {scan_id[:8]}...")
    
    # Show scan history
    print(f"\n📋 Recent scan history:")
    history = result_storage.get_scan_history(limit=5)
    for record in history:
        status = "✅" if record.get('success') else "❌"
        print(f"  {status} {record['target']} ({record['scan_type']}) - {record['start_time']}")

def demo_agent_pipeline():
    """Demonstrate agent result pipeline."""
    print("\n🔄 Agent Pipeline Demonstration")
    print("=" * 50)
    
    target = "pipeline.example.com"
    scan_type = "multi-agent"
    
    # Start a scan session
    session_id = result_pipeline.start_scan_session(target, scan_type)
    print(f"🚀 Started scan session: {session_id[:8]}...")
    
    # Simulate multiple agents completing scans
    agents = [
        ("reconnaissance_agent", "nmap"),
        ("vulnerability_scanner", "openvas"),
        ("web_scanner", "zap")
    ]
    
    print(f"\n🤖 Simulating agent execution...")
    
    for agent_name, tool_name in agents:
        print(f"  🔍 {agent_name} using {tool_name}...")
        
        # Create and store agent result
        scan_result = create_sample_scan_result(agent_name, tool_name, target)
        result_pipeline.store_agent_result(session_id, agent_name, scan_result)
        
        print(f"     ✅ {agent_name} completed")
        time.sleep(0.5)  # Simulate processing time
    
    # Retrieve individual agent results
    print(f"\n📊 Individual agent results:")
    all_results = result_pipeline.get_all_agent_results(session_id)
    
    for agent_name, scan_result in all_results.items():
        print(f"  {agent_name}: {len(scan_result.vulnerabilities)} vulnerabilities found")
    
    # Consolidate results
    print(f"\n🔗 Consolidating results...")
    consolidated = result_pipeline.consolidate_results(session_id)
    
    print(f"✅ Consolidated scan completed:")
    print(f"   Total vulnerabilities: {len(consolidated.vulnerabilities)}")
    print(f"   Agents involved: {len(all_results)}")
    print(f"   Scan duration: {consolidated.metadata.duration:.1f}s")
    
    # Cleanup
    result_pipeline.cleanup_session(session_id)
    print(f"🧹 Session cleaned up")

def demo_file_operations():
    """Demonstrate file I/O operations."""
    print("\n📁 File I/O Demonstration")
    print("=" * 50)
    
    scan_result = create_sample_scan_result("file_demo_agent", "nmap", "fileio.example.com")
    
    # Create output directory
    output_dir = Path("file_demo_outputs")
    output_dir.mkdir(exist_ok=True)
    
    print(f"📂 Output directory: {output_dir}")
    
    # Save in multiple formats with custom filenames
    formats_and_files = [
        (OutputFormat.JSON, "detailed_scan_report.json"),
        (OutputFormat.HTML, "executive_report.html"),
        (OutputFormat.CSV, "vulnerability_list.csv"),
        (OutputFormat.XML, "machine_readable.xml"),
        (OutputFormat.TXT, "simple_report.txt")
    ]
    
    saved_files = []
    
    for format_type, filename in formats_and_files:
        filepath = output_dir / filename
        
        try:
            formatted_output = output_formatter.format(scan_result, format_type)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(formatted_output)
            
            file_size = filepath.stat().st_size
            saved_files.append((filepath, file_size))
            
            print(f"💾 {filename}: {file_size:,} bytes")
            
        except Exception as e:
            print(f"❌ Failed to save {filename}: {e}")
    
    # File statistics
    total_size = sum(size for _, size in saved_files)
    print(f"\n📊 Total files saved: {len(saved_files)}")
    print(f"📊 Total disk usage: {total_size:,} bytes ({total_size/1024:.1f} KB)")
    
    # Demonstrate file reading
    print(f"\n📖 Reading back JSON file...")
    json_file = output_dir / "detailed_scan_report.json"
    if json_file.exists():
        import json
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        print(f"   Metadata keys: {list(data['metadata'].keys())}")
        print(f"   Vulnerabilities: {len(data['vulnerabilities'])}")
        print(f"   Statistics: {data['statistics']['total_vulnerabilities']} total vulns")

def demo_search_and_analysis():
    """Demonstrate search and analysis capabilities."""
    print("\n🔍 Search and Analysis Demonstration")
    print("=" * 50)
    
    # Create and store multiple scan results with different vulnerability profiles
    targets = ["web-app.example.com", "database.example.com", "api.example.com"]
    
    print("📥 Creating sample data...")
    for target in targets:
        scan_result = create_sample_scan_result("analysis_agent", "comprehensive", target)
        result_storage.store_result(scan_result, OutputFormat.JSON)
        print(f"   Stored scan for {target}")
    
    # Demonstrate scan history filtering
    print(f"\n📋 Scan history analysis:")
    all_history = result_storage.get_scan_history(limit=10)
    print(f"   Total scans in database: {len(all_history)}")
    
    # Filter by target
    web_history = result_storage.get_scan_history(target="web-app.example.com", limit=5)
    print(f"   Scans for web-app.example.com: {len(web_history)}")
    
    # Vulnerability statistics
    print(f"\n🔓 Vulnerability analysis:")
    total_vulns = 0
    severity_counts = {sev.value: 0 for sev in SeverityLevel}
    
    for record in all_history[:5]:  # Analyze recent scans
        scan_result = result_storage.retrieve_result(record['scan_id'])
        if scan_result:
            total_vulns += len(scan_result.vulnerabilities)
            for vuln in scan_result.vulnerabilities:
                severity_counts[vuln.severity.value] += 1
    
    print(f"   Total vulnerabilities analyzed: {total_vulns}")
    for severity, count in severity_counts.items():
        if count > 0:
            print(f"   {severity.capitalize()}: {count}")

def main():
    """Main demonstration function."""
    print("🎭 VAPT Agents Output Management Demo")
    print("=" * 60)
    print("This demo showcases the comprehensive output management")
    print("features including structured formats, file I/O, and")
    print("intermediate result storage between agents.")
    print("=" * 60)
    
    try:
        # Run all demonstrations
        demo_output_formats()
        demo_result_storage()
        demo_agent_pipeline()
        demo_file_operations()
        demo_search_and_analysis()
        
        print("\n🎉 Demo Completed Successfully!")
        print("=" * 40)
        print("✅ Structured output formats working")
        print("✅ File I/O operations functional")
        print("✅ Result storage and retrieval active")
        print("✅ Agent pipeline coordination ready")
        print("✅ Search and analysis capabilities enabled")
        
        print(f"\n📁 Check the following directories for outputs:")
        print(f"   • demo_results/ - Format examples")
        print(f"   • file_demo_outputs/ - File I/O examples")
        print(f"   • scan_results/ - Stored scan results")
        
        print(f"\n💡 Try the CLI tool:")
        print(f"   python output_cli.py list")
        print(f"   python output_cli.py stats")
        
    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
