#!/usr/bin/env python3
"""
Command Line Interface for VAPT Agents Output Management.
Provides tools for managing, converting, and analyzing scan results.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from output_manager import (
    result_storage, output_formatter, OutputFormat, 
    ScanResult, ScanMetadata, Vulnerability
)
from config import config

def list_scan_results(target: Optional[str] = None, limit: int = 20) -> None:
    """List recent scan results."""
    print(f"📋 Recent Scan Results (limit: {limit})")
    print("=" * 60)
    
    history = result_storage.get_scan_history(target=target, limit=limit)
    
    if not history:
        print("No scan results found.")
        return
    
    for i, record in enumerate(history, 1):
        status = "✅" if record.get('success') else "❌"
        print(f"{i:2d}. {status} {record['target']} ({record['scan_type']})")
        print(f"    Agent: {record['agent_name']} | Tool: {record['tool_name']}")
        print(f"    Time: {record['start_time']} | ID: {record['scan_id'][:8]}...")
        if record.get('error_message'):
            print(f"    Error: {record['error_message']}")
        print()

def show_scan_details(scan_id: str) -> None:
    """Show detailed information about a specific scan."""
    print(f"🔍 Scan Details: {scan_id}")
    print("=" * 60)
    
    scan_result = result_storage.retrieve_result(scan_id)
    
    if not scan_result:
        print(f"❌ Scan not found: {scan_id}")
        return
    
    # Metadata
    print("📊 Metadata:")
    print(f"  Target: {scan_result.metadata.target}")
    print(f"  Type: {scan_result.metadata.scan_type}")
    print(f"  Agent: {scan_result.metadata.agent_name}")
    print(f"  Tool: {scan_result.metadata.tool_name}")
    print(f"  Start: {scan_result.metadata.start_time}")
    print(f"  End: {scan_result.metadata.end_time}")
    print(f"  Success: {'✅' if scan_result.metadata.success else '❌'}")
    
    if scan_result.metadata.error_message:
        print(f"  Error: {scan_result.metadata.error_message}")
    
    # Statistics
    print(f"\n📈 Statistics:")
    for key, value in scan_result.statistics.items():
        if isinstance(value, dict):
            print(f"  {key}:")
            for sub_key, sub_value in value.items():
                print(f"    {sub_key}: {sub_value}")
        else:
            print(f"  {key}: {value}")
    
    # Vulnerabilities summary
    print(f"\n🔓 Vulnerabilities ({len(scan_result.vulnerabilities)}):")
    if scan_result.vulnerabilities:
        for vuln in scan_result.vulnerabilities[:5]:  # Show first 5
            print(f"  • {vuln.name} [{vuln.severity.value.upper()}]")
            if vuln.cve_id:
                print(f"    CVE: {vuln.cve_id}")
        
        if len(scan_result.vulnerabilities) > 5:
            print(f"  ... and {len(scan_result.vulnerabilities) - 5} more")
    else:
        print("  No vulnerabilities found")

def convert_result_format(scan_id: str, output_format: str, output_file: Optional[str] = None) -> None:
    """Convert scan result to different format."""
    print(f"🔄 Converting scan {scan_id} to {output_format.upper()}")
    
    try:
        format_enum = OutputFormat(output_format.lower())
    except ValueError:
        print(f"❌ Unsupported format: {output_format}")
        print(f"Supported formats: {', '.join([f.value for f in OutputFormat])}")
        return
    
    scan_result = result_storage.retrieve_result(scan_id)
    if not scan_result:
        print(f"❌ Scan not found: {scan_id}")
        return
    
    try:
        formatted_output = output_formatter.format(scan_result, format_enum)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(formatted_output)
            print(f"✅ Converted result saved to: {output_file}")
        else:
            print("=" * 60)
            print(formatted_output)
            print("=" * 60)
            
    except Exception as e:
        print(f"❌ Conversion failed: {e}")

def export_results(target: Optional[str] = None, output_dir: str = "./exports", 
                  formats: List[str] = None) -> None:
    """Export scan results in multiple formats."""
    if formats is None:
        formats = ['json', 'html', 'csv']
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    print(f"📦 Exporting scan results to: {output_path}")
    print(f"📋 Target filter: {target or 'All targets'}")
    print(f"📄 Formats: {', '.join(formats)}")
    print()
    
    history = result_storage.get_scan_history(target=target, limit=100)
    
    if not history:
        print("❌ No scan results found to export")
        return
    
    exported_count = 0
    
    for record in history:
        scan_id = record['scan_id']
        scan_result = result_storage.retrieve_result(scan_id)
        
        if not scan_result:
            continue
        
        target_safe = record['target'].replace('.', '_').replace(':', '_')
        base_filename = f"{target_safe}_{scan_id[:8]}"
        
        for format_str in formats:
            try:
                format_enum = OutputFormat(format_str.lower())
                formatted_output = output_formatter.format(scan_result, format_enum)
                
                output_file = output_path / f"{base_filename}.{format_str}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(formatted_output)
                
                print(f"✅ Exported: {output_file}")
                exported_count += 1
                
            except Exception as e:
                print(f"❌ Failed to export {scan_id} as {format_str}: {e}")
    
    print(f"\n📈 Export Summary: {exported_count} files exported")

def search_vulnerabilities(cve_id: Optional[str] = None, severity: Optional[str] = None, 
                         keyword: Optional[str] = None) -> None:
    """Search for vulnerabilities across all scan results."""
    print("🔍 Searching Vulnerabilities")
    print("=" * 40)
    
    if cve_id:
        print(f"CVE ID: {cve_id}")
    if severity:
        print(f"Severity: {severity}")
    if keyword:
        print(f"Keyword: {keyword}")
    print()
    
    history = result_storage.get_scan_history(limit=100)
    matching_vulns = []
    
    for record in history:
        scan_result = result_storage.retrieve_result(record['scan_id'])
        if not scan_result:
            continue
        
        for vuln in scan_result.vulnerabilities:
            match = True
            
            if cve_id and vuln.cve_id != cve_id:
                match = False
            
            if severity and vuln.severity.value.lower() != severity.lower():
                match = False
            
            if keyword and keyword.lower() not in vuln.name.lower() and keyword.lower() not in vuln.description.lower():
                match = False
            
            if match:
                matching_vulns.append({
                    'vulnerability': vuln,
                    'target': record['target'],
                    'scan_id': record['scan_id'],
                    'scan_time': record['start_time']
                })
    
    if not matching_vulns:
        print("❌ No matching vulnerabilities found")
        return
    
    print(f"📊 Found {len(matching_vulns)} matching vulnerabilities:\n")
    
    for i, match in enumerate(matching_vulns, 1):
        vuln = match['vulnerability']
        print(f"{i:2d}. {vuln.name} [{vuln.severity.value.upper()}]")
        print(f"    Target: {match['target']}")
        print(f"    Scan: {match['scan_id'][:8]}... ({match['scan_time']})")
        if vuln.cve_id:
            print(f"    CVE: {vuln.cve_id}")
        if vuln.cvss_score:
            print(f"    CVSS: {vuln.cvss_score}")
        print(f"    Service: {vuln.affected_service} (Port: {vuln.port})")
        print()

def cleanup_old_results(days: int = 30, dry_run: bool = True) -> None:
    """Clean up old scan results."""
    print(f"🧹 Cleanup Old Results (older than {days} days)")
    print(f"🔍 Mode: {'Dry run' if dry_run else 'Execute'}")
    print("=" * 50)
    
    from datetime import datetime, timedelta
    
    cutoff_date = datetime.now() - timedelta(days=days)
    history = result_storage.get_scan_history(limit=1000)
    
    old_results = []
    for record in history:
        try:
            scan_time = datetime.fromisoformat(record['start_time'].replace('Z', '+00:00'))
            if scan_time < cutoff_date:
                old_results.append(record)
        except Exception:
            continue
    
    if not old_results:
        print("✅ No old results found to clean up")
        return
    
    print(f"📊 Found {len(old_results)} old results:")
    
    total_size = 0
    for record in old_results:
        file_path = record.get('file_path')
        if file_path and Path(file_path).exists():
            size = Path(file_path).stat().st_size
            total_size += size
            
        print(f"  • {record['target']} - {record['start_time']} (ID: {record['scan_id'][:8]}...)")
    
    print(f"\n💾 Total disk space to free: {total_size / (1024*1024):.2f} MB")
    
    if not dry_run:
        print("\n🗑️  Deleting old results...")
        # Implementation would go here - for safety, only showing what would be deleted
        print("❌ Actual deletion not implemented for safety - use database tools")
    else:
        print("\n💡 Run with --execute to actually delete these files")

def show_statistics() -> None:
    """Show overall statistics for all scans."""
    print("📊 VAPT Agents Statistics")
    print("=" * 40)
    
    history = result_storage.get_scan_history(limit=1000)
    
    if not history:
        print("❌ No scan data available")
        return
    
    # Basic stats
    total_scans = len(history)
    successful_scans = sum(1 for r in history if r.get('success'))
    failed_scans = total_scans - successful_scans
    
    print(f"Total Scans: {total_scans}")
    print(f"Successful: {successful_scans} ({successful_scans/total_scans*100:.1f}%)")
    print(f"Failed: {failed_scans} ({failed_scans/total_scans*100:.1f}%)")
    print()
    
    # Scan types
    scan_types = {}
    agents = {}
    targets = set()
    
    total_vulns = 0
    severity_counts = {sev: 0 for sev in ['critical', 'high', 'medium', 'low', 'info']}
    
    for record in history:
        scan_type = record.get('scan_type', 'unknown')
        agent = record.get('agent_name', 'unknown')
        target = record['target']
        
        scan_types[scan_type] = scan_types.get(scan_type, 0) + 1
        agents[agent] = agents.get(agent, 0) + 1
        targets.add(target)
        
        # Get vulnerability stats
        scan_result = result_storage.retrieve_result(record['scan_id'])
        if scan_result:
            total_vulns += len(scan_result.vulnerabilities)
            for vuln in scan_result.vulnerabilities:
                severity_counts[vuln.severity.value] += 1
    
    print("📋 Scan Types:")
    for scan_type, count in sorted(scan_types.items(), key=lambda x: x[1], reverse=True):
        print(f"  {scan_type}: {count}")
    
    print(f"\n🤖 Agents:")
    for agent, count in sorted(agents.items(), key=lambda x: x[1], reverse=True):
        print(f"  {agent}: {count}")
    
    print(f"\n🎯 Unique Targets: {len(targets)}")
    
    print(f"\n🔓 Vulnerabilities:")
    print(f"  Total: {total_vulns}")
    for severity, count in severity_counts.items():
        if count > 0:
            print(f"  {severity.capitalize()}: {count}")

def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description="VAPT Agents Output Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python output_cli.py list                           # List recent scans
  python output_cli.py show abc123                    # Show scan details
  python output_cli.py convert abc123 html            # Convert to HTML
  python output_cli.py export --target example.com    # Export target results
  python output_cli.py search --cve CVE-2023-1234     # Search for CVE
  python output_cli.py stats                          # Show statistics
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List scan results')
    list_parser.add_argument('--target', help='Filter by target')
    list_parser.add_argument('--limit', type=int, default=20, help='Limit number of results')
    
    # Show command
    show_parser = subparsers.add_parser('show', help='Show scan details')
    show_parser.add_argument('scan_id', help='Scan ID to show')
    
    # Convert command
    convert_parser = subparsers.add_parser('convert', help='Convert scan result format')
    convert_parser.add_argument('scan_id', help='Scan ID to convert')
    convert_parser.add_argument('format', choices=['json', 'xml', 'html', 'csv', 'txt', 'yaml'], 
                               help='Output format')
    convert_parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export scan results')
    export_parser.add_argument('--target', help='Filter by target')
    export_parser.add_argument('--output-dir', default='./exports', help='Output directory')
    export_parser.add_argument('--formats', nargs='+', default=['json', 'html', 'csv'],
                              choices=['json', 'xml', 'html', 'csv', 'txt', 'yaml'],
                              help='Output formats')
    
    # Search command
    search_parser = subparsers.add_parser('search', help='Search vulnerabilities')
    search_parser.add_argument('--cve', help='CVE ID to search for')
    search_parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low', 'info'],
                              help='Severity level')
    search_parser.add_argument('--keyword', help='Keyword to search in name/description')
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean up old results')
    cleanup_parser.add_argument('--days', type=int, default=30, help='Delete results older than N days')
    cleanup_parser.add_argument('--execute', action='store_true', help='Actually delete (default: dry run)')
    
    # Stats command
    subparsers.add_parser('stats', help='Show statistics')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        if args.command == 'list':
            list_scan_results(args.target, args.limit)
        elif args.command == 'show':
            show_scan_details(args.scan_id)
        elif args.command == 'convert':
            convert_result_format(args.scan_id, args.format, args.output)
        elif args.command == 'export':
            export_results(args.target, args.output_dir, args.formats)
        elif args.command == 'search':
            search_vulnerabilities(args.cve, args.severity, args.keyword)
        elif args.command == 'cleanup':
            cleanup_old_results(args.days, not args.execute)
        elif args.command == 'stats':
            show_statistics()
        
        return 0
        
    except KeyboardInterrupt:
        print("\n👋 Operation cancelled by user")
        return 130
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
