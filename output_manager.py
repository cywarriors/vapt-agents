"""
Output Management System for VAPT Agents.
Handles structured output formats, file I/O, and result storage.
"""

import json
import xml.etree.ElementTree as ET
import csv
import yaml
import logging
import hashlib
import sqlite3
import pickle
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

from config import config

logger = logging.getLogger(__name__)

class OutputFormat(Enum):
    """Supported output formats."""
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    YAML = "yaml"
    HTML = "html"
    TXT = "txt"
    PICKLE = "pickle"

class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class ScanMetadata:
    """Metadata for scan operations."""
    scan_id: str
    target: str
    target_type: str
    scan_type: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
    agent_name: str = ""
    tool_name: str = ""
    success: bool = False
    error_message: Optional[str] = None
    
    def __post_init__(self):
        if isinstance(self.start_time, str):
            self.start_time = datetime.fromisoformat(self.start_time)
        if isinstance(self.end_time, str) and self.end_time:
            self.end_time = datetime.fromisoformat(self.end_time)

@dataclass
class Vulnerability:
    """Structured vulnerability information."""
    id: str
    name: str
    severity: SeverityLevel
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    description: str = ""
    affected_service: str = ""
    port: Optional[int] = None
    protocol: str = ""
    evidence: str = ""
    recommendation: str = ""
    references: List[str] = None
    owasp_category: Optional[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
        if isinstance(self.severity, str):
            self.severity = SeverityLevel(self.severity.lower())

@dataclass
class ScanResult:
    """Comprehensive scan result structure."""
    metadata: ScanMetadata
    vulnerabilities: List[Vulnerability]
    raw_output: str = ""
    structured_data: Dict[str, Any] = None
    statistics: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.structured_data is None:
            self.structured_data = {}
        if self.statistics is None:
            self.statistics = self._generate_statistics()
    
    def _generate_statistics(self) -> Dict[str, Any]:
        """Generate vulnerability statistics."""
        severity_counts = {severity.value: 0 for severity in SeverityLevel}
        
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity.value] += 1
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': severity_counts,
            'highest_severity': self._get_highest_severity(),
            'unique_services': len(set(v.affected_service for v in self.vulnerabilities if v.affected_service)),
            'ports_affected': len(set(v.port for v in self.vulnerabilities if v.port))
        }
    
    def _get_highest_severity(self) -> str:
        """Get the highest severity level found."""
        severity_order = [SeverityLevel.CRITICAL, SeverityLevel.HIGH, 
                         SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]
        
        for severity in severity_order:
            if any(v.severity == severity for v in self.vulnerabilities):
                return severity.value
        
        return SeverityLevel.INFO.value

class ResultStorage:
    """Manages intermediate result storage between agents."""
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize result storage.
        
        Args:
            storage_path (str, optional): Path to storage directory
        """
        self.storage_path = Path(storage_path or config.get('reporting.results_directory', './scan_results'))
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize SQLite database for metadata
        self.db_path = self.storage_path / 'scan_metadata.db'
        self._init_database()
        
        # In-memory cache for active scans
        self._active_scans: Dict[str, ScanResult] = {}
    
    def _init_database(self):
        """Initialize SQLite database for scan metadata."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS scan_metadata (
                        scan_id TEXT PRIMARY KEY,
                        target TEXT NOT NULL,
                        target_type TEXT,
                        scan_type TEXT,
                        agent_name TEXT,
                        tool_name TEXT,
                        start_time TEXT,
                        end_time TEXT,
                        duration REAL,
                        success BOOLEAN,
                        error_message TEXT,
                        file_path TEXT,
                        format TEXT,
                        checksum TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        id TEXT PRIMARY KEY,
                        scan_id TEXT,
                        name TEXT,
                        severity TEXT,
                        cvss_score REAL,
                        cve_id TEXT,
                        description TEXT,
                        affected_service TEXT,
                        port INTEGER,
                        protocol TEXT,
                        evidence TEXT,
                        recommendation TEXT,
                        owasp_category TEXT,
                        FOREIGN KEY (scan_id) REFERENCES scan_metadata (scan_id)
                    )
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_scan_metadata_target ON scan_metadata(target);
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
                ''')
                
                conn.commit()
                logger.info(f"Database initialized at {self.db_path}")
                
        except sqlite3.Error as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    def store_result(self, scan_result: ScanResult, format_type: OutputFormat = OutputFormat.JSON) -> str:
        """
        Store scan result to filesystem and database.
        
        Args:
            scan_result (ScanResult): Scan result to store
            format_type (OutputFormat): Output format for file storage
            
        Returns:
            str: Path to stored file
        """
        try:
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_safe = self._sanitize_filename(scan_result.metadata.target)
            filename = f"{scan_result.metadata.agent_name}_{target_safe}_{timestamp}.{format_type.value}"
            file_path = self.storage_path / filename
            
            # Format and save data
            formatter = OutputFormatter()
            formatted_data = formatter.format(scan_result, format_type)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(formatted_data)
            
            # Calculate checksum
            checksum = self._calculate_checksum(file_path)
            
            # Store metadata in database
            self._store_metadata(scan_result, str(file_path), format_type.value, checksum)
            
            # Cache for immediate access
            self._active_scans[scan_result.metadata.scan_id] = scan_result
            
            logger.info(f"Scan result stored: {file_path}")
            return str(file_path)
            
        except Exception as e:
            logger.error(f"Failed to store scan result: {e}")
            raise
    
    def retrieve_result(self, scan_id: str) -> Optional[ScanResult]:
        """
        Retrieve scan result by ID.
        
        Args:
            scan_id (str): Scan ID
            
        Returns:
            Optional[ScanResult]: Scan result or None if not found
        """
        # Check cache first
        if scan_id in self._active_scans:
            return self._active_scans[scan_id]
        
        # Load from database and file
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'SELECT * FROM scan_metadata WHERE scan_id = ?',
                    (scan_id,)
                )
                row = cursor.fetchone()
                
                if not row:
                    return None
                
                # Load file
                file_path = row[11]  # file_path column
                if Path(file_path).exists():
                    return self._load_from_file(file_path, scan_id)
                else:
                    logger.warning(f"Scan file not found: {file_path}")
                    return None
                    
        except Exception as e:
            logger.error(f"Failed to retrieve scan result {scan_id}: {e}")
            return None
    
    def get_scan_history(self, target: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get scan history.
        
        Args:
            target (str, optional): Filter by target
            limit (int): Maximum number of results
            
        Returns:
            List[Dict[str, Any]]: Scan history records
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                if target:
                    cursor = conn.execute(
                        'SELECT * FROM scan_metadata WHERE target = ? ORDER BY created_at DESC LIMIT ?',
                        (target, limit)
                    )
                else:
                    cursor = conn.execute(
                        'SELECT * FROM scan_metadata ORDER BY created_at DESC LIMIT ?',
                        (limit,)
                    )
                
                columns = [description[0] for description in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get scan history: {e}")
            return []
    
    def _store_metadata(self, scan_result: ScanResult, file_path: str, 
                       format_type: str, checksum: str):
        """Store scan metadata in database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Store main metadata
                conn.execute('''
                    INSERT OR REPLACE INTO scan_metadata 
                    (scan_id, target, target_type, scan_type, agent_name, tool_name,
                     start_time, end_time, duration, success, error_message, 
                     file_path, format, checksum)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_result.metadata.scan_id,
                    scan_result.metadata.target,
                    scan_result.metadata.target_type,
                    scan_result.metadata.scan_type,
                    scan_result.metadata.agent_name,
                    scan_result.metadata.tool_name,
                    scan_result.metadata.start_time.isoformat() if scan_result.metadata.start_time else None,
                    scan_result.metadata.end_time.isoformat() if scan_result.metadata.end_time else None,
                    scan_result.metadata.duration,
                    scan_result.metadata.success,
                    scan_result.metadata.error_message,
                    file_path,
                    format_type,
                    checksum
                ))
                
                # Store vulnerabilities
                for vuln in scan_result.vulnerabilities:
                    conn.execute('''
                        INSERT OR REPLACE INTO vulnerabilities
                        (id, scan_id, name, severity, cvss_score, cve_id, description,
                         affected_service, port, protocol, evidence, recommendation, owasp_category)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        vuln.id,
                        scan_result.metadata.scan_id,
                        vuln.name,
                        vuln.severity.value,
                        vuln.cvss_score,
                        vuln.cve_id,
                        vuln.description,
                        vuln.affected_service,
                        vuln.port,
                        vuln.protocol,
                        vuln.evidence,
                        vuln.recommendation,
                        vuln.owasp_category
                    ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to store metadata: {e}")
            raise
    
    def _load_from_file(self, file_path: str, scan_id: str) -> Optional[ScanResult]:
        """Load scan result from file."""
        try:
            file_path_obj = Path(file_path)
            
            if file_path_obj.suffix == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                return self._deserialize_from_dict(data)
            
            elif file_path_obj.suffix == '.pickle':
                with open(file_path, 'rb') as f:
                    return pickle.load(f)
            
            else:
                logger.warning(f"Unsupported file format for loading: {file_path}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to load from file {file_path}: {e}")
            return None
    
    def _deserialize_from_dict(self, data: Dict[str, Any]) -> ScanResult:
        """Deserialize scan result from dictionary."""
        # Convert metadata
        metadata_dict = data['metadata']
        metadata = ScanMetadata(**metadata_dict)
        
        # Convert vulnerabilities
        vulnerabilities = []
        for vuln_dict in data.get('vulnerabilities', []):
            vuln = Vulnerability(**vuln_dict)
            vulnerabilities.append(vuln)
        
        return ScanResult(
            metadata=metadata,
            vulnerabilities=vulnerabilities,
            raw_output=data.get('raw_output', ''),
            structured_data=data.get('structured_data', {}),
            statistics=data.get('statistics', {})
        )
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for filesystem compatibility."""
        import re
        # Replace invalid characters with underscores
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        return sanitized[:100]  # Limit length
    
    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

class OutputFormatter:
    """Formats scan results into various output formats."""
    
    def format(self, scan_result: ScanResult, format_type: OutputFormat) -> str:
        """
        Format scan result into specified format.
        
        Args:
            scan_result (ScanResult): Scan result to format
            format_type (OutputFormat): Target format
            
        Returns:
            str: Formatted output
        """
        if format_type == OutputFormat.JSON:
            return self._format_json(scan_result)
        elif format_type == OutputFormat.XML:
            return self._format_xml(scan_result)
        elif format_type == OutputFormat.CSV:
            return self._format_csv(scan_result)
        elif format_type == OutputFormat.YAML:
            return self._format_yaml(scan_result)
        elif format_type == OutputFormat.HTML:
            return self._format_html(scan_result)
        elif format_type == OutputFormat.TXT:
            return self._format_text(scan_result)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _format_json(self, scan_result: ScanResult) -> str:
        """Format as JSON."""
        def convert_to_dict(obj):
            if hasattr(obj, '__dict__'):
                return {k: convert_to_dict(v) for k, v in obj.__dict__.items()}
            elif isinstance(obj, list):
                return [convert_to_dict(item) for item in obj]
            elif isinstance(obj, Enum):
                return obj.value
            elif isinstance(obj, datetime):
                return obj.isoformat()
            else:
                return obj
        
        data = convert_to_dict(scan_result)
        return json.dumps(data, indent=2, ensure_ascii=False)
    
    def _format_xml(self, scan_result: ScanResult) -> str:
        """Format as XML."""
        root = ET.Element("scan_result")
        
        # Metadata
        metadata_elem = ET.SubElement(root, "metadata")
        for key, value in asdict(scan_result.metadata).items():
            elem = ET.SubElement(metadata_elem, key)
            elem.text = str(value) if value is not None else ""
        
        # Vulnerabilities
        vulns_elem = ET.SubElement(root, "vulnerabilities")
        for vuln in scan_result.vulnerabilities:
            vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
            for key, value in asdict(vuln).items():
                if key == 'references' and isinstance(value, list):
                    refs_elem = ET.SubElement(vuln_elem, "references")
                    for ref in value:
                        ref_elem = ET.SubElement(refs_elem, "reference")
                        ref_elem.text = str(ref)
                else:
                    elem = ET.SubElement(vuln_elem, key)
                    if isinstance(value, Enum):
                        elem.text = value.value
                    else:
                        elem.text = str(value) if value is not None else ""
        
        # Statistics
        stats_elem = ET.SubElement(root, "statistics")
        for key, value in scan_result.statistics.items():
            if isinstance(value, dict):
                sub_elem = ET.SubElement(stats_elem, key)
                for sub_key, sub_value in value.items():
                    sub_sub_elem = ET.SubElement(sub_elem, sub_key)
                    sub_sub_elem.text = str(sub_value)
            else:
                elem = ET.SubElement(stats_elem, key)
                elem.text = str(value)
        
        return ET.tostring(root, encoding='unicode', xml_declaration=True)
    
    def _format_csv(self, scan_result: ScanResult) -> str:
        """Format vulnerabilities as CSV."""
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        headers = ['id', 'name', 'severity', 'cvss_score', 'cve_id', 'description', 
                  'affected_service', 'port', 'protocol', 'evidence', 'recommendation', 'owasp_category']
        writer.writerow(headers)
        
        # Data
        for vuln in scan_result.vulnerabilities:
            row = [
                vuln.id, vuln.name, vuln.severity.value, vuln.cvss_score, vuln.cve_id,
                vuln.description, vuln.affected_service, vuln.port, vuln.protocol,
                vuln.evidence, vuln.recommendation, vuln.owasp_category
            ]
            writer.writerow(row)
        
        return output.getvalue()
    
    def _format_yaml(self, scan_result: ScanResult) -> str:
        """Format as YAML."""
        def convert_for_yaml(obj):
            if hasattr(obj, '__dict__'):
                return {k: convert_for_yaml(v) for k, v in obj.__dict__.items()}
            elif isinstance(obj, list):
                return [convert_for_yaml(item) for item in obj]
            elif isinstance(obj, Enum):
                return obj.value
            elif isinstance(obj, datetime):
                return obj.isoformat()
            else:
                return obj
        
        data = convert_for_yaml(scan_result)
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)
    
    def _format_html(self, scan_result: ScanResult) -> str:
        """Format as HTML report."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 15px; border-radius: 5px; }}
        .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #dc3545; }}
        .high {{ border-left: 5px solid #fd7e14; }}
        .medium {{ border-left: 5px solid #ffc107; }}
        .low {{ border-left: 5px solid #20c997; }}
        .info {{ border-left: 5px solid #17a2b8; }}
        .stats {{ background-color: #e9ecef; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Vulnerability Assessment Report</h1>
        <p><strong>Target:</strong> {scan_result.metadata.target}</p>
        <p><strong>Scan Type:</strong> {scan_result.metadata.scan_type}</p>
        <p><strong>Start Time:</strong> {scan_result.metadata.start_time}</p>
        <p><strong>Agent:</strong> {scan_result.metadata.agent_name}</p>
    </div>
    
    <div class="stats">
        <h2>Summary Statistics</h2>
        <p><strong>Total Vulnerabilities:</strong> {scan_result.statistics['total_vulnerabilities']}</p>
        <p><strong>Highest Severity:</strong> {scan_result.statistics['highest_severity'].upper()}</p>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>"""
        
        for severity, count in scan_result.statistics['severity_breakdown'].items():
            html += f"<tr><td>{severity.capitalize()}</td><td>{count}</td></tr>"
        
        html += """</table>
    </div>
    
    <h2>Vulnerabilities</h2>"""
        
        for vuln in scan_result.vulnerabilities:
            html += f"""
    <div class="vulnerability {vuln.severity.value}">
        <h3>{vuln.name}</h3>
        <p><strong>Severity:</strong> {vuln.severity.value.upper()}</p>
        <p><strong>Service:</strong> {vuln.affected_service}</p>
        <p><strong>Port:</strong> {vuln.port or 'N/A'}</p>
        <p><strong>Description:</strong> {vuln.description}</p>
        <p><strong>Recommendation:</strong> {vuln.recommendation}</p>
        {f'<p><strong>CVE:</strong> {vuln.cve_id}</p>' if vuln.cve_id else ''}
        {f'<p><strong>CVSS Score:</strong> {vuln.cvss_score}</p>' if vuln.cvss_score else ''}
    </div>"""
        
        html += """
</body>
</html>"""
        return html
    
    def _format_text(self, scan_result: ScanResult) -> str:
        """Format as plain text report."""
        text = f"""VULNERABILITY ASSESSMENT REPORT
{'=' * 50}

Target: {scan_result.metadata.target}
Scan Type: {scan_result.metadata.scan_type}
Start Time: {scan_result.metadata.start_time}
Agent: {scan_result.metadata.agent_name}
Tool: {scan_result.metadata.tool_name}

SUMMARY STATISTICS
{'=' * 20}
Total Vulnerabilities: {scan_result.statistics['total_vulnerabilities']}
Highest Severity: {scan_result.statistics['highest_severity'].upper()}

Severity Breakdown:"""
        
        for severity, count in scan_result.statistics['severity_breakdown'].items():
            text += f"\n  {severity.capitalize()}: {count}"
        
        text += f"\n\nVULNERABILITIES\n{'=' * 15}\n"
        
        for i, vuln in enumerate(scan_result.vulnerabilities, 1):
            text += f"""
{i}. {vuln.name}
   Severity: {vuln.severity.value.upper()}
   Service: {vuln.affected_service}
   Port: {vuln.port or 'N/A'}
   Description: {vuln.description}
   Recommendation: {vuln.recommendation}"""
            
            if vuln.cve_id:
                text += f"\n   CVE: {vuln.cve_id}"
            if vuln.cvss_score:
                text += f"\n   CVSS Score: {vuln.cvss_score}"
            
            text += "\n" + "-" * 50
        
        return text

class AgentResultPipeline:
    """Manages result flow between agents."""
    
    def __init__(self, storage: ResultStorage):
        """
        Initialize agent result pipeline.
        
        Args:
            storage (ResultStorage): Result storage backend
        """
        self.storage = storage
        self._pipeline_cache: Dict[str, Dict[str, Any]] = {}
    
    def start_scan_session(self, target: str, scan_type: str) -> str:
        """
        Start a new scan session.
        
        Args:
            target (str): Scan target
            scan_type (str): Type of scan
            
        Returns:
            str: Session ID
        """
        session_id = str(uuid.uuid4())
        self._pipeline_cache[session_id] = {
            'target': target,
            'scan_type': scan_type,
            'start_time': datetime.now(timezone.utc),
            'agents_completed': [],
            'intermediate_results': {},
            'final_result': None
        }
        
        logger.info(f"Started scan session {session_id} for target {target}")
        return session_id
    
    def store_agent_result(self, session_id: str, agent_name: str, 
                          scan_result: ScanResult) -> None:
        """
        Store intermediate result from an agent.
        
        Args:
            session_id (str): Scan session ID
            agent_name (str): Name of the agent
            scan_result (ScanResult): Agent's scan result
        """
        if session_id not in self._pipeline_cache:
            raise ValueError(f"Invalid session ID: {session_id}")
        
        # Store in pipeline cache
        self._pipeline_cache[session_id]['intermediate_results'][agent_name] = scan_result
        self._pipeline_cache[session_id]['agents_completed'].append(agent_name)
        
        # Persist to storage
        self.storage.store_result(scan_result, OutputFormat.JSON)
        
        logger.info(f"Stored result from agent {agent_name} for session {session_id}")
    
    def get_agent_result(self, session_id: str, agent_name: str) -> Optional[ScanResult]:
        """
        Get result from a specific agent.
        
        Args:
            session_id (str): Scan session ID
            agent_name (str): Name of the agent
            
        Returns:
            Optional[ScanResult]: Agent result or None
        """
        if session_id not in self._pipeline_cache:
            return None
        
        return self._pipeline_cache[session_id]['intermediate_results'].get(agent_name)
    
    def get_all_agent_results(self, session_id: str) -> Dict[str, ScanResult]:
        """
        Get all agent results for a session.
        
        Args:
            session_id (str): Scan session ID
            
        Returns:
            Dict[str, ScanResult]: All agent results
        """
        if session_id not in self._pipeline_cache:
            return {}
        
        return self._pipeline_cache[session_id]['intermediate_results'].copy()
    
    def consolidate_results(self, session_id: str) -> ScanResult:
        """
        Consolidate all agent results into final result.
        
        Args:
            session_id (str): Scan session ID
            
        Returns:
            ScanResult: Consolidated scan result
        """
        if session_id not in self._pipeline_cache:
            raise ValueError(f"Invalid session ID: {session_id}")
        
        session_data = self._pipeline_cache[session_id]
        agent_results = session_data['intermediate_results']
        
        if not agent_results:
            raise ValueError("No agent results to consolidate")
        
        # Create consolidated metadata
        consolidated_metadata = ScanMetadata(
            scan_id=str(uuid.uuid4()),
            target=session_data['target'],
            target_type='consolidated',
            scan_type=session_data['scan_type'],
            start_time=session_data['start_time'],
            end_time=datetime.now(timezone.utc),
            agent_name='consolidated',
            tool_name='multi-agent',
            success=True
        )
        consolidated_metadata.duration = (
            consolidated_metadata.end_time - consolidated_metadata.start_time
        ).total_seconds()
        
        # Consolidate vulnerabilities (remove duplicates)
        all_vulnerabilities = []
        seen_vulns = set()
        
        for agent_name, result in agent_results.items():
            for vuln in result.vulnerabilities:
                # Create a unique key for deduplication
                vuln_key = (vuln.name, vuln.affected_service, vuln.port, vuln.severity.value)
                if vuln_key not in seen_vulns:
                    seen_vulns.add(vuln_key)
                    all_vulnerabilities.append(vuln)
        
        # Consolidate raw output
        consolidated_raw_output = "\n\n".join([
            f"=== {agent_name.upper()} RESULTS ===\n{result.raw_output}"
            for agent_name, result in agent_results.items()
            if result.raw_output
        ])
        
        # Consolidate structured data
        consolidated_structured_data = {
            'agent_results': {
                agent_name: result.structured_data
                for agent_name, result in agent_results.items()
            },
            'consolidation_info': {
                'total_agents': len(agent_results),
                'agents_completed': session_data['agents_completed'],
                'consolidation_time': datetime.now(timezone.utc).isoformat()
            }
        }
        
        # Create final consolidated result
        consolidated_result = ScanResult(
            metadata=consolidated_metadata,
            vulnerabilities=all_vulnerabilities,
            raw_output=consolidated_raw_output,
            structured_data=consolidated_structured_data
        )
        
        # Store final result
        session_data['final_result'] = consolidated_result
        self.storage.store_result(consolidated_result, OutputFormat.JSON)
        
        logger.info(f"Consolidated results for session {session_id}: {len(all_vulnerabilities)} vulnerabilities")
        return consolidated_result
    
    def cleanup_session(self, session_id: str) -> None:
        """
        Clean up session data.
        
        Args:
            session_id (str): Session ID to clean up
        """
        if session_id in self._pipeline_cache:
            del self._pipeline_cache[session_id]
            logger.info(f"Cleaned up session {session_id}")

# Global instances
result_storage = ResultStorage()
result_pipeline = AgentResultPipeline(result_storage)
output_formatter = OutputFormatter()
