from crewai.tools import BaseTool
import subprocess
import logging
import signal
import time
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from validation import (
    TargetValidator, ConfigValidator, ValidationError, 
    NetworkError, ScanTimeoutError, log_scan_attempt
)
from output_manager import (
    ScanResult as OutputScanResult, ScanMetadata, Vulnerability, 
    SeverityLevel, OutputFormat, result_storage, output_formatter
)

# Configure logging
logger = logging.getLogger(__name__)

class ToolScanResult:
    """Standardized scan result container for individual tools."""
    
    def __init__(self, success: bool, data: str, error: Optional[str] = None, 
                 metadata: Optional[Dict[str, Any]] = None, 
                 vulnerabilities: Optional[List[Vulnerability]] = None):
        self.success = success
        self.data = data
        self.error = error
        self.metadata = metadata or {}
        self.timestamp = time.time()
        self.vulnerabilities = vulnerabilities or []
        self.scan_id = str(uuid.uuid4())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'scan_id': self.scan_id,
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'metadata': self.metadata,
            'timestamp': self.timestamp,
            'vulnerabilities': [
                {
                    'id': v.id,
                    'name': v.name,
                    'severity': v.severity.value,
                    'description': v.description,
                    'affected_service': v.affected_service,
                    'port': v.port,
                    'evidence': v.evidence,
                    'recommendation': v.recommendation
                } for v in self.vulnerabilities
            ]
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)
    
    def to_structured_result(self, agent_name: str, tool_name: str, 
                           target: str, target_type: str) -> OutputScanResult:
        """Convert to structured OutputScanResult for storage."""
        metadata = ScanMetadata(
            scan_id=self.scan_id,
            target=target,
            target_type=target_type,
            scan_type=tool_name,
            start_time=datetime.fromtimestamp(self.timestamp, timezone.utc),
            end_time=datetime.now(timezone.utc),
            agent_name=agent_name,
            tool_name=tool_name,
            success=self.success,
            error_message=self.error
        )
        
        return OutputScanResult(
            metadata=metadata,
            vulnerabilities=self.vulnerabilities,
            raw_output=self.data,
            structured_data=self.metadata
        )
    
    def save_to_file(self, filepath: str, format_type: OutputFormat = OutputFormat.JSON):
        """Save scan result to file in specified format."""
        try:
            formatted_data = output_formatter.format(
                self.to_structured_result("unknown", "unknown", "unknown", "unknown"),
                format_type
            )
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(formatted_data)
                
            logger.info(f"Scan result saved to {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to save scan result: {e}")
            raise

class TimeoutHandler:
    """Handles command timeouts using signals."""
    
    def __init__(self, timeout: float):
        self.timeout = timeout
        self.process = None
    
    def timeout_handler(self, signum, frame):
        if self.process:
            self.process.terminate()
            time.sleep(2)
            if self.process.poll() is None:
                self.process.kill()
        raise ScanTimeoutError(f"Operation timed out after {self.timeout} seconds")
    
    def __enter__(self):
        signal.signal(signal.SIGALRM, self.timeout_handler)
        signal.alarm(int(self.timeout))
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.alarm(0)
        return False

class NmapReconTool(BaseTool):
    name: str = "nmap"
    description: str = "Performs network reconnaissance using nmap to discover hosts, open ports, and service banners."
    timeout: float = 300
    timing_template: str = "T3"
    max_retries: int = 3
    retry_delay: int = 5
    
    def __init__(self, timeout: float = 300, timing_template: str = "T3"):
        super().__init__()
        self.timeout = ConfigValidator.validate_timeout(timeout)
        self.timing_template = timing_template
        self.max_retries = 3
        self.retry_delay = 5

    def _run(self):
        raise NotImplementedError("NmapReconTool._run is not yet implemented")
        
    def run(self, target: str, **kwargs) -> str:
        """
        Runs nmap scan on the specified target with comprehensive error handling.
        
        Args:
            target (str): The IP address or hostname to scan.
            **kwargs: Additional parameters (timeout, ports, scan_type)
            
        Returns:
            str: JSON formatted scan result
        """
        # Extract optional parameters
        custom_timeout = kwargs.get('timeout', self.timeout)
        ports = kwargs.get('ports', None)
        scan_type = kwargs.get('scan_type', 'comprehensive')
        
        try:
            # Validate and log scan attempt
            validated_target, target_type = TargetValidator.validate_target(target)
            log_scan_attempt(validated_target, "nmap")
            
            # Build nmap command
            scan_result = self._execute_scan_with_retry(
                validated_target, custom_timeout, ports, scan_type
            )
            
            return scan_result.to_json()
            
        except ValidationError as e:
            error_result = ToolScanResult(False, "", f"Validation error: {str(e)}")
            logger.error(f"Nmap validation error: {e}")
            return error_result.to_json()
            
        except NetworkError as e:
            error_result = ToolScanResult(False, "", f"Network error: {str(e)}")
            logger.error(f"Nmap network error: {e}")
            return error_result.to_json()
            
        except ScanTimeoutError as e:
            error_result = ToolScanResult(False, "", f"Scan timeout: {str(e)}")
            logger.error(f"Nmap timeout error: {e}")
            return error_result.to_json()
            
        except Exception as e:
            error_result = ToolScanResult(False, "", f"Unexpected error: {str(e)}")
            logger.error(f"Nmap unexpected error: {e}")
            return error_result.to_json()
    
    def _execute_scan_with_retry(self, target: str, timeout: float, 
                                ports: Optional[str], scan_type: str) -> ToolScanResult:
        """
        Execute nmap scan with retry logic.
        
        Args:
            target (str): Validated target
            timeout (float): Scan timeout
            ports (str, optional): Port specification
            scan_type (str): Type of scan to perform
            
        Returns:
            ScanResult: Scan execution result
        """
        last_exception = None
        
        for attempt in range(self.max_retries):
            try:
                logger.info(f"Nmap scan attempt {attempt + 1}/{self.max_retries} for {target}")
                
                cmd = self._build_nmap_command(target, ports, scan_type)
                
                # Execute with timeout handling
                start_time = time.time()
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=timeout,
                    check=False
                )
                execution_time = time.time() - start_time
                
                metadata = {
                    'command': ' '.join(cmd),
                    'execution_time': execution_time,
                    'attempt': attempt + 1,
                    'return_code': result.returncode
                }
                
                if result.returncode == 0:
                    logger.info(f"Nmap scan successful for {target} in {execution_time:.2f}s")
                    
                    # Parse vulnerabilities from nmap output
                    vulnerabilities = self._parse_nmap_vulnerabilities(result.stdout, target)
                    
                    return ToolScanResult(
                        True, result.stdout, 
                        metadata=metadata, 
                        vulnerabilities=vulnerabilities
                    )
                else:
                    logger.warning(f"Nmap returned non-zero exit code {result.returncode}")
                    error_msg = f"Nmap error (exit code {result.returncode}): {result.stderr}"
                    
                    # Check if this is a retryable error
                    if self._is_retryable_error(result.stderr):
                        last_exception = NetworkError(error_msg)
                        if attempt < self.max_retries - 1:
                            logger.info(f"Retrying in {self.retry_delay} seconds...")
                            time.sleep(self.retry_delay)
                            continue
                    
                    return ToolScanResult(False, result.stdout, error_msg, metadata)
                    
            except subprocess.TimeoutExpired:
                timeout_msg = f"Nmap scan timed out after {timeout} seconds"
                logger.error(timeout_msg)
                last_exception = ScanTimeoutError(timeout_msg)
                
                if attempt < self.max_retries - 1:
                    logger.info(f"Retrying with extended timeout...")
                    timeout *= 1.5  # Increase timeout for retry
                    time.sleep(self.retry_delay)
                    continue
                    
            except subprocess.SubprocessError as e:
                subprocess_msg = f"Subprocess error: {str(e)}"
                logger.error(subprocess_msg)
                last_exception = NetworkError(subprocess_msg)
                
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                    continue
                    
            except Exception as e:
                unexpected_msg = f"Unexpected error during nmap execution: {str(e)}"
                logger.error(unexpected_msg)
                last_exception = Exception(unexpected_msg)
                break
        
        # All retries failed
        if last_exception:
            raise last_exception
        else:
            raise Exception("All nmap scan attempts failed")
    
    def _build_nmap_command(self, target: str, ports: Optional[str], scan_type: str) -> list:
        """
        Build nmap command based on scan parameters.
        
        Args:
            target (str): Target to scan
            ports (str, optional): Port specification
            scan_type (str): Type of scan
            
        Returns:
            list: Nmap command as list
        """
        cmd = ["nmap"]
        
        # Add timing template
        cmd.extend(["-T", self.timing_template[-1]])  # Extract number from T3, T4, etc.
        
        # Add scan type specific options
        if scan_type == "comprehensive":
            cmd.extend(["-A", "-sV", "-sC"])  # OS detection, version detection, default scripts
        elif scan_type == "quick":
            cmd.extend(["-sV", "-F"])  # Version detection, fast scan
        elif scan_type == "stealth":
            cmd.extend(["-sS", "-sV"])  # SYN stealth scan
        elif scan_type == "discovery":
            cmd.extend(["-sn"])  # Ping scan only
        
        # Add port specification
        if ports:
            try:
                # Validate port range
                if '-' in ports or ',' in ports:
                    # Complex port specification - basic validation
                    cmd.extend(["-p", ports])
                else:
                    # Single port
                    ConfigValidator.validate_port(ports)
                    cmd.extend(["-p", ports])
            except ValidationError as e:
                logger.warning(f"Invalid port specification '{ports}': {e}")
                # Continue without port specification
        
        # Add output options
        cmd.extend(["-oN", "-"])  # Normal output to stdout
        
        # Add target
        cmd.append(target)
        
        return cmd
    
    def _is_retryable_error(self, stderr: str) -> bool:
        """
        Determine if an error is retryable.
        
        Args:
            stderr (str): Error message from nmap
            
        Returns:
            bool: True if error is retryable
        """
        retryable_patterns = [
            "network is unreachable",
            "no route to host",
            "connection timed out",
            "temporary failure in name resolution",
            "resource temporarily unavailable"
        ]
        
        stderr_lower = stderr.lower()
        return any(pattern in stderr_lower for pattern in retryable_patterns)
    
    def _parse_nmap_vulnerabilities(self, output: str, target: str) -> List[Vulnerability]:
        """
        Parse vulnerabilities from nmap output.
        
        Args:
            output (str): Nmap scan output
            target (str): Scan target
            
        Returns:
            List[Vulnerability]: Parsed vulnerabilities
        """
        vulnerabilities = []
        lines = output.split('\n')
        
        current_port = None
        current_service = None
        
        for line in lines:
            line = line.strip()
            
            # Parse port information
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0]
                    port_number = port_info.split('/')[0]
                    try:
                        current_port = int(port_number)
                        current_service = parts[2] if len(parts) > 2 else 'unknown'
                    except ValueError:
                        continue
            
            # Look for vulnerability indicators
            if any(keyword in line.lower() for keyword in ['vulnerable', 'cve-', 'exploit']):
                vuln_id = str(uuid.uuid4())
                
                # Determine severity based on keywords
                severity = SeverityLevel.INFO
                if any(word in line.lower() for word in ['critical', 'severe']):
                    severity = SeverityLevel.CRITICAL
                elif any(word in line.lower() for word in ['high', 'dangerous']):
                    severity = SeverityLevel.HIGH
                elif any(word in line.lower() for word in ['medium', 'moderate']):
                    severity = SeverityLevel.MEDIUM
                elif any(word in line.lower() for word in ['low', 'minor']):
                    severity = SeverityLevel.LOW
                
                # Extract CVE if present
                cve_id = None
                import re
                cve_match = re.search(r'CVE-\d{4}-\d{4,}', line)
                if cve_match:
                    cve_id = cve_match.group()
                
                vulnerability = Vulnerability(
                    id=vuln_id,
                    name=line.strip(),
                    severity=severity,
                    cve_id=cve_id,
                    description=f"Potential vulnerability detected by nmap: {line}",
                    affected_service=current_service or 'unknown',
                    port=current_port,
                    protocol='tcp',  # Default to TCP
                    evidence=line,
                    recommendation="Investigate and patch if confirmed vulnerable"
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities

class NessusScanTool(BaseTool):
    name: str = "nessus"
    description: str = "Performs vulnerability scanning using Nessus. Requires Nessus to be installed and accessible via CLI or API."
    timeout: float = 1800
    api_url: Optional[str] = None
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    max_retries: int = 2
    retry_delay: int = 10
    
    def __init__(self, timeout: float = 1800, api_url: Optional[str] = None, 
                 access_key: Optional[str] = None, secret_key: Optional[str] = None):
        super().__init__()
        self.timeout = ConfigValidator.validate_timeout(timeout)
        self.api_url = api_url
        self.access_key = access_key
        self.secret_key = secret_key
        self.max_retries = 2
        self.retry_delay = 10

    def _run(self):
        raise NotImplementedError("NessusScanTool._run is not yet implemented")

    def run(self, target: str, **kwargs) -> str:
        """
        Runs a Nessus scan on the specified target with enhanced error handling.
        
        Args:
            target (str): The IP address or hostname to scan.
            **kwargs: Additional parameters (scan_template, timeout)
            
        Returns:
            str: JSON formatted scan result
        """
        custom_timeout = kwargs.get('timeout', self.timeout)
        scan_template = kwargs.get('scan_template', 'basic')
        
        try:
            # Validate target
            validated_target, target_type = TargetValidator.validate_target(target)
            log_scan_attempt(validated_target, "nessus")
            
            # Check if Nessus is properly configured
            if not self._is_configured():
                error_result = ToolScanResult(
                    False, "", 
                    "Nessus not configured. Please provide API credentials or CLI access.",
                    metadata={'configuration_required': True}
                )
                return error_result.to_json()
            
            # Execute scan with retry logic
            scan_result = self._execute_nessus_scan(
                validated_target, custom_timeout, scan_template
            )
            
            return scan_result.to_json()
            
        except ValidationError as e:
            error_result = ToolScanResult(False, "", f"Validation error: {str(e)}")
            logger.error(f"Nessus validation error: {e}")
            return error_result.to_json()
            
        except NetworkError as e:
            error_result = ToolScanResult(False, "", f"Network error: {str(e)}")
            logger.error(f"Nessus network error: {e}")
            return error_result.to_json()
            
        except ScanTimeoutError as e:
            error_result = ToolScanResult(False, "", f"Scan timeout: {str(e)}")
            logger.error(f"Nessus timeout error: {e}")
            return error_result.to_json()
            
        except Exception as e:
            error_result = ScanResult(False, "", f"Unexpected error: {str(e)}")
            logger.error(f"Nessus unexpected error: {e}")
            return error_result.to_json()
    
    def _is_configured(self) -> bool:
        """
        Check if Nessus is properly configured.
        
        Returns:
            bool: True if configured, False otherwise
        """
        # Check for API configuration
        if self.api_url and self.access_key and self.secret_key:
            return True
        
        # Check for CLI availability
        try:
            result = subprocess.run(
                ["nessuscli", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def _execute_nessus_scan(self, target: str, timeout: float, 
                           scan_template: str) -> ToolScanResult:
        """
        Execute Nessus scan with proper error handling.
        
        Args:
            target (str): Validated target
            timeout (float): Scan timeout
            scan_template (str): Scan template to use
            
        Returns:
            ToolScanResult: Scan execution result
        """
        start_time = time.time()
        
        # For now, return a placeholder with proper structure
        # TODO: Implement actual Nessus API/CLI integration
        
        logger.info(f"Starting Nessus scan for {target} with template {scan_template}")
        
        # Simulate scan duration
        time.sleep(2)  # Remove this in actual implementation
        
        execution_time = time.time() - start_time
        
        metadata = {
            'scan_template': scan_template,
            'execution_time': execution_time,
            'target_type': 'placeholder',
            'implementation_status': 'placeholder'
        }
        
        placeholder_data = f"""Nessus scan completed for {target}
Scan Template: {scan_template}
Execution Time: {execution_time:.2f}s

NOTE: This is a placeholder implementation.
To enable actual Nessus scanning:
1. Install Nessus Professional or Nessus Essentials
2. Configure API access or CLI integration
3. Implement actual Nessus API calls in this method

Placeholder findings:
- Port 22/tcp open (SSH)
- Port 80/tcp open (HTTP)
- Port 443/tcp open (HTTPS)
- Potential vulnerabilities require actual Nessus integration"""
        
        return ToolScanResult(True, placeholder_data, metadata=metadata)

class OpenVASScanTool(BaseTool):
    name: str = "openvas"
    description: str = "Performs vulnerability scanning using OpenVAS. Requires OpenVAS to be installed and accessible via CLI or API."
    timeout: float = 1800
    gvm_host: Optional[str] = None
    gvm_port: int = 9390
    username: Optional[str] = None
    password: Optional[str] = None
    max_retries: int = 2
    retry_delay: int = 10
    
    def __init__(self, timeout: float = 1800, gvm_host: Optional[str] = None, 
                 gvm_port: int = 9390, username: Optional[str] = None, 
                 password: Optional[str] = None):
        super().__init__()
        self.timeout = ConfigValidator.validate_timeout(timeout)
        self.gvm_host = gvm_host or "127.0.0.1"
        self.gvm_port = ConfigValidator.validate_port(gvm_port)
        self.username = username
        self.password = password
        self.max_retries = 2
        self.retry_delay = 15

    def _run(self):
        raise NotImplementedError("OpenVASScanTool._run is not yet implemented")

    def run(self, target: str, **kwargs) -> str:
        """
        Runs an OpenVAS scan on the specified target with enhanced error handling.
        
        Args:
            target (str): The IP address or hostname to scan.
            **kwargs: Additional parameters (scan_config, timeout)
            
        Returns:
            str: JSON formatted scan result
        """
        custom_timeout = kwargs.get('timeout', self.timeout)
        scan_config = kwargs.get('scan_config', 'Full and fast')
        
        try:
            # Validate target
            validated_target, target_type = TargetValidator.validate_target(target)
            log_scan_attempt(validated_target, "openvas")
            
            # Check if OpenVAS is available
            if not self._is_available():
                error_result = ToolScanResult(
                    False, "", 
                    "OpenVAS/GVM not available. Please install and configure OpenVAS.",
                    metadata={'installation_required': True}
                )
                return error_result.to_json()
            
            # Execute scan with retry logic
            scan_result = self._execute_openvas_scan(
                validated_target, custom_timeout, scan_config
            )
            
            return scan_result.to_json()
            
        except ValidationError as e:
            error_result = ScanResult(False, "", f"Validation error: {str(e)}")
            logger.error(f"OpenVAS validation error: {e}")
            return error_result.to_json()
            
        except NetworkError as e:
            error_result = ScanResult(False, "", f"Network error: {str(e)}")
            logger.error(f"OpenVAS network error: {e}")
            return error_result.to_json()
            
        except ScanTimeoutError as e:
            error_result = ScanResult(False, "", f"Scan timeout: {str(e)}")
            logger.error(f"OpenVAS timeout error: {e}")
            return error_result.to_json()
            
        except Exception as e:
            error_result = ScanResult(False, "", f"Unexpected error: {str(e)}")
            logger.error(f"OpenVAS unexpected error: {e}")
            return error_result.to_json()
    
    def _is_available(self) -> bool:
        """
        Check if OpenVAS/GVM is available.
        
        Returns:
            bool: True if available, False otherwise
        """
        try:
            # Check for gvm-cli
            result = subprocess.run(
                ["gvm-cli", "--help"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0:
                return True
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        try:
            # Check for omp (OpenVAS Management Protocol)
            result = subprocess.run(
                ["omp", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def _execute_openvas_scan(self, target: str, timeout: float, 
                            scan_config: str) -> ToolScanResult:
        """
        Execute OpenVAS scan with proper error handling.
        
        Args:
            target (str): Validated target
            timeout (float): Scan timeout
            scan_config (str): Scan configuration to use
            
        Returns:
            ScanResult: Scan execution result
        """
        start_time = time.time()
        
        # For now, return a placeholder with proper structure
        # TODO: Implement actual OpenVAS/GVM integration
        
        logger.info(f"Starting OpenVAS scan for {target} with config {scan_config}")
        
        # Simulate scan duration
        time.sleep(2)  # Remove this in actual implementation
        
        execution_time = time.time() - start_time
        
        metadata = {
            'scan_config': scan_config,
            'execution_time': execution_time,
            'gvm_host': self.gvm_host,
            'gvm_port': self.gvm_port,
            'implementation_status': 'placeholder'
        }
        
        placeholder_data = f"""OpenVAS scan completed for {target}
Scan Configuration: {scan_config}
Execution Time: {execution_time:.2f}s

NOTE: This is a placeholder implementation.
To enable actual OpenVAS scanning:
1. Install OpenVAS/Greenbone Vulnerability Manager (GVM)
2. Configure GVM daemon and web interface
3. Set up scan targets and configurations
4. Implement actual GMP (Greenbone Management Protocol) integration

Placeholder findings:
- Host is alive
- Multiple open ports detected
- Potential vulnerabilities require actual OpenVAS integration
- CVE database updates recommended"""
        
        return ToolScanResult(True, placeholder_data, metadata=metadata)

class NmapNSETool(BaseTool):
    name: str = "nmap_nse"
    description: str = "Performs advanced vulnerability scanning using Nmap NSE scripts."
    timeout: float = 600
    script_categories: Optional[list] = None
    max_retries: int = 3
    retry_delay: int = 10
    
    def __init__(self, timeout: float = 600, script_categories: Optional[list] = None):
        super().__init__()
        self.timeout = ConfigValidator.validate_timeout(timeout)
        self.script_categories = script_categories or ['vuln', 'exploit']
        self.max_retries = 3
        self.retry_delay = 10

    def _run(self):
        raise NotImplementedError("NmapNSETool._run is not yet implemented")

    def run(self, target: str, **kwargs) -> str:
        """
        Runs Nmap with NSE scripts on the specified target with enhanced error handling.
        
        Args:
            target (str): The IP address or hostname to scan.
            **kwargs: Additional parameters (timeout, scripts, ports)
            
        Returns:
            str: JSON formatted scan result
        """
        custom_timeout = kwargs.get('timeout', self.timeout)
        custom_scripts = kwargs.get('scripts', None)
        ports = kwargs.get('ports', None)
        
        try:
            # Validate target
            validated_target, target_type = TargetValidator.validate_target(target)
            log_scan_attempt(validated_target, "nmap_nse")
            
            # Execute scan with retry logic
            scan_result = self._execute_nse_scan_with_retry(
                validated_target, custom_timeout, custom_scripts, ports
            )
            
            return scan_result.to_json()
            
        except ValidationError as e:
            error_result = ToolScanResult(False, "", f"Validation error: {str(e)}")
            logger.error(f"Nmap NSE validation error: {e}")
            return error_result.to_json()
            
        except NetworkError as e:
            error_result = ScanResult(False, "", f"Network error: {str(e)}")
            logger.error(f"Nmap NSE network error: {e}")
            return error_result.to_json()
            
        except ScanTimeoutError as e:
            error_result = ScanResult(False, "", f"Scan timeout: {str(e)}")
            logger.error(f"Nmap NSE timeout error: {e}")
            return error_result.to_json()
            
        except Exception as e:
            error_result = ScanResult(False, "", f"Unexpected error: {str(e)}")
            logger.error(f"Nmap NSE unexpected error: {e}")
            return error_result.to_json()
    
    def _execute_nse_scan_with_retry(self, target: str, timeout: float, 
                                   custom_scripts: Optional[str], 
                                   ports: Optional[str]) -> ToolScanResult:
        """
        Execute Nmap NSE scan with retry logic.
        
        Args:
            target (str): Validated target
            timeout (float): Scan timeout
            custom_scripts (str, optional): Custom script specification
            ports (str, optional): Port specification
            
        Returns:
            ScanResult: Scan execution result
        """
        last_exception = None
        
        for attempt in range(self.max_retries):
            try:
                logger.info(f"Nmap NSE scan attempt {attempt + 1}/{self.max_retries} for {target}")
                
                cmd = self._build_nse_command(target, custom_scripts, ports)
                
                start_time = time.time()
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=timeout,
                    check=False
                )
                execution_time = time.time() - start_time
                
                metadata = {
                    'command': ' '.join(cmd),
                    'execution_time': execution_time,
                    'attempt': attempt + 1,
                    'return_code': result.returncode,
                    'scripts_used': custom_scripts or ','.join(self.script_categories)
                }
                
                if result.returncode == 0:
                    logger.info(f"Nmap NSE scan successful for {target} in {execution_time:.2f}s")
                    return ScanResult(True, result.stdout, metadata=metadata)
                else:
                    logger.warning(f"Nmap NSE returned non-zero exit code {result.returncode}")
                    error_msg = f"Nmap NSE error (exit code {result.returncode}): {result.stderr}"
                    
                    # Check if this is a retryable error
                    if self._is_retryable_nse_error(result.stderr):
                        last_exception = NetworkError(error_msg)
                        if attempt < self.max_retries - 1:
                            logger.info(f"Retrying in {self.retry_delay} seconds...")
                            time.sleep(self.retry_delay)
                            continue
                    
                    return ScanResult(False, result.stdout, error_msg, metadata)
                    
            except subprocess.TimeoutExpired:
                timeout_msg = f"Nmap NSE scan timed out after {timeout} seconds"
                logger.error(timeout_msg)
                last_exception = ScanTimeoutError(timeout_msg)
                
                if attempt < self.max_retries - 1:
                    logger.info(f"Retrying with extended timeout...")
                    timeout *= 1.3  # Moderate increase for NSE scripts
                    time.sleep(self.retry_delay)
                    continue
                    
            except Exception as e:
                unexpected_msg = f"Unexpected error during nmap NSE execution: {str(e)}"
                logger.error(unexpected_msg)
                last_exception = Exception(unexpected_msg)
                break
        
        # All retries failed
        if last_exception:
            raise last_exception
        else:
            raise Exception("All nmap NSE scan attempts failed")
    
    def _build_nse_command(self, target: str, custom_scripts: Optional[str], 
                          ports: Optional[str]) -> list:
        """
        Build Nmap NSE command.
        
        Args:
            target (str): Target to scan
            custom_scripts (str, optional): Custom script specification
            ports (str, optional): Port specification
            
        Returns:
            list: Nmap command as list
        """
        cmd = ["nmap", "-sV"]  # Service version detection
        
        # Add script specification
        if custom_scripts:
            cmd.extend(["--script", custom_scripts])
        else:
            # Use default script categories
            script_arg = ','.join(self.script_categories)
            cmd.extend(["--script", script_arg])
        
        # Add script arguments for better vulnerability detection
        cmd.extend(["--script-args", "vulns.showall"])
        
        # Add port specification
        if ports:
            try:
                # Validate port range
                if '-' in ports or ',' in ports:
                    cmd.extend(["-p", ports])
                else:
                    ConfigValidator.validate_port(ports)
                    cmd.extend(["-p", ports])
            except ValidationError as e:
                logger.warning(f"Invalid port specification '{ports}': {e}")
        
        # Add timing template for reasonable speed
        cmd.extend(["-T3"])
        
        # Add target
        cmd.append(target)
        
        return cmd
    
    def _is_retryable_nse_error(self, stderr: str) -> bool:
        """
        Determine if an NSE error is retryable.
        
        Args:
            stderr (str): Error message from nmap NSE
            
        Returns:
            bool: True if error is retryable
        """
        retryable_patterns = [
            "script execution failed",
            "connection refused",
            "network unreachable",
            "timeout",
            "temporary failure"
        ]
        
        stderr_lower = stderr.lower()
        return any(pattern in stderr_lower for pattern in retryable_patterns)

class ReportWriterTool(BaseTool):
    name: str = "report_writer"
    description: str = "Compiles vulnerability scan findings into a comprehensive, structured report with risk ratings, remediation steps, and OWASP ASVS mapping."
    output_format: str = "text"
    include_executive_summary: bool = True
    risk_matrix: dict = None
    
    def __init__(self, output_format: str = "text", include_executive_summary: bool = True):
        super().__init__()
        self.output_format = output_format.lower()
        self.include_executive_summary = include_executive_summary
        self.risk_matrix = {
            'critical': {'score': 9.0, 'color': 'RED'},
            'high': {'score': 7.0, 'color': 'ORANGE'},
            'medium': {'score': 4.0, 'color': 'YELLOW'},
            'low': {'score': 2.0, 'color': 'GREEN'},
            'info': {'score': 0.0, 'color': 'BLUE'}
        }

    def _run(self):
        raise NotImplementedError("ReportWriterTool._run is not yet implemented")

    def run(self, findings: str, **kwargs) -> str:
        """
        Generates a vulnerability assessment report from provided findings with enhanced error handling.
        
        Args:
            findings (str): The vulnerability scan findings in structured text or JSON format.
            **kwargs: Additional parameters (target_info, scan_metadata)
            
        Returns:
            str: JSON formatted report result
        """
        target_info = kwargs.get('target_info', {})
        scan_metadata = kwargs.get('scan_metadata', {})
        
        try:
            # Validate input
            if not findings or not findings.strip():
                raise ValidationError("Findings cannot be empty")
            
            # Generate report with comprehensive error handling
            report_result = self._generate_comprehensive_report(
                findings, target_info, scan_metadata
            )
            
            return report_result.to_json()
            
        except ValidationError as e:
            error_result = ScanResult(False, "", f"Validation error: {str(e)}")
            logger.error(f"Report validation error: {e}")
            return error_result.to_json()
            
        except Exception as e:
            error_result = ScanResult(False, "", f"Report generation error: {str(e)}")
            logger.error(f"Report generation error: {e}")
            return error_result.to_json()
    
    def _generate_comprehensive_report(self, findings: str, target_info: dict, 
                                     scan_metadata: dict) -> ToolScanResult:
        """
        Generate a comprehensive vulnerability assessment report.
        
        Args:
            findings (str): Scan findings
            target_info (dict): Target information
            scan_metadata (dict): Scan metadata
            
        Returns:
            ScanResult: Report generation result
        """
        start_time = time.time()
        
        try:
            # Parse findings (attempt JSON first, then treat as text)
            parsed_findings = self._parse_findings(findings)
            
            # Generate report sections
            report_sections = {
                'header': self._generate_header(target_info, scan_metadata),
                'executive_summary': self._generate_executive_summary(parsed_findings) if self.include_executive_summary else "",
                'technical_findings': self._generate_technical_findings(parsed_findings),
                'risk_assessment': self._generate_risk_assessment(parsed_findings),
                'remediation': self._generate_remediation_guidance(parsed_findings),
                'owasp_mapping': self._generate_owasp_mapping(parsed_findings),
                'appendix': self._generate_appendix(scan_metadata)
            }
            
            # Combine sections into final report
            if self.output_format == "json":
                report_data = json.dumps(report_sections, indent=2)
            else:
                report_data = self._format_text_report(report_sections)
            
            execution_time = time.time() - start_time
            
            metadata = {
                'generation_time': execution_time,
                'output_format': self.output_format,
                'sections_included': list(report_sections.keys()),
                'findings_count': len(parsed_findings) if isinstance(parsed_findings, list) else 1
            }
            
            logger.info(f"Report generated successfully in {execution_time:.2f}s")
            return ScanResult(True, report_data, metadata=metadata)
            
        except Exception as e:
            error_msg = f"Error generating report: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg)
    
    def _parse_findings(self, findings: str) -> list:
        """
        Parse findings from string format.
        
        Args:
            findings (str): Raw findings data
            
        Returns:
            list: Parsed findings
        """
        try:
            # Try to parse as JSON first
            if findings.strip().startswith(('[', '{')):
                parsed = json.loads(findings)
                return parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            pass
        
        # Treat as text and create basic structure
        return [{
            'type': 'text_finding',
            'data': findings,
            'severity': 'info',
            'timestamp': time.time()
        }]
    
    def _generate_header(self, target_info: dict, scan_metadata: dict) -> str:
        """
        Generate report header.
        
        Args:
            target_info (dict): Target information
            scan_metadata (dict): Scan metadata
            
        Returns:
            str: Report header
        """
        current_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        target = target_info.get('target', 'Unknown')
        
        return f"""=== VULNERABILITY ASSESSMENT REPORT ===
Generated: {current_time}
Target: {target}
Scan Type: Comprehensive Security Assessment
Framework: VAPT Agents v1.0

⚠️  CONFIDENTIAL SECURITY ASSESSMENT ⚠️
This document contains sensitive security information.
Distribute only to authorized personnel.
"""
    
    def _generate_executive_summary(self, findings: list) -> str:
        """
        Generate executive summary.
        
        Args:
            findings (list): Parsed findings
            
        Returns:
            str: Executive summary
        """
        total_findings = len(findings)
        
        # Count findings by severity (placeholder logic)
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts['info'] += 1
        
        return f"""EXECUTIVE SUMMARY
================

This vulnerability assessment identified {total_findings} findings across the target environment.

Severity Breakdown:
- Critical: {severity_counts['critical']} findings
- High: {severity_counts['high']} findings
- Medium: {severity_counts['medium']} findings
- Low: {severity_counts['low']} findings
- Informational: {severity_counts['info']} findings

Recommendation: Address critical and high-severity findings immediately.
Implement a systematic remediation plan for medium and low-severity issues.
"""
    
    def _generate_technical_findings(self, findings: list) -> str:
        """
        Generate technical findings section.
        
        Args:
            findings (list): Parsed findings
            
        Returns:
            str: Technical findings section
        """
        section = "TECHNICAL FINDINGS\n================\n\n"
        
        for i, finding in enumerate(findings, 1):
            finding_type = finding.get('type', 'Unknown')
            severity = finding.get('severity', 'info').upper()
            data = finding.get('data', 'No data available')
            
            section += f"Finding {i}: {finding_type}\n"
            section += f"Severity: {severity}\n"
            section += f"Details:\n{data}\n"
            section += "-" * 50 + "\n\n"
        
        return section
    
    def _generate_risk_assessment(self, findings: list) -> str:
        """
        Generate risk assessment section.
        
        Args:
            findings (list): Parsed findings
            
        Returns:
            str: Risk assessment section
        """
        return """RISK ASSESSMENT
===============

Risk Methodology:
This assessment uses a combination of CVSS scoring and business impact analysis.

Risk Calculation:
- Critical (9.0-10.0): Immediate action required
- High (7.0-8.9): Address within 7 days
- Medium (4.0-6.9): Address within 30 days
- Low (0.1-3.9): Address within 90 days
- Informational (0.0): Monitor and document

Overall Risk Level: [Calculated based on findings]
"""
    
    def _generate_remediation_guidance(self, findings: list) -> str:
        """
        Generate remediation guidance section.
        
        Args:
            findings (list): Parsed findings
            
        Returns:
            str: Remediation guidance section
        """
        return """REMEDIATION GUIDANCE
===================

Immediate Actions:
1. Patch all critical and high-severity vulnerabilities
2. Implement network segmentation where applicable
3. Update security configurations
4. Review and update access controls

Long-term Recommendations:
1. Establish regular vulnerability scanning schedule
2. Implement security awareness training
3. Deploy intrusion detection systems
4. Create incident response procedures

Compliance Considerations:
- Ensure remediation aligns with organizational policies
- Document all changes for audit purposes
- Test fixes in development environment first
"""
    
    def _generate_owasp_mapping(self, findings: list) -> str:
        """
        Generate OWASP ASVS mapping section.
        
        Args:
            findings (list): Parsed findings
            
        Returns:
            str: OWASP mapping section
        """
        return """OWASP ASVS MAPPING
==================

This assessment is aligned with OWASP Application Security Verification Standard (ASVS) v4.0.

Relevant ASVS Categories:
- V1: Architecture, Design and Threat Modeling
- V2: Authentication
- V3: Session Management
- V4: Access Control
- V5: Validation, Sanitization and Encoding
- V7: Error Handling and Logging
- V9: Communications
- V10: Malicious Code
- V11: Business Logic
- V12: Files and Resources
- V13: API and Web Service
- V14: Configuration

Note: Specific findings should be mapped to relevant ASVS requirements
for comprehensive compliance assessment.
"""
    
    def _generate_appendix(self, scan_metadata: dict) -> str:
        """
        Generate appendix section.
        
        Args:
            scan_metadata (dict): Scan metadata
            
        Returns:
            str: Appendix section
        """
        return f"""APPENDIX
========

Scan Methodology:
This assessment utilized multiple security scanning tools and techniques:
- Network reconnaissance (Nmap)
- Vulnerability scanning (Nessus, OpenVAS)
- Advanced script-based testing (Nmap NSE)

Scan Metadata:
{json.dumps(scan_metadata, indent=2) if scan_metadata else 'No metadata available'}

Disclaimer:
This assessment provides a point-in-time security evaluation.
Security posture may change due to system updates, configuration changes,
or new vulnerability discoveries. Regular assessments are recommended.

Contact Information:
For questions regarding this assessment, contact the security team.
"""
    
    def _format_text_report(self, sections: dict) -> str:
        """
        Format sections into text report.
        
        Args:
            sections (dict): Report sections
            
        Returns:
            str: Formatted text report
        """
        report = ""
        for section_name, content in sections.items():
            if content.strip():
                report += content + "\n\n"
        
        return report.strip()
