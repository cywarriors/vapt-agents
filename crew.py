from agents import vuln_scan_agent, vuln_comprehensive_scanner_agent, report_generator_agent
from tasks import reconnaissance_task, comprehensive_vuln_scan_task, report_generation_task
from crewai import Crew
import logging
import sys
import time
from validation import (
    TargetValidator, ValidationError, NetworkError, 
    ScanTimeoutError, get_user_confirmation, log_scan_attempt
)
from output_manager import (
    result_storage, result_pipeline, OutputFormat, 
    ScanResult, ScanMetadata, output_formatter
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vapt_agents.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create the Crew for Vulnerability Scanning
vuln_scan_crew = Crew(
    agents=[
        vuln_scan_agent,
        vuln_comprehensive_scanner_agent,
        report_generator_agent
    ],
    tasks=[
        reconnaissance_task,
        comprehensive_vuln_scan_task,
        report_generation_task
    ],
    verbose=True
)


def execute_vuln_scan(target, require_confirmation=True, scan_config=None):
    """
    Executes the vulnerability scanning crew workflow for the specified target with comprehensive validation.
    
    Args:
        target (str): The IP address or hostname to scan.
        require_confirmation (bool): Whether to require user confirmation for scanning
        scan_config (dict, optional): Custom scan configuration
        
    Returns:
        dict: The result of the crew's execution with status information
    """
    scan_result = {
        'success': False,
        'target': target,
        'error': None,
        'data': None,
        'metadata': {}
    }
    
    try:
        logger.info(f"Starting vulnerability scan for target: {target}")
        
        # Validate target format and authorization
        try:
            validated_target, target_type = TargetValidator.validate_target(
                target, 
                allow_private=True,  # Allow private IPs for internal testing
                require_authorization=True
            )
            scan_result['metadata']['target_type'] = target_type
            scan_result['metadata']['validated_target'] = validated_target
            
        except ValidationError as e:
            error_msg = f"Target validation failed: {str(e)}"
            logger.error(error_msg)
            scan_result['error'] = error_msg
            return scan_result
        
        # Get user confirmation for scanning
        if require_confirmation:
            if not get_user_confirmation(validated_target, target_type):
                error_msg = "Scan cancelled: User did not confirm authorization"
                logger.warning(error_msg)
                scan_result['error'] = error_msg
                return scan_result
        
        # Resolve hostname if needed
        if target_type == 'hostname':
            try:
                resolved_ip = TargetValidator.resolve_hostname(validated_target)
                if resolved_ip:
                    scan_result['metadata']['resolved_ip'] = resolved_ip
                    logger.info(f"Resolved {validated_target} to {resolved_ip}")
            except NetworkError as e:
                logger.warning(f"DNS resolution failed: {e}")
                # Continue with hostname - some tools can handle DNS resolution
        
        # Log scan attempt for audit purposes
        log_scan_attempt(validated_target, "comprehensive_scan")
        
        # Prepare scan inputs
        scan_inputs = {
            "target": validated_target,
            "target_type": target_type,
            "scan_config": scan_config or {},
            "metadata": scan_result['metadata']
        }
        
        # Start scan session for agent pipeline
        session_id = result_pipeline.start_scan_session(validated_target, scan_config.get('type', 'comprehensive'))
        scan_result['metadata']['session_id'] = session_id
        
        # Execute the crew workflow with enhanced error handling
        try:
            logger.info("Executing crew workflow...")
            crew_result = vuln_scan_crew.kickoff(inputs=scan_inputs)
            
            scan_result['success'] = True
            scan_result['data'] = crew_result
            scan_result['metadata']['crew_execution'] = 'completed'
            
            # Save results in multiple formats
            try:
                saved_files = save_scan_results_multiple_formats(
                    crew_result, validated_target, session_id, scan_config
                )
                scan_result['metadata']['saved_files'] = saved_files
                logger.info(f"Results saved in {len(saved_files)} formats")
            except Exception as save_error:
                logger.warning(f"Failed to save some result formats: {save_error}")
            
            logger.info(f"Vulnerability scan completed successfully for {validated_target}")
            
        except Exception as crew_error:
            error_msg = f"Crew execution failed: {str(crew_error)}"
            logger.error(error_msg)
            scan_result['error'] = error_msg
            scan_result['metadata']['crew_execution'] = 'failed'
            
    except NetworkError as e:
        error_msg = f"Network error during scan: {str(e)}"
        logger.error(error_msg)
        scan_result['error'] = error_msg
        
    except ScanTimeoutError as e:
        error_msg = f"Scan timeout: {str(e)}"
        logger.error(error_msg)
        scan_result['error'] = error_msg
        
    except KeyboardInterrupt:
        error_msg = "Scan interrupted by user"
        logger.warning(error_msg)
        scan_result['error'] = error_msg
        
    except Exception as e:
        error_msg = f"Unexpected error during scan: {str(e)}"
        logger.error(error_msg)
        scan_result['error'] = error_msg
    
    return scan_result

def save_scan_results_multiple_formats(crew_result, target, session_id, scan_config):
    """
    Save scan results in multiple formats.
    
    Args:
        crew_result: Result from crew execution
        target (str): Scan target
        session_id (str): Session ID
        scan_config (dict): Scan configuration
        
    Returns:
        dict: Dictionary of saved file paths by format
    """
    saved_files = {}
    
    try:
        # Create a structured scan result for formatting
        from datetime import datetime, timezone
        import uuid
        
        metadata = ScanMetadata(
            scan_id=session_id,
            target=target,
            target_type='consolidated',
            scan_type=scan_config.get('type', 'comprehensive'),
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            agent_name='crew_consolidated',
            tool_name='vapt_agents',
            success=True
        )
        
        # Parse vulnerabilities from crew result (basic parsing)
        vulnerabilities = []
        if isinstance(crew_result, str) and crew_result:
            # Simple vulnerability detection in text
            lines = crew_result.split('\n')
            for line in lines:
                if any(keyword in line.lower() for keyword in ['vulnerability', 'cve-', 'exploit', 'vulnerable']):
                    from output_manager import Vulnerability, SeverityLevel
                    vuln = Vulnerability(
                        id=str(uuid.uuid4()),
                        name=line.strip()[:100],  # Limit name length
                        severity=SeverityLevel.INFO,  # Default severity
                        description=line.strip(),
                        evidence=line.strip(),
                        recommendation="Review and investigate this finding"
                    )
                    vulnerabilities.append(vuln)
        
        structured_result = ScanResult(
            metadata=metadata,
            vulnerabilities=vulnerabilities,
            raw_output=str(crew_result),
            structured_data={'scan_config': scan_config}
        )
        
        # Save in multiple formats
        formats_to_save = [
            (OutputFormat.JSON, 'json'),
            (OutputFormat.TXT, 'txt'),
            (OutputFormat.HTML, 'html')
        ]
        
        # Add XML and CSV if there are vulnerabilities
        if vulnerabilities:
            formats_to_save.extend([
                (OutputFormat.XML, 'xml'),
                (OutputFormat.CSV, 'csv')
            ])
        
        for format_type, extension in formats_to_save:
            try:
                file_path = result_storage.storage_path / f"scan_{target.replace('.', '_')}_{session_id[:8]}.{extension}"
                
                formatted_data = output_formatter.format(structured_result, format_type)
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(formatted_data)
                
                saved_files[format_type.value] = str(file_path)
                logger.info(f"Saved {format_type.value.upper()} report: {file_path}")
                
            except Exception as e:
                logger.warning(f"Failed to save {format_type.value} format: {e}")
        
        # Store in result storage system
        try:
            storage_path = result_storage.store_result(structured_result, OutputFormat.JSON)
            saved_files['storage_path'] = storage_path
        except Exception as e:
            logger.warning(f"Failed to store in result storage: {e}")
        
    except Exception as e:
        logger.error(f"Error saving scan results: {e}")
    
    return saved_files

def validate_scan_environment():
    """
    Validate that the scanning environment is properly configured.
    
    Returns:
        tuple: (is_valid, error_messages)
    """
    error_messages = []
    
    # Check for required tools
    import subprocess
    
    try:
        # Check nmap availability
        result = subprocess.run(['nmap', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            error_messages.append("Nmap is not properly installed or accessible")
    except (subprocess.SubprocessError, FileNotFoundError):
        error_messages.append("Nmap is not installed or not in PATH")
    except subprocess.TimeoutExpired:
        error_messages.append("Nmap check timed out")
    
    # Check Python dependencies
    try:
        import crewai
        import crewai_tools
    except ImportError as e:
        error_messages.append(f"Missing Python dependency: {e}")
    
    # Check file permissions for logging
    try:
        with open('vapt_agents.log', 'a') as f:
            f.write("# Environment validation check\n")
    except PermissionError:
        error_messages.append("Cannot write to log file - check permissions")
    
    is_valid = len(error_messages) == 0
    return is_valid, error_messages

def interactive_scan():
    """
    Interactive scan function with enhanced user experience.
    
    Returns:
        dict: Scan result
    """
    print("🔍 VAPT Agents - Vulnerability Assessment Tool")
    print("=" * 50)
    
    # Validate environment
    is_valid, errors = validate_scan_environment()
    if not is_valid:
        print("\n❌ Environment validation failed:")
        for error in errors:
            print(f"   - {error}")
        print("\nPlease fix these issues before proceeding.")
        return {'success': False, 'error': 'Environment validation failed'}
    
    print("\n✅ Environment validation passed")
    
    # Get target from user
    while True:
        try:
            target = input("\nEnter target IP, hostname, or URL: ").strip()
            if not target:
                print("❌ Target cannot be empty")
                continue
            
            # Basic validation
            validated_target, target_type = TargetValidator.validate_target(target)
            print(f"✅ Target validated: {validated_target} (Type: {target_type})")
            break
            
        except ValidationError as e:
            print(f"❌ Invalid target: {e}")
            continue
        except KeyboardInterrupt:
            print("\n\n👋 Scan cancelled by user")
            return {'success': False, 'error': 'Cancelled by user'}
    
    # Get scan configuration
    print("\n📋 Scan Configuration:")
    print("1. Quick scan (faster, basic checks)")
    print("2. Comprehensive scan (thorough, slower)")
    print("3. Custom scan")
    
    scan_config = {'type': 'comprehensive'}  # Default
    
    try:
        choice = input("\nSelect scan type (1-3, default=2): ").strip()
        if choice == '1':
            scan_config['type'] = 'quick'
        elif choice == '3':
            print("Custom scan options:")
            timeout = input("Timeout in seconds (default=300): ").strip()
            if timeout:
                try:
                    scan_config['timeout'] = int(timeout)
                except ValueError:
                    print("Invalid timeout, using default")
    except KeyboardInterrupt:
        print("\n\n👋 Scan cancelled by user")
        return {'success': False, 'error': 'Cancelled by user'}
    
    print(f"\n🚀 Starting {scan_config['type']} scan for {target}...")
    print("This may take several minutes depending on the target and scan type.")
    print("Press Ctrl+C to cancel at any time.\n")
    
    # Execute scan
    result = execute_vuln_scan(target, require_confirmation=True, scan_config=scan_config)
    
    return result

# Example usage:
if __name__ == "__main__":
    try:
        # Run interactive scan
        result = interactive_scan()
        
        if result['success']:
            print("\n✅ Scan completed successfully!")
            print(f"Target: {result['target']}")
            if result.get('data'):
                print("\n📊 Scan Results:")
                print("-" * 40)
                print(result['data'])
            
            # Save results to file
            try:
                import json
                timestamp = int(time.time())
                filename = f"scan_results_{result['target'].replace('.', '_')}_{timestamp}.json"
                with open(filename, 'w') as f:
                    json.dump(result, f, indent=2, default=str)
                print(f"\n💾 Results saved to: {filename}")
            except Exception as e:
                logger.warning(f"Could not save results to file: {e}")
                
        else:
            print("\n❌ Scan failed!")
            if result.get('error'):
                print(f"Error: {result['error']}")
            
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error in main: {e}")
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)

