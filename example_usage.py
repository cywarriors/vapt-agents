#!/usr/bin/env python3
"""
Example usage of VAPT agents with enhanced error handling and validation.
This script demonstrates various ways to use the vulnerability assessment framework.
"""

import sys
import json
import time
from pathlib import Path

# Import VAPT components
from crew import execute_vuln_scan, validate_scan_environment
from validation import TargetValidator, ValidationError, NetworkError
from config import config

def example_basic_scan():
    """Example of a basic vulnerability scan."""
    print("=== Basic Scan Example ===")
    
    target = "scanme.nmap.org"  # Nmap's official test target
    
    try:
        # Execute scan with default settings
        result = execute_vuln_scan(
            target=target,
            require_confirmation=False,  # Skip confirmation for example
            scan_config={'type': 'quick'}
        )
        
        if result['success']:
            print(f"✅ Scan completed successfully for {target}")
            print(f"Target type: {result['metadata'].get('target_type', 'unknown')}")
            
            # Save results
            save_scan_results(result, "basic_scan_example")
        else:
            print(f"❌ Scan failed: {result['error']}")
            
    except Exception as e:
        print(f"💥 Unexpected error: {e}")

def example_comprehensive_scan():
    """Example of a comprehensive vulnerability scan."""
    print("\n=== Comprehensive Scan Example ===")
    
    target = "127.0.0.1"  # Localhost example
    
    # Custom scan configuration
    scan_config = {
        'type': 'comprehensive',
        'timeout': 600,
        'include_nse': True,
        'nmap_timing': 'T3'
    }
    
    try:
        result = execute_vuln_scan(
            target=target,
            require_confirmation=False,
            scan_config=scan_config
        )
        
        if result['success']:
            print(f"✅ Comprehensive scan completed for {target}")
            save_scan_results(result, "comprehensive_scan_example")
        else:
            print(f"❌ Scan failed: {result['error']}")
            
    except KeyboardInterrupt:
        print("\n🛑 Scan interrupted by user")
    except Exception as e:
        print(f"💥 Unexpected error: {e}")

def example_batch_scan():
    """Example of scanning multiple targets."""
    print("\n=== Batch Scan Example ===")
    
    targets = [
        "127.0.0.1",
        "scanme.nmap.org",
        # Add more targets as needed
    ]
    
    results = []
    
    for i, target in enumerate(targets, 1):
        print(f"\n📍 Scanning target {i}/{len(targets)}: {target}")
        
        try:
            # Validate target first
            validated_target, target_type = TargetValidator.validate_target(target)
            print(f"   Target validated: {validated_target} (Type: {target_type})")
            
            # Execute scan
            result = execute_vuln_scan(
                target=target,
                require_confirmation=False,
                scan_config={'type': 'quick', 'timeout': 300}
            )
            
            results.append({
                'target': target,
                'result': result,
                'timestamp': time.time()
            })
            
            if result['success']:
                print(f"   ✅ Scan completed successfully")
            else:
                print(f"   ❌ Scan failed: {result['error']}")
                
        except ValidationError as e:
            print(f"   ❌ Validation error: {e}")
            results.append({
                'target': target,
                'result': {'success': False, 'error': f'Validation error: {e}'},
                'timestamp': time.time()
            })
        except Exception as e:
            print(f"   💥 Unexpected error: {e}")
            results.append({
                'target': target,
                'result': {'success': False, 'error': f'Unexpected error: {e}'},
                'timestamp': time.time()
            })
    
    # Save batch results
    save_batch_results(results)
    print_batch_summary(results)

def example_configuration_management():
    """Example of configuration management."""
    print("\n=== Configuration Management Example ===")
    
    # Display current configuration
    print("Current timeouts:")
    for operation in ['nmap_basic', 'nmap_comprehensive', 'nessus', 'openvas']:
        timeout = config.get_timeout(operation)
        print(f"  {operation}: {timeout}s")
    
    # Check tool availability
    print("\nTool availability:")
    for tool in ['nmap', 'nessus', 'openvas']:
        enabled = config.is_tool_enabled(tool)
        print(f"  {tool}: {'✅ Enabled' if enabled else '❌ Disabled'}")
    
    # Validate configuration
    is_valid, errors = config.validate_config()
    if is_valid:
        print("\n✅ Configuration is valid")
    else:
        print("\n❌ Configuration errors:")
        for error in errors:
            print(f"  - {error}")
    
    # Example of updating configuration
    print("\nUpdating scan timeout...")
    original_timeout = config.get_timeout('nmap_basic')
    config.set('timeouts.nmap_basic', 450, save=False)
    new_timeout = config.get_timeout('nmap_basic')
    print(f"  Timeout changed from {original_timeout}s to {new_timeout}s")
    
    # Restore original value
    config.set('timeouts.nmap_basic', original_timeout, save=False)

def example_error_handling():
    """Example of error handling scenarios."""
    print("\n=== Error Handling Examples ===")
    
    # Test invalid target
    print("1. Testing invalid target validation...")
    try:
        TargetValidator.validate_target("invalid..target..format")
    except ValidationError as e:
        print(f"   ✅ Correctly caught validation error: {e}")
    
    # Test forbidden target
    print("2. Testing forbidden target detection...")
    try:
        TargetValidator.validate_target("example.gov", require_authorization=True)
    except ValidationError as e:
        print(f"   ✅ Correctly caught forbidden target: {e}")
    
    # Test DNS resolution
    print("3. Testing DNS resolution...")
    try:
        ip = TargetValidator.resolve_hostname("nonexistent.invalid.domain.test")
        print(f"   Resolved to: {ip}")
    except NetworkError as e:
        print(f"   ✅ Correctly caught network error: {e}")
    
    # Test configuration validation
    print("4. Testing configuration validation...")
    original_timeout = config.get('timeouts.nmap_basic')
    config.set('timeouts.nmap_basic', -100, save=False)  # Invalid timeout
    is_valid, errors = config.validate_config()
    if not is_valid:
        print(f"   ✅ Correctly caught config error: {errors[0]}")
    config.set('timeouts.nmap_basic', original_timeout, save=False)  # Restore

def save_scan_results(result, filename_prefix):
    """Save scan results to file."""
    try:
        results_dir = config.create_results_directory()
        timestamp = int(time.time())
        filename = f"{filename_prefix}_{timestamp}.json"
        filepath = Path(results_dir) / filename
        
        with open(filepath, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        
        print(f"💾 Results saved to: {filepath}")
        
    except Exception as e:
        print(f"⚠️  Could not save results: {e}")

def save_batch_results(results):
    """Save batch scan results to file."""
    try:
        results_dir = config.create_results_directory()
        timestamp = int(time.time())
        filename = f"batch_scan_results_{timestamp}.json"
        filepath = Path(results_dir) / filename
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"💾 Batch results saved to: {filepath}")
        
    except Exception as e:
        print(f"⚠️  Could not save batch results: {e}")

def print_batch_summary(results):
    """Print summary of batch scan results."""
    print(f"\n📊 Batch Scan Summary:")
    print(f"   Total targets: {len(results)}")
    
    successful = sum(1 for r in results if r['result']['success'])
    failed = len(results) - successful
    
    print(f"   Successful scans: {successful}")
    print(f"   Failed scans: {failed}")
    
    if failed > 0:
        print(f"\nFailed targets:")
        for result in results:
            if not result['result']['success']:
                print(f"   - {result['target']}: {result['result']['error']}")

def main():
    """Main example function."""
    print("🔍 VAPT Agents - Error Handling Examples")
    print("=" * 50)
    
    # Validate environment first
    print("Validating scan environment...")
    is_valid, errors = validate_scan_environment()
    
    if not is_valid:
        print("❌ Environment validation failed:")
        for error in errors:
            print(f"   - {error}")
        print("\nPlease fix these issues before running scans.")
        return 1
    
    print("✅ Environment validation passed\n")
    
    try:
        # Run examples
        example_configuration_management()
        example_error_handling()
        
        # Ask user which scan examples to run
        print("\nAvailable scan examples:")
        print("1. Basic scan (quick)")
        print("2. Comprehensive scan")
        print("3. Batch scan (multiple targets)")
        print("4. All examples")
        print("5. Skip scan examples")
        
        choice = input("\nSelect examples to run (1-5, default=5): ").strip()
        
        if choice == '1':
            example_basic_scan()
        elif choice == '2':
            example_comprehensive_scan()
        elif choice == '3':
            example_batch_scan()
        elif choice == '4':
            example_basic_scan()
            example_comprehensive_scan()
            example_batch_scan()
        else:
            print("Skipping scan examples.")
        
        print("\n✅ Examples completed successfully!")
        return 0
        
    except KeyboardInterrupt:
        print("\n\n👋 Examples interrupted by user")
        return 130
    except Exception as e:
        print(f"\n💥 Unexpected error in examples: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
