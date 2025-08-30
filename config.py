"""
Configuration management for VAPT agents project.
Centralized configuration for all scanning tools and behavior.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class VAPTConfig:
    """Configuration manager for VAPT agents."""
    
    DEFAULT_CONFIG = {
        # Scan timeouts (seconds)
        'timeouts': {
            'nmap_basic': 300,
            'nmap_comprehensive': 600,
            'nmap_nse': 900,
            'nessus': 1800,
            'openvas': 1800,
            'dns_resolution': 10
        },
        
        # Scan behavior
        'scan_behavior': {
            'max_retries': 3,
            'retry_delay': 5,
            'timing_template': 'T3',
            'require_user_confirmation': True,
            'allow_private_ips': True,
            'enable_audit_logging': True
        },
        
        # Report settings
        'reporting': {
            'output_format': 'text',
            'include_executive_summary': True,
            'save_results': True,
            'results_directory': './scan_results',
            'include_metadata': True
        },
        
        # Tool configurations
        'tools': {
            'nmap': {
                'enabled': True,
                'path': 'nmap',
                'default_args': ['-A', '-T3'],
                'script_categories': ['vuln', 'exploit']
            },
            'nessus': {
                'enabled': False,
                'api_url': None,
                'access_key': None,
                'secret_key': None,
                'default_template': 'basic'
            },
            'openvas': {
                'enabled': False,
                'gvm_host': '127.0.0.1',
                'gvm_port': 9390,
                'username': None,
                'password': None,
                'default_config': 'Full and fast'
            }
        },
        
        # Security settings
        'security': {
            'forbidden_domains': [
                r'.*\.gov$',
                r'.*\.mil$',
                r'.*bank.*',
                r'.*hospital.*'
            ],
            'require_explicit_authorization': True,
            'log_all_attempts': True,
            'rate_limiting': {
                'enabled': False,
                'max_scans_per_hour': 10
            }
        },
        
        # Logging configuration
        'logging': {
            'level': 'INFO',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'file': 'vapt_agents.log',
            'max_size_mb': 100,
            'backup_count': 5
        }
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_file (str, optional): Path to configuration file
        """
        self.config_file = config_file or 'vapt_config.json'
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from file or create default.
        
        Returns:
            Dict[str, Any]: Configuration dictionary
        """
        config_path = Path(self.config_file)
        
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    file_config = json.load(f)
                
                # Merge with defaults
                config = self._deep_merge(self.DEFAULT_CONFIG.copy(), file_config)
                logger.info(f"Configuration loaded from {self.config_file}")
                return config
                
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load config file {self.config_file}: {e}")
                logger.info("Using default configuration")
        
        # Create default config file
        self._save_config(self.DEFAULT_CONFIG)
        return self.DEFAULT_CONFIG.copy()
    
    def _save_config(self, config: Dict[str, Any]) -> None:
        """
        Save configuration to file.
        
        Args:
            config (Dict[str, Any]): Configuration to save
        """
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info(f"Configuration saved to {self.config_file}")
        except IOError as e:
            logger.error(f"Failed to save config file {self.config_file}: {e}")
    
    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deep merge two dictionaries.
        
        Args:
            base (Dict[str, Any]): Base dictionary
            override (Dict[str, Any]): Override dictionary
            
        Returns:
            Dict[str, Any]: Merged dictionary
        """
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.
        
        Args:
            key_path (str): Dot-separated key path (e.g., 'tools.nmap.enabled')
            default (Any): Default value if key not found
            
        Returns:
            Any: Configuration value
        """
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any, save: bool = True) -> None:
        """
        Set configuration value using dot notation.
        
        Args:
            key_path (str): Dot-separated key path
            value (Any): Value to set
            save (bool): Whether to save to file immediately
        """
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to parent key
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set the value
        config[keys[-1]] = value
        
        if save:
            self._save_config(self.config)
    
    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """
        Get configuration for a specific tool.
        
        Args:
            tool_name (str): Name of the tool
            
        Returns:
            Dict[str, Any]: Tool configuration
        """
        return self.get(f'tools.{tool_name}', {})
    
    def is_tool_enabled(self, tool_name: str) -> bool:
        """
        Check if a tool is enabled.
        
        Args:
            tool_name (str): Name of the tool
            
        Returns:
            bool: True if tool is enabled
        """
        return self.get(f'tools.{tool_name}.enabled', False)
    
    def get_timeout(self, operation: str) -> float:
        """
        Get timeout for a specific operation.
        
        Args:
            operation (str): Operation name
            
        Returns:
            float: Timeout in seconds
        """
        return float(self.get(f'timeouts.{operation}', 300))
    
    def update_from_env(self) -> None:
        """
        Update configuration from environment variables.
        Environment variables should be prefixed with VAPT_
        """
        env_mappings = {
            'VAPT_NESSUS_API_URL': 'tools.nessus.api_url',
            'VAPT_NESSUS_ACCESS_KEY': 'tools.nessus.access_key',
            'VAPT_NESSUS_SECRET_KEY': 'tools.nessus.secret_key',
            'VAPT_OPENVAS_HOST': 'tools.openvas.gvm_host',
            'VAPT_OPENVAS_PORT': 'tools.openvas.gvm_port',
            'VAPT_OPENVAS_USERNAME': 'tools.openvas.username',
            'VAPT_OPENVAS_PASSWORD': 'tools.openvas.password',
            'VAPT_LOG_LEVEL': 'logging.level',
            'VAPT_RESULTS_DIR': 'reporting.results_directory'
        }
        
        for env_var, config_path in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                # Convert port to int if needed
                if 'port' in env_var.lower():
                    try:
                        env_value = int(env_value)
                    except ValueError:
                        logger.warning(f"Invalid port value in {env_var}: {env_value}")
                        continue
                
                self.set(config_path, env_value, save=False)
                logger.info(f"Updated {config_path} from environment variable {env_var}")
    
    def validate_config(self) -> tuple[bool, list[str]]:
        """
        Validate current configuration.
        
        Returns:
            tuple[bool, list[str]]: (is_valid, error_messages)
        """
        errors = []
        
        # Validate timeouts
        for timeout_key, timeout_value in self.get('timeouts', {}).items():
            try:
                timeout_float = float(timeout_value)
                if timeout_float <= 0:
                    errors.append(f"Timeout '{timeout_key}' must be positive, got {timeout_float}")
            except (ValueError, TypeError):
                errors.append(f"Invalid timeout value for '{timeout_key}': {timeout_value}")
        
        # Validate results directory
        results_dir = self.get('reporting.results_directory')
        if results_dir:
            try:
                Path(results_dir).mkdir(parents=True, exist_ok=True)
            except OSError as e:
                errors.append(f"Cannot create results directory '{results_dir}': {e}")
        
        # Validate tool configurations
        for tool_name, tool_config in self.get('tools', {}).items():
            if tool_config.get('enabled', False):
                if tool_name == 'nessus':
                    if not all([tool_config.get('api_url'), 
                              tool_config.get('access_key'), 
                              tool_config.get('secret_key')]):
                        errors.append(f"Nessus is enabled but missing required credentials")
                
                elif tool_name == 'openvas':
                    if not all([tool_config.get('username'), 
                              tool_config.get('password')]):
                        errors.append(f"OpenVAS is enabled but missing required credentials")
        
        is_valid = len(errors) == 0
        return is_valid, errors
    
    def create_results_directory(self) -> str:
        """
        Create and return results directory path.
        
        Returns:
            str: Results directory path
        """
        results_dir = self.get('reporting.results_directory', './scan_results')
        Path(results_dir).mkdir(parents=True, exist_ok=True)
        return results_dir
    
    def get_scan_config(self, scan_type: str = 'comprehensive') -> Dict[str, Any]:
        """
        Get scan configuration for a specific scan type.
        
        Args:
            scan_type (str): Type of scan ('quick', 'comprehensive', 'custom')
            
        Returns:
            Dict[str, Any]: Scan configuration
        """
        base_config = {
            'require_confirmation': self.get('scan_behavior.require_user_confirmation', True),
            'allow_private_ips': self.get('scan_behavior.allow_private_ips', True),
            'max_retries': self.get('scan_behavior.max_retries', 3),
            'retry_delay': self.get('scan_behavior.retry_delay', 5)
        }
        
        if scan_type == 'quick':
            base_config.update({
                'nmap_timeout': self.get_timeout('nmap_basic'),
                'nmap_timing': 'T4',
                'skip_nse': True,
                'skip_nessus': True,
                'skip_openvas': True
            })
        elif scan_type == 'comprehensive':
            base_config.update({
                'nmap_timeout': self.get_timeout('nmap_comprehensive'),
                'nse_timeout': self.get_timeout('nmap_nse'),
                'nessus_timeout': self.get_timeout('nessus'),
                'openvas_timeout': self.get_timeout('openvas'),
                'nmap_timing': self.get('scan_behavior.timing_template', 'T3'),
                'include_all_tools': True
            })
        
        return base_config

# Global configuration instance
config = VAPTConfig()

# Load environment variables on import
config.update_from_env()
