"""
Validation utilities for VAPT agents project.
Provides input validation, error handling, and utility functions.
"""

import re
import socket
import ipaddress
import logging
from typing import Union, Tuple, Optional
from urllib.parse import urlparse

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

class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass

class NetworkError(Exception):
    """Custom exception for network-related errors."""
    pass

class ScanTimeoutError(Exception):
    """Custom exception for scan timeout errors."""
    pass

class TargetValidator:
    """Validates and sanitizes scan targets."""
    
    # Private IP ranges (RFC 1918)
    PRIVATE_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),  # Loopback
    ]
    
    # Forbidden target patterns
    FORBIDDEN_PATTERNS = [
        r'.*\.gov$',           # Government domains
        r'.*\.mil$',           # Military domains
        r'.*\.edu$',           # Educational institutions (be cautious)
        r'.*bank.*',           # Banking related
        r'.*hospital.*',       # Healthcare related
    ]
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """
        Validate if string is a valid IP address.
        
        Args:
            ip (str): IP address string to validate
            
        Returns:
            bool: True if valid IP address, False otherwise
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_hostname(hostname: str) -> bool:
        """
        Validate if string is a valid hostname.
        
        Args:
            hostname (str): Hostname string to validate
            
        Returns:
            bool: True if valid hostname, False otherwise
        """
        if len(hostname) > 253:
            return False
        
        # Remove trailing dot if present
        if hostname.endswith('.'):
            hostname = hostname[:-1]
        
        # Check each label
        labels = hostname.split('.')
        for label in labels:
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$', label):
                return False
        
        return True
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """
        Validate if string is a valid URL.
        
        Args:
            url (str): URL string to validate
            
        Returns:
            bool: True if valid URL, False otherwise
        """
        try:
            parsed = urlparse(url)
            return all([parsed.scheme, parsed.netloc])
        except Exception:
            return False
    
    @classmethod
    def is_private_ip(cls, ip: str) -> bool:
        """
        Check if IP address is in private range.
        
        Args:
            ip (str): IP address to check
            
        Returns:
            bool: True if private IP, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in network for network in cls.PRIVATE_RANGES)
        except ValueError:
            return False
    
    @classmethod
    def is_forbidden_target(cls, target: str) -> bool:
        """
        Check if target matches forbidden patterns.
        
        Args:
            target (str): Target to check
            
        Returns:
            bool: True if forbidden, False otherwise
        """
        target_lower = target.lower()
        return any(re.match(pattern, target_lower) for pattern in cls.FORBIDDEN_PATTERNS)
    
    @classmethod
    def validate_target(cls, target: str, allow_private: bool = True, 
                       require_authorization: bool = True) -> Tuple[str, str]:
        """
        Comprehensive target validation.
        
        Args:
            target (str): Target to validate (IP, hostname, or URL)
            allow_private (bool): Whether to allow private IP ranges
            require_authorization (bool): Whether to check for forbidden patterns
            
        Returns:
            Tuple[str, str]: (validated_target, target_type)
            
        Raises:
            ValidationError: If target is invalid or forbidden
        """
        if not target or not isinstance(target, str):
            raise ValidationError("Target must be a non-empty string")
        
        target = target.strip()
        
        if not target:
            raise ValidationError("Target cannot be empty or whitespace only")
        
        # Check for forbidden patterns first
        if require_authorization and cls.is_forbidden_target(target):
            raise ValidationError(f"Target '{target}' matches forbidden pattern. "
                                "Ensure you have proper authorization.")
        
        # Determine target type and validate
        if cls.is_valid_ip(target):
            if not allow_private and cls.is_private_ip(target):
                logger.warning(f"Private IP address detected: {target}")
            return target, "ip"
        
        elif cls.is_valid_url(target):
            parsed = urlparse(target)
            hostname = parsed.hostname
            if hostname:
                if cls.is_valid_ip(hostname):
                    if not allow_private and cls.is_private_ip(hostname):
                        logger.warning(f"Private IP in URL detected: {hostname}")
                elif not cls.is_valid_hostname(hostname):
                    raise ValidationError(f"Invalid hostname in URL: {hostname}")
            return target, "url"
        
        elif cls.is_valid_hostname(target):
            return target, "hostname"
        
        else:
            raise ValidationError(f"Invalid target format: '{target}'. "
                                "Must be a valid IP address, hostname, or URL.")
    
    @staticmethod
    def resolve_hostname(hostname: str, timeout: int = 5) -> Optional[str]:
        """
        Resolve hostname to IP address.
        
        Args:
            hostname (str): Hostname to resolve
            timeout (int): Timeout in seconds
            
        Returns:
            Optional[str]: Resolved IP address or None if resolution fails
            
        Raises:
            NetworkError: If DNS resolution fails
        """
        try:
            socket.setdefaulttimeout(timeout)
            ip = socket.gethostbyname(hostname)
            logger.info(f"Resolved {hostname} to {ip}")
            return ip
        except socket.gaierror as e:
            raise NetworkError(f"DNS resolution failed for {hostname}: {e}")
        except socket.timeout:
            raise NetworkError(f"DNS resolution timeout for {hostname}")
        except Exception as e:
            raise NetworkError(f"Unexpected error resolving {hostname}: {e}")
        finally:
            socket.setdefaulttimeout(None)

class ConfigValidator:
    """Validates configuration parameters."""
    
    @staticmethod
    def validate_timeout(timeout: Union[int, float]) -> float:
        """
        Validate timeout value.
        
        Args:
            timeout: Timeout value to validate
            
        Returns:
            float: Validated timeout value
            
        Raises:
            ValidationError: If timeout is invalid
        """
        try:
            timeout_float = float(timeout)
            if timeout_float <= 0:
                raise ValidationError("Timeout must be positive")
            if timeout_float > 3600:  # 1 hour max
                logger.warning(f"Very long timeout specified: {timeout_float}s")
            return timeout_float
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid timeout value: {timeout}")
    
    @staticmethod
    def validate_port(port: Union[int, str]) -> int:
        """
        Validate port number.
        
        Args:
            port: Port number to validate
            
        Returns:
            int: Validated port number
            
        Raises:
            ValidationError: If port is invalid
        """
        try:
            port_int = int(port)
            if not (1 <= port_int <= 65535):
                raise ValidationError(f"Port must be between 1 and 65535, got {port_int}")
            return port_int
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid port value: {port}")
    
    @staticmethod
    def validate_port_range(port_range: str) -> Tuple[int, int]:
        """
        Validate port range string.
        
        Args:
            port_range (str): Port range in format "start-end" or single port
            
        Returns:
            Tuple[int, int]: (start_port, end_port)
            
        Raises:
            ValidationError: If port range is invalid
        """
        if '-' in port_range:
            try:
                start_str, end_str = port_range.split('-', 1)
                start_port = ConfigValidator.validate_port(start_str.strip())
                end_port = ConfigValidator.validate_port(end_str.strip())
                
                if start_port > end_port:
                    raise ValidationError(f"Invalid port range: start port {start_port} > end port {end_port}")
                
                return start_port, end_port
            except ValueError:
                raise ValidationError(f"Invalid port range format: {port_range}")
        else:
            port = ConfigValidator.validate_port(port_range)
            return port, port

def log_scan_attempt(target: str, tool: str, user_id: Optional[str] = None) -> None:
    """
    Log scan attempt for audit purposes.
    
    Args:
        target (str): Target being scanned
        tool (str): Tool being used
        user_id (str, optional): User identifier
    """
    log_entry = f"SCAN_ATTEMPT - Target: {target}, Tool: {tool}"
    if user_id:
        log_entry += f", User: {user_id}"
    
    logger.info(log_entry)

def get_user_confirmation(target: str, target_type: str) -> bool:
    """
    Get user confirmation for scanning target.
    
    Args:
        target (str): Target to scan
        target_type (str): Type of target (ip, hostname, url)
        
    Returns:
        bool: True if user confirms, False otherwise
    """
    print(f"\n⚠️  AUTHORIZATION CONFIRMATION ⚠️")
    print(f"Target: {target} (Type: {target_type})")
    print(f"Are you authorized to scan this target?")
    print(f"Unauthorized scanning may be illegal and unethical.")
    
    while True:
        response = input("Do you have explicit permission to scan this target? (yes/no): ").strip().lower()
        if response in ['yes', 'y']:
            logger.info(f"User confirmed authorization for target: {target}")
            return True
        elif response in ['no', 'n']:
            logger.warning(f"User denied authorization for target: {target}")
            return False
        else:
            print("Please enter 'yes' or 'no'")
