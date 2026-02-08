"""
Anomaly Detection Module
AI-powered threat detection and analysis for security logs
"""

import os
import re
from typing import Dict, List, Any, Optional
from enum import Enum
from dataclasses import dataclass
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class ThreatLevel(Enum):
    """Severity levels for detected threats"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AnomalyType(Enum):
    """Types of security anomalies"""
    BRUTE_FORCE = "Brute Force Attack"
    UNAUTHORIZED_ACCESS = "Unauthorized Access Attempt"
    SUSPICIOUS_TRAFFIC = "Suspicious Network Traffic"
    DATA_EXFILTRATION = "Potential Data Exfiltration"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    MALWARE_ACTIVITY = "Malware Activity"
    SQL_INJECTION = "SQL Injection Attempt"
    XSS_ATTACK = "Cross-Site Scripting"
    DOS_ATTACK = "Denial of Service"
    UNUSUAL_PATTERN = "Unusual Activity Pattern"
    FAILED_AUTH = "Failed Authentication"
    ACCOUNT_COMPROMISE = "Potential Account Compromise"


@dataclass
class Anomaly:
    """Represents a detected security anomaly"""
    type: AnomalyType
    severity: ThreatLevel
    description: str
    recommendation: str
    confidence: float
    affected_resources: List[str]
    timestamp: Optional[str] = None
    indicators: Optional[List[str]] = None


class SecurityLogDetector:
    """
    AI-powered anomaly detector for security logs
    Uses pattern matching and AI analysis to identify threats
    """
    
    def __init__(self, ai_enabled: bool = False, openai_api_key: str = None):
        """
        Initialize the anomaly detector
        
        Args:
            ai_enabled: Enable AI-powered analysis (requires OpenAI key)
            openai_api_key: OpenAI API key (default from env)
        """
        self.ai_enabled = ai_enabled
        self.openai_api_key = openai_api_key or os.getenv('OPENAI_API_KEY')
        
        # Pattern-based detection rules
        self.patterns = self._initialize_patterns()
        
        # If AI is enabled, initialize OpenAI client
        if self.ai_enabled and self.openai_api_key:
            try:
                from openai import OpenAI
                self.ai_client = OpenAI(api_key=self.openai_api_key)
            except ImportError:
                print("Warning: OpenAI not installed. Using pattern-based detection only.")
                self.ai_enabled = False
    
    def _initialize_patterns(self) -> Dict[str, Dict[str, Any]]:
        """
        Initialize threat detection patterns
        
        Returns:
            Dictionary of regex patterns and their associated threat info
        """
        return {
            # Brute Force Attacks
            'brute_force': {
                'pattern': r'(failed.*login|failed.*authentication|brute.*force|multiple.*failed|account.*lockout)',
                'type': AnomalyType.BRUTE_FORCE,
                'severity': ThreatLevel.CRITICAL,
                'threshold': 2
            },
            
            # SQL Injection
            'sql_injection': {
                'pattern': r"(sql.*injection|union.*select|drop.*table|or.*1=1|or.*'1'='1|database.*error|sql.*syntax)",
                'type': AnomalyType.SQL_INJECTION,
                'severity': ThreatLevel.CRITICAL,
                'threshold': 1
            },
            
            # Ransomware
            'ransomware': {
                'pattern': r'(ransomware|encryption.*detected|mass.*file.*encryption|\.locked|decrypt.*txt|backup.*deleted)',
                'type': AnomalyType.MALWARE_ACTIVITY,
                'severity': ThreatLevel.CRITICAL,
                'threshold': 1
            },
            
            # Insider Threat / Data Loss
            'insider_threat': {
                'pattern': r'(data.*export|employee.*records|usb.*device|external.*drive|data.*loss|sensitive.*data|database.*backup.*downloaded)',
                'type': AnomalyType.DATA_EXFILTRATION,
                'severity': ThreatLevel.CRITICAL,
                'threshold': 1
            },
            
            # DDoS Attack
            'ddos_attack': {
                'pattern': r'(ddos.*attack|traffic.*spike|requests.*from|resource.*exhaustion|cpu.*usage.*9|memory.*usage.*9|bandwidth.*saturated|service.*downtime)',
                'type': AnomalyType.DOS_ATTACK,
                'severity': ThreatLevel.CRITICAL,
                'threshold': 1
            },
            
            # Privilege Escalation
            'privilege_escalation': {
                'pattern': r'(privilege.*escalat|sudo.*command|mimikatz|credential.*dump|lsass\.exe|registry.*modification|sam.*hive|domain.*admins|security.*event.*log.*cleared)',
                'type': AnomalyType.PRIVILEGE_ESCALATION,
                'severity': ThreatLevel.CRITICAL,
                'threshold': 1
            },
            
            # C2 Communication / Backdoor
            'c2_communication': {
                'pattern': r'(command.*control|c2.*server|\.onion|beacon.*detected|backdoor|remote.*code.*execution|trojan|dns.*tunneling)',
                'type': AnomalyType.SUSPICIOUS_TRAFFIC,
                'severity': ThreatLevel.CRITICAL,
                'threshold': 1
            },
            
            # Phishing / Credential Theft
            'phishing': {
                'pattern': r'(phishing|credential|fake.*login|password.*reuse|session.*hijacking|account.*compromise|spoofing|malicious.*link)',
                'type': AnomalyType.ACCOUNT_COMPROMISE,
                'severity': ThreatLevel.CRITICAL,
                'threshold': 1
            },
            
            # Cryptomining
            'cryptomining': {
                'pattern': r'(cryptomining|cryptocurrency|mining.*pool|xmrig|cpu.*usage.*spike|mining.*software|wallet.*address|stratum.*protocol)',
                'type': AnomalyType.MALWARE_ACTIVITY,
                'severity': ThreatLevel.HIGH,
                'threshold': 1
            },
            
            # Zero-Day / APT
            'zero_day_apt': {
                'pattern': r'(zero-day|apt|advanced.*persistent|nation-state|webshell|lateral.*movement|fileless.*malware|kerberoast|anti-forensic|persistence.*mechanism)',
                'type': AnomalyType.MALWARE_ACTIVITY,
                'severity': ThreatLevel.CRITICAL,
                'threshold': 1
            },
            
            # General Data Exfiltration
            'data_exfiltration': {
                'pattern': r'(data.*transfer|exfiltration|uploaded.*to|transferred.*to|gb.*data|sensitive.*data)',
                'type': AnomalyType.DATA_EXFILTRATION,
                'severity': ThreatLevel.CRITICAL,
                'threshold': 1
            },
            
            # Unauthorized Access
            'unauthorized_access': {
                'pattern': r'(unauthorized|access.*denied|permission.*denied|attempted.*access)',
                'type': AnomalyType.UNAUTHORIZED_ACCESS,
                'severity': ThreatLevel.HIGH,
                'threshold': 1
            },
            
            # Suspicious Process
            'suspicious_process': {
                'pattern': r'(suspicious.*process|malicious.*file|\.exe.*started|process.*inject)',
                'type': AnomalyType.MALWARE_ACTIVITY,
                'severity': ThreatLevel.HIGH,
                'threshold': 1
            }
        }
    
    def detect_anomalies(self, logs: str, compressed_context: str = None) -> List[Anomaly]:
        """
        Detect anomalies in security logs
        
        Args:
            logs: Raw security logs
            compressed_context: Compressed logs from ScaleDown (optional)
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        # Pattern-based detection
        pattern_anomalies = self._pattern_based_detection(logs)
        anomalies.extend(pattern_anomalies)
        
        # AI-powered detection (if enabled and compressed context provided)
        if self.ai_enabled and compressed_context:
            ai_anomalies = self._ai_based_detection(compressed_context)
            anomalies.extend(ai_anomalies)
        
        # Remove duplicates and sort by severity
        anomalies = self._deduplicate_anomalies(anomalies)
        anomalies = sorted(anomalies, key=lambda x: self._severity_score(x.severity), reverse=True)
        
        return anomalies
    
    def _pattern_based_detection(self, logs: str) -> List[Anomaly]:
        """
        Use regex patterns to detect known threat patterns
        
        Args:
            logs: Raw log text
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        logs_lower = logs.lower()
        
        for name, rule in self.patterns.items():
            matches = re.findall(rule['pattern'], logs_lower, re.IGNORECASE)
            
            if len(matches) >= rule['threshold']:
                # Extract affected IPs and users
                affected = self._extract_indicators(logs, matches)
                
                anomaly = Anomaly(
                    type=rule['type'],
                    severity=rule['severity'],
                    description=self._generate_description(rule['type'], len(matches)),
                    recommendation=self._generate_recommendation(rule['type']),
                    confidence=min(0.95, 0.7 + (len(matches) * 0.05)),
                    affected_resources=affected,
                    indicators=matches[:5] if matches else None
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def _ai_based_detection(self, compressed_logs: str) -> List[Anomaly]:
        """
        Use AI (GPT) to analyze compressed logs for anomalies
        
        Args:
            compressed_logs: Compressed log context
            
        Returns:
            List of AI-detected anomalies
        """
        try:
            response = self.ai_client.chat.completions.create(
                model=os.getenv('TARGET_MODEL', 'gpt-4o-mini'),
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert analyzing security logs. "
                                   "Identify threats, anomalies, and security issues. "
                                   "Respond in JSON format with: type, severity, description, recommendation."
                    },
                    {
                        "role": "user",
                        "content": f"Analyze these security logs and identify all threats and anomalies:\n\n{compressed_logs}"
                    }
                ],
                temperature=0.3,
                max_tokens=500
            )
            
            # Parse AI response and create anomalies
            ai_analysis = response.choices[0].message.content
            return self._parse_ai_response(ai_analysis)
            
        except Exception as e:
            print(f"AI detection error: {e}")
            return []
    
    def _parse_ai_response(self, ai_text: str) -> List[Anomaly]:
        """Parse AI response into Anomaly objects"""
        # Simplified parsing - in production, use structured output
        anomalies = []
        
        # Try to extract key information
        if "critical" in ai_text.lower():
            anomalies.append(Anomaly(
                type=AnomalyType.UNUSUAL_PATTERN,
                severity=ThreatLevel.HIGH,
                description="AI detected unusual patterns requiring investigation",
                recommendation="Review detailed AI analysis and investigate flagged activities",
                confidence=0.85,
                affected_resources=[]
            ))
        
        return anomalies
    
    def _extract_indicators(self, logs: str, matches: List) -> List[str]:
        """Extract IPs, usernames, and other indicators from logs"""
        indicators = []
        
        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, logs)
        indicators.extend(set(ips[:5]))  # Limit to 5 unique IPs
        
        # Extract usernames
        user_pattern = r'(?:user|username|account)[\s:]+(\w+)'
        users = re.findall(user_pattern, logs, re.IGNORECASE)
        indicators.extend(set(users[:5]))
        
        return indicators[:10]  # Max 10 indicators
    
    def _generate_description(self, anomaly_type: AnomalyType, count: int) -> str:
        """Generate human-readable description"""
        descriptions = {
            AnomalyType.BRUTE_FORCE: f"Multiple failed login attempts detected ({count} occurrences)",
            AnomalyType.UNAUTHORIZED_ACCESS: f"Unauthorized access attempts identified ({count} occurrences)",
            AnomalyType.SUSPICIOUS_TRAFFIC: "Unusual network traffic patterns detected",
            AnomalyType.DATA_EXFILTRATION: "Potential data exfiltration activity identified",
            AnomalyType.PRIVILEGE_ESCALATION: "Suspicious privilege escalation attempt detected",
            AnomalyType.SQL_INJECTION: "SQL injection attack attempt detected",
            AnomalyType.MALWARE_ACTIVITY: "Potential malware activity identified",
            AnomalyType.FAILED_AUTH: "Account lockout due to failed authentication"
        }
        return descriptions.get(anomaly_type, f"Security anomaly detected: {anomaly_type.value}")
    
    def _generate_recommendation(self, anomaly_type: AnomalyType) -> str:
        """Generate security recommendations"""
        recommendations = {
            AnomalyType.BRUTE_FORCE: "Immediately block source IP, enforce account lockout policy, and review authentication logs",
            AnomalyType.UNAUTHORIZED_ACCESS: "Review access controls, audit user permissions, and investigate unauthorized attempts",
            AnomalyType.SUSPICIOUS_TRAFFIC: "Investigate destination, check firewall rules, and monitor for data leakage",
            AnomalyType.DATA_EXFILTRATION: "Isolate affected systems, review data access logs, and conduct forensic analysis",
            AnomalyType.PRIVILEGE_ESCALATION: "Audit privilege assignments, review sudo logs, and check for compromised credentials",
            AnomalyType.SQL_INJECTION: "Patch vulnerable endpoints, implement input validation, and review database access logs",
            AnomalyType.MALWARE_ACTIVITY: "Quarantine affected systems, run antivirus scans, and check for persistence mechanisms",
            AnomalyType.FAILED_AUTH: "Verify account ownership, reset credentials if compromised, and review recent activity"
        }
        return recommendations.get(anomaly_type, "Investigate immediately and follow incident response procedures")
    
    def _deduplicate_anomalies(self, anomalies: List[Anomaly]) -> List[Anomaly]:
        """Remove duplicate anomalies based on type and severity"""
        seen = set()
        unique = []
        
        for anomaly in anomalies:
            key = (anomaly.type, anomaly.severity)
            if key not in seen:
                seen.add(key)
                unique.append(anomaly)
        
        return unique
    
    def _severity_score(self, severity: ThreatLevel) -> int:
        """Convert severity to numeric score for sorting"""
        scores = {
            ThreatLevel.CRITICAL: 5,
            ThreatLevel.HIGH: 4,
            ThreatLevel.MEDIUM: 3,
            ThreatLevel.LOW: 2,
            ThreatLevel.INFO: 1
        }
        return scores.get(severity, 0)
    
    def calculate_threat_level(self, anomalies: List[Anomaly]) -> ThreatLevel:
        """
        Calculate overall threat level based on detected anomalies
        
        Args:
            anomalies: List of detected anomalies
            
        Returns:
            Overall threat level
        """
        if not anomalies:
            return ThreatLevel.INFO
        
        # Check for critical threats
        if any(a.severity == ThreatLevel.CRITICAL for a in anomalies):
            return ThreatLevel.CRITICAL
        
        # Count high severity threats
        high_count = sum(1 for a in anomalies if a.severity == ThreatLevel.HIGH)
        if high_count >= 2:
            return ThreatLevel.CRITICAL
        elif high_count >= 1:
            return ThreatLevel.HIGH
        
        # Count medium severity
        medium_count = sum(1 for a in anomalies if a.severity == ThreatLevel.MEDIUM)
        if medium_count >= 3:
            return ThreatLevel.HIGH
        elif medium_count >= 1:
            return ThreatLevel.MEDIUM
        
        return ThreatLevel.LOW


# Example usage
if __name__ == "__main__":
    # Sample security logs
    sample_logs = """
    2026-02-01 10:23:45 INFO User admin logged in from 192.168.1.100
    2026-02-01 10:24:12 WARN Failed login attempt for user root from 203.0.113.45
    2026-02-01 10:24:15 WARN Failed login attempt for user root from 203.0.113.45
    2026-02-01 10:24:18 WARN Failed login attempt for user root from 203.0.113.45
    2026-02-01 10:24:22 ERROR Failed login attempt for user root from 203.0.113.45 - Account locked
    2026-02-01 10:25:01 INFO Database backup completed successfully
    2026-02-01 10:26:33 CRITICAL Unusual outbound traffic detected to 198.51.100.77:4444
    2026-02-01 10:27:15 WARN Suspicious data transfer of 500MB to external IP
    """
    
    # Initialize detector (without AI for testing)
    detector = SecurityLogDetector(ai_enabled=False)
    
    # Detect anomalies
    print("Analyzing security logs...\n")
    anomalies = detector.detect_anomalies(sample_logs)
    
    # Display results
    print(f"=== DETECTED ANOMALIES: {len(anomalies)} ===\n")
    
    for i, anomaly in enumerate(anomalies, 1):
        print(f"[{i}] {anomaly.type.value}")
        print(f"    Severity: {anomaly.severity.value}")
        print(f"    Confidence: {anomaly.confidence:.0%}")
        print(f"    Description: {anomaly.description}")
        print(f"    Recommendation: {anomaly.recommendation}")
        if anomaly.affected_resources:
            print(f"    Affected: {', '.join(anomaly.affected_resources[:3])}")
        print()
    
    # Calculate overall threat level
    overall_threat = detector.calculate_threat_level(anomalies)
    print(f"=== OVERALL THREAT LEVEL: {overall_threat.value} ===")
