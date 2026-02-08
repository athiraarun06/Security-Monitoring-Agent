"""
Threat Severity Scoring System
Calculates risk scores for threats based on multiple factors
"""

from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum
import math


class RiskLevel(Enum):
    """Risk level categories"""
    CRITICAL = "CRITICAL"  # 80-100
    HIGH = "HIGH"          # 60-79
    MEDIUM = "MEDIUM"      # 40-59
    LOW = "LOW"            # 20-39
    MINIMAL = "MINIMAL"    # 0-19


@dataclass
class ThreatScore:
    """Calculated threat score with breakdown"""
    threat_type: str
    base_score: float
    frequency_multiplier: float
    target_sensitivity: float
    sophistication_score: float
    final_score: float
    risk_level: RiskLevel
    factors: Dict[str, Any]


class ThreatScoringEngine:
    """
    Threat severity scoring system
    Calculates risk scores based on multiple factors
    """
    
    # Base severity scores for different threat types
    BASE_SCORES = {
        'Brute Force Attack': 65,
        'SQL Injection Attempt': 85,
        'Cross-Site Scripting': 70,
        'Potential Data Exfiltration': 95,
        'Suspicious Network Traffic': 50,
        'Privilege Escalation': 90,
        'Malware Activity': 95,
        'Unauthorized Access Attempt': 75,
        'Failed Authentication': 40,
        'Denial of Service': 80,
        'Unusual Activity Pattern': 45,
        'Potential Account Compromise': 85
    }
    
    # Sensitivity levels for different targets
    TARGET_SENSITIVITY = {
        'database': 1.5,
        'admin': 1.4,
        'root': 1.5,
        'config': 1.3,
        'password': 1.4,
        'user': 1.1,
        'api': 1.2,
        'system': 1.3
    }
    
    def __init__(self):
        """Initialize scoring engine"""
        self.threat_history = []
    
    def calculate_threat_score(
        self,
        threat_type: str,
        threat_count: int = 1,
        affected_resources: List[str] = None,
        confidence: float = 1.0,
        time_window_minutes: int = 60
    ) -> ThreatScore:
        """
        Calculate comprehensive threat score
        
        Args:
            threat_type: Type of threat detected
            threat_count: Number of occurrences
            affected_resources: List of affected systems/users
            confidence: Detection confidence (0-1)
            time_window_minutes: Time window for frequency calculation
            
        Returns:
            ThreatScore object with detailed breakdown
        """
        if affected_resources is None:
            affected_resources = []
        
        # 1. Base score from threat type
        base_score = self.BASE_SCORES.get(threat_type, 50)
        
        # 2. Frequency multiplier (more frequent = higher score)
        frequency_multiplier = self._calculate_frequency_multiplier(
            threat_count, time_window_minutes
        )
        
        # 3. Target sensitivity (admin, database, etc.)
        target_sensitivity = self._calculate_target_sensitivity(
            affected_resources
        )
        
        # 4. Sophistication score
        sophistication_score = self._calculate_sophistication(
            threat_type, threat_count
        )
        
        # 5. Calculate final score
        final_score = (
            base_score * 
            frequency_multiplier * 
            target_sensitivity * 
            confidence * 
            sophistication_score
        )
        
        # Cap at 100
        final_score = min(final_score, 100.0)
        
        # Determine risk level
        risk_level = self._get_risk_level(final_score)
        
        # Build factors breakdown
        factors = {
            'base_score': base_score,
            'threat_count': threat_count,
            'frequency_multiplier': round(frequency_multiplier, 2),
            'target_sensitivity': round(target_sensitivity, 2),
            'sophistication': round(sophistication_score, 2),
            'confidence': confidence,
            'time_window_minutes': time_window_minutes
        }
        
        return ThreatScore(
            threat_type=threat_type,
            base_score=base_score,
            frequency_multiplier=frequency_multiplier,
            target_sensitivity=target_sensitivity,
            sophistication_score=sophistication_score,
            final_score=round(final_score, 1),
            risk_level=risk_level,
            factors=factors
        )
    
    def _calculate_frequency_multiplier(
        self,
        count: int,
        time_window_minutes: int
    ) -> float:
        """
        Calculate multiplier based on attack frequency
        More frequent attacks = higher score
        """
        if count <= 1:
            return 1.0
        
        # Logarithmic scaling
        frequency_rate = count / (time_window_minutes / 60)  # per hour
        
        if frequency_rate >= 10:
            return 1.5
        elif frequency_rate >= 5:
            return 1.3
        elif frequency_rate >= 2:
            return 1.15
        else:
            return 1.05
    
    def _calculate_target_sensitivity(
        self,
        affected_resources: List[str]
    ) -> float:
        """
        Calculate sensitivity multiplier based on affected targets
        Attacks on sensitive systems get higher scores
        """
        if not affected_resources:
            return 1.0
        
        max_sensitivity = 1.0
        
        for resource in affected_resources:
            resource_lower = resource.lower()
            for sensitive_term, multiplier in self.TARGET_SENSITIVITY.items():
                if sensitive_term in resource_lower:
                    max_sensitivity = max(max_sensitivity, multiplier)
        
        return max_sensitivity
    
    def _calculate_sophistication(
        self,
        threat_type: str,
        count: int
    ) -> float:
        """
        Estimate attack sophistication
        """
        # More sophisticated attacks
        sophisticated_attacks = [
            'SQL Injection',
            'Privilege Escalation',
            'Data Exfiltration',
            'Malware'
        ]
        
        for sophisticated in sophisticated_attacks:
            if sophisticated in threat_type:
                return 1.2
        
        # Coordinated attacks (multiple occurrences quickly)
        if count >= 5:
            return 1.15
        
        return 1.0
    
    def _get_risk_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level"""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    def calculate_overall_security_score(
        self,
        threat_scores: List[ThreatScore]
    ) -> Dict[str, Any]:
        """
        Calculate overall security health score
        
        Args:
            threat_scores: List of individual threat scores
            
        Returns:
            Dictionary with overall security assessment
        """
        if not threat_scores:
            return {
                'overall_score': 100,
                'health_status': 'EXCELLENT',
                'risk_distribution': {},
                'highest_risk': None,
                'total_threats': 0
            }
        
        # Calculate weighted average
        total_weight = sum(score.final_score for score in threat_scores)
        avg_threat_score = total_weight / len(threat_scores)
        
        # Overall security score (inverse of threat score)
        overall_score = max(0, 100 - avg_threat_score)
        
        # Risk distribution
        risk_distribution = {}
        for score in threat_scores:
            level = score.risk_level.value
            risk_distribution[level] = risk_distribution.get(level, 0) + 1
        
        # Find highest risk threat
        highest_risk = max(threat_scores, key=lambda x: x.final_score)
        
        # Determine health status
        if overall_score >= 90:
            health_status = 'EXCELLENT'
        elif overall_score >= 70:
            health_status = 'GOOD'
        elif overall_score >= 50:
            health_status = 'FAIR'
        elif overall_score >= 30:
            health_status = 'POOR'
        else:
            health_status = 'CRITICAL'
        
        return {
            'overall_score': round(overall_score, 1),
            'health_status': health_status,
            'risk_distribution': risk_distribution,
            'highest_risk': {
                'type': highest_risk.threat_type,
                'score': highest_risk.final_score,
                'level': highest_risk.risk_level.value
            },
            'total_threats': len(threat_scores),
            'average_threat_score': round(avg_threat_score, 1)
        }
    
    def get_recommendations(self, threat_score: ThreatScore) -> List[str]:
        """
        Get specific recommendations based on threat score
        
        Args:
            threat_score: Calculated threat score
            
        Returns:
            List of actionable recommendations
        """
        recommendations = []
        
        if threat_score.risk_level == RiskLevel.CRITICAL:
            recommendations.append("🚨 IMMEDIATE ACTION REQUIRED")
            recommendations.append("Isolate affected systems immediately")
            recommendations.append("Initiate incident response procedures")
        
        if threat_score.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            recommendations.append("Review and block source IPs")
            recommendations.append("Enable additional monitoring")
            recommendations.append("Notify security team")
        
        # Frequency-based recommendations
        if threat_score.factors.get('frequency_multiplier', 1.0) > 1.2:
            recommendations.append("Implement rate limiting")
            recommendations.append("Configure automated blocking rules")
        
        # Target-based recommendations
        if threat_score.factors.get('target_sensitivity', 1.0) > 1.3:
            recommendations.append("Increase access controls for sensitive resources")
            recommendations.append("Enable MFA if not already active")
        
        # Threat-specific recommendations
        if 'Brute Force' in threat_score.threat_type:
            recommendations.append("Implement account lockout policies")
            recommendations.append("Review password policies")
        
        if 'SQL Injection' in threat_score.threat_type:
            recommendations.append("Update input validation")
            recommendations.append("Use parameterized queries")
        
        if 'Data Exfiltration' in threat_score.threat_type:
            recommendations.append("Review data loss prevention policies")
            recommendations.append("Audit recent data access logs")
        
        return recommendations
