"""
AI-Powered Log Insights
Generate natural language summaries and recommendations using AI
"""

import os
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv

load_dotenv()


class AIInsightsEngine:
    """
    AI-powered insights generator
    Uses OpenAI to create executive summaries and recommendations
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-3.5-turbo"):
        """
        Initialize AI insights engine
        
        Args:
            api_key: OpenAI API key (defaults to env var)
            model: OpenAI model to use
        """
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.model = model
        self.enabled = bool(self.api_key)
        
        if self.enabled:
            try:
                from openai import OpenAI
                self.client = OpenAI(api_key=self.api_key)
            except ImportError:
                print("Warning: OpenAI library not installed. AI insights disabled.")
                self.enabled = False
    
    def generate_executive_summary(
        self,
        threats: List[Dict],
        overall_stats: Dict,
        ip_data: Optional[Dict] = None
    ) -> str:
        """
        Generate an executive summary of the security analysis
        
        Args:
            threats: List of detected threats
            overall_stats: Overall security statistics
            ip_data: Optional IP intelligence data
            
        Returns:
            Natural language summary
        """
        if not self.enabled:
            return self._generate_basic_summary(threats, overall_stats)
        
        # Prepare context for AI
        context = self._prepare_context(threats, overall_stats, ip_data)
        
        prompt = f"""You are a cybersecurity analyst. Provide a brief executive summary of this security analysis.
Focus on the most critical findings and overall security posture.
Keep it under 150 words.

Analysis Data:
{context}

Provide a clear, actionable executive summary."""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert providing executive summaries."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=200,
                temperature=0.7
            )
            
            return response.choices[0].message.content.strip()
        
        except Exception as e:
            print(f"AI summary generation failed: {e}")
            return self._generate_basic_summary(threats, overall_stats)
    
    def generate_incident_response_plan(
        self,
        threat: Dict,
        severity: str
    ) -> List[str]:
        """
        Generate incident response recommendations for a specific threat
        
        Args:
            threat: Threat details
            severity: Threat severity level
            
        Returns:
            List of actionable steps
        """
        if not self.enabled:
            return self._generate_basic_recommendations(threat, severity)
        
        prompt = f"""You are a cybersecurity incident responder. Provide 4-6 specific, actionable steps to respond to this threat.

Threat Type: {threat.get('type', 'Unknown')}
Severity: {severity}
Description: {threat.get('description', 'N/A')}
Affected Resources: {', '.join(threat.get('affected', [])[:3])}

Provide numbered steps (1-6) for immediate response. Be specific and technical."""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity incident response expert."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=300,
                temperature=0.7
            )
            
            # Parse numbered steps
            content = response.choices[0].message.content.strip()
            steps = [line.strip() for line in content.split('\n') if line.strip() and any(c.isdigit() for c in line[:3])]
            
            return steps if steps else self._generate_basic_recommendations(threat, severity)
        
        except Exception as e:
            print(f"AI recommendations generation failed: {e}")
            return self._generate_basic_recommendations(threat, severity)
    
    def analyze_attack_pattern(
        self,
        threats: List[Dict]
    ) -> Dict[str, Any]:
        """
        Analyze if threats are part of a coordinated attack
        
        Args:
            threats: List of detected threats
            
        Returns:
            Analysis of attack patterns
        """
        if not self.enabled or len(threats) < 2:
            return {
                'is_coordinated': False,
                'confidence': 0,
                'analysis': 'Insufficient data or AI unavailable'
            }
        
        # Prepare threat summary
        threat_summary = "\n".join([
            f"- {t.get('type')}: {t.get('description')[:100]}"
            for t in threats[:10]
        ])
        
        prompt = f"""Analyze if these security threats are part of a coordinated attack or attack chain.

Threats detected:
{threat_summary}

Answer in JSON format:
{{
  "is_coordinated": true/false,
  "confidence": 0-100,
  "attack_chain": "brief description if coordinated",
  "attack_goal": "likely objective"
}}"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a threat intelligence analyst. Respond only in JSON."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=200,
                temperature=0.5
            )
            
            import json
            result = json.loads(response.choices[0].message.content.strip())
            return result
        
        except Exception as e:
            print(f"Attack pattern analysis failed: {e}")
            return {
                'is_coordinated': False,
                'confidence': 0,
                'analysis': f'Analysis failed: {str(e)}'
            }
    
    def _prepare_context(
        self,
        threats: List[Dict],
        overall_stats: Dict,
        ip_data: Optional[Dict]
    ) -> str:
        """Prepare context string for AI"""
        context_parts = [
            f"Total Threats: {len(threats)}",
            f"Security Score: {overall_stats.get('overall_score', 'N/A')}/100",
            f"Health Status: {overall_stats.get('health_status', 'N/A')}"
        ]
        
        # Add threat breakdown
        if threats:
            threat_types = {}
            for threat in threats:
                t_type = threat.get('type', 'Unknown')
                threat_types[t_type] = threat_types.get(t_type, 0) + 1
            
            context_parts.append("Threat Types:")
            for t_type, count in list(threat_types.items())[:5]:
                context_parts.append(f"  - {t_type}: {count}")
        
        # Add IP data if available
        if ip_data:
            threat_ips = ip_data.get('threat_ips', [])
            if threat_ips:
                context_parts.append(f"Malicious IPs: {len(threat_ips)}")
                countries = ip_data.get('countries', {})
                if countries:
                    top_country = max(countries.items(), key=lambda x: x[1])
                    context_parts.append(f"Primary Attack Source: {top_country[0]}")
        
        return "\n".join(context_parts)
    
    def _generate_basic_summary(
        self,
        threats: List[Dict],
        overall_stats: Dict
    ) -> str:
        """Generate a basic summary without AI"""
        threat_count = len(threats)
        score = overall_stats.get('overall_score', 0)
        status = overall_stats.get('health_status', 'UNKNOWN')
        
        if threat_count == 0:
            return f"[OK] Security Status: {status} ({score}/100). No threats detected in this analysis."
        
        # Count threat types
        threat_types = {}
        for threat in threats:
            t_type = threat.get('type', 'Unknown')
            threat_types[t_type] = threat_types.get(t_type, 0) + 1
        
        # Find most common
        most_common = max(threat_types.items(), key=lambda x: x[1]) if threat_types else ('Unknown', 0)
        
        summary = f"[ANALYSIS] Security Status: {status} ({score}/100)\n\n"
        summary += f"Detected {threat_count} security threat(s). "
        summary += f"Most common: {most_common[0]} ({most_common[1]} occurrence(s)). "
        
        if score < 50:
            summary += "[WARNING] Immediate attention recommended."
        elif score < 70:
            summary += "Review and address identified threats."
        else:
            summary += "Monitor and maintain current security posture."
        
        return summary
    
    def _generate_basic_recommendations(
        self,
        threat: Dict,
        severity: str
    ) -> List[str]:
        """Generate basic recommendations without AI"""
        recommendations = []
        threat_type = threat.get('type', '')
        
        # Generic high-priority actions
        if severity in ['CRITICAL', 'HIGH']:
            recommendations.append("1. Isolate affected systems immediately")
            recommendations.append("2. Review and block source IPs")
            recommendations.append("3. Notify security team and management")
        
        # Threat-specific recommendations
        if 'Brute Force' in threat_type:
            recommendations.append("4. Implement account lockout policies")
            recommendations.append("5. Enable multi-factor authentication")
            recommendations.append("6. Review password policies")
        elif 'SQL Injection' in threat_type:
            recommendations.append("4. Patch application vulnerabilities")
            recommendations.append("5. Implement input validation")
            recommendations.append("6. Use parameterized queries")
        elif 'Data Exfiltration' in threat_type:
            recommendations.append("4. Audit recent data access logs")
            recommendations.append("5. Review data loss prevention policies")
            recommendations.append("6. Investigate data transfer destinations")
        else:
            recommendations.append("4. Review security logs for additional activity")
            recommendations.append("5. Update detection rules")
            recommendations.append("6. Conduct security audit of affected systems")
        
        return recommendations
