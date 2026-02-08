"""
PDF Report Generator
Creates professional PDF security reports
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("Warning: reportlab not installed. PDF generation disabled.")


class PDFReportGenerator:
    """
    Professional PDF report generator for security analysis
    """
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize PDF generator
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.enabled = REPORTLAB_AVAILABLE
    
    def generate_report(
        self,
        threats: List[Dict],
        overall_stats: Dict,
        compression_stats: Dict,
        ip_data: Optional[Dict] = None,
        executive_summary: Optional[str] = None,
        filename: Optional[str] = None
    ) -> Optional[str]:
        """
        Generate comprehensive PDF security report
        
        Args:
            threats: List of detected threats
            overall_stats: Overall security statistics
            compression_stats: Compression metrics
            ip_data: Optional IP intelligence data
            executive_summary: Optional AI-generated summary
            filename: Optional custom filename
            
        Returns:
            Path to generated PDF file, or None if failed
        """
        if not self.enabled:
            print("PDF generation unavailable: reportlab not installed")
            return None
        
        # Generate filename
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"security_report_{timestamp}.pdf"
        
        filepath = self.output_dir / filename
        
        try:
            # Create PDF document
            doc = SimpleDocTemplate(
                str(filepath),
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build document content
            story = []
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#2E1A47'),
                spaceAfter=30,
                alignment=TA_CENTER
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#7C3AED'),
                spaceAfter=12,
                spaceBefore=12
            )
            
            # Title Page
            story.append(Spacer(1, 2*inch))
            story.append(Paragraph("Security Analysis Report", title_style))
            story.append(Spacer(1, 0.3*inch))
            
            # Date and time
            report_date = datetime.now().strftime('%B %d, %Y %I:%M %p')
            story.append(Paragraph(f"<para align=center><i>Generated: {report_date}</i></para>", styles['Normal']))
            story.append(PageBreak())
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", heading_style))
            if executive_summary:
                story.append(Paragraph(executive_summary.replace('\n', '<br/>'), styles['Normal']))
            else:
                story.append(Paragraph(
                    f"This report analyzes {len(threats)} security threat(s) detected during log analysis. "
                    f"Overall security score: {overall_stats.get('overall_score', 0)}/100 "
                    f"({overall_stats.get('health_status', 'UNKNOWN')}).",
                    styles['Normal']
                ))
            story.append(Spacer(1, 0.3*inch))
            
            # Overall Statistics
            story.append(Paragraph("Security Overview", heading_style))
            stats_data = [
                ['Metric', 'Value'],
                ['Total Threats Detected', str(len(threats))],
                ['Security Score', f"{overall_stats.get('overall_score', 0)}/100"],
                ['Health Status', overall_stats.get('health_status', 'UNKNOWN')],
                ['Logs Analyzed', str(compression_stats.get('original_tokens', 'N/A'))],
                ['Compression Ratio', f"{compression_stats.get('compression_ratio', 0):.1%}"],
                ['Cost Savings', f"${compression_stats.get('estimated_cost_saved', 0):.2f}"]
            ]
            
            stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#7C3AED')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(stats_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Threat Details
            if threats:
                story.append(Paragraph("Detected Threats", heading_style))
                
                for i, threat in enumerate(threats, 1):
                    # Threat header
                    threat_title = f"{i}. {threat.get('type', 'Unknown Threat')}"
                    story.append(Paragraph(threat_title, styles['Heading3']))
                    
                    # Threat details table
                    threat_data = [
                        ['Severity', threat.get('severity', 'UNKNOWN')],
                        ['Risk Score', f"{threat.get('risk_score', 0):.1f}/100"],
                        ['Confidence', f"{threat.get('confidence', 0):.0%}"],
                        ['Description', threat.get('description', 'N/A')[:100]],
                        ['Affected Resources', ', '.join(threat.get('affected', [])[:3])]
                    ]
                    
                    if threat.get('source_ip'):
                        threat_data.append(['Source IP', threat['source_ip']])
                    if threat.get('country'):
                        threat_data.append(['Location', threat['country']])
                    
                    threat_table = Table(threat_data, colWidths=[1.5*inch, 4*inch])
                    threat_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F3E8FF')),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP')
                    ]))
                    story.append(threat_table)
                    story.append(Spacer(1, 0.2*inch))
            
            # IP Intelligence
            if ip_data and ip_data.get('threat_ips'):
                story.append(PageBreak())
                story.append(Paragraph("IP Threat Intelligence", heading_style))
                
                ip_summary = f"Analyzed {ip_data.get('total_ips', 0)} unique IP addresses. "
                ip_summary += f"Found {len(ip_data.get('threat_ips', []))} malicious IPs."
                story.append(Paragraph(ip_summary, styles['Normal']))
                story.append(Spacer(1, 0.2*inch))
                
                # Malicious IPs table
                ip_data_table = [['IP Address', 'Country', 'Threat Level', 'Types']]
                for ip_info in ip_data.get('threat_ips', [])[:10]:
                    ip_data_table.append([
                        ip_info.get('ip', 'N/A'),
                        ip_info.get('country', 'Unknown'),
                        ip_info.get('threat_level', 'UNKNOWN'),
                        ', '.join(ip_info.get('threat_types', [])[:2])
                    ])
                
                ip_table = Table(ip_data_table, colWidths=[1.5*inch, 1.5*inch, 1*inch, 2.5*inch])
                ip_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#DC2626')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
                ]))
                story.append(ip_table)
            
            # Footer
            story.append(PageBreak())
            story.append(Paragraph("Recommendations", heading_style))
            recommendations = [
                "• Review and address all CRITICAL and HIGH severity threats immediately",
                "• Implement recommended security controls for each threat type",
                "• Monitor suspicious IP addresses and consider blocking repeat offenders",
                "• Enable additional logging for affected resources",
                "• Schedule follow-up security assessment within 7 days",
                "• Update incident response procedures based on findings"
            ]
            for rec in recommendations:
                story.append(Paragraph(rec, styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
            
            story.append(Spacer(1, 0.3*inch))
            story.append(Paragraph(
                "<para align=center><i>End of Report - Security Monitoring Agent</i></para>",
                styles['Normal']
            ))
            
            # Build PDF
            doc.build(story)
            
            print(f"Report generated: {filepath}")
            return str(filepath)
        
        except Exception as e:
            print(f"PDF generation failed: {e}")
            return None
    
    def generate_quick_summary(
        self,
        overall_stats: Dict,
        threat_count: int,
        filename: Optional[str] = None
    ) -> Optional[str]:
        """
        Generate a quick one-page summary PDF
        
        Args:
            overall_stats: Overall security statistics
            threat_count: Number of threats detected
            filename: Optional custom filename
            
        Returns:
            Path to generated PDF file, or None if failed
        """
        if not self.enabled:
            return None
        
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"security_summary_{timestamp}.pdf"
        
        filepath = self.output_dir / filename
        
        try:
            doc = SimpleDocTemplate(str(filepath), pagesize=letter)
            story = []
            styles = getSampleStyleSheet()
            
            story.append(Paragraph("Security Analysis Summary", styles['Title']))
            story.append(Spacer(1, 0.5*inch))
            
            summary_text = f"""
            <para>
            <b>Date:</b> {datetime.now().strftime('%B %d, %Y')}<br/>
            <b>Threats Detected:</b> {threat_count}<br/>
            <b>Security Score:</b> {overall_stats.get('overall_score', 0)}/100<br/>
            <b>Status:</b> {overall_stats.get('health_status', 'UNKNOWN')}<br/>
            </para>
            """
            story.append(Paragraph(summary_text, styles['Normal']))
            
            doc.build(story)
            return str(filepath)
        
        except Exception as e:
            print(f"Quick summary generation failed: {e}")
            return None
