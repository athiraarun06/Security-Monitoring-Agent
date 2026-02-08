"""
Security Monitoring Agent - Enhanced Main Application
Features: Compression, Threat Detection, IP Intelligence, Scoring, AI Insights, History, PDF Reports
Version: 2.0.0 - Production Ready
"""

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import os
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

from src.compressor import SecurityLogCompressor
from src.detector import SecurityLogDetector
from src.ip_intelligence import IPThreatIntelligence
from src.scoring import ThreatScoringEngine
from src.ai_insights import AIInsightsEngine
from src.history import ThreatHistoryDB
from src.pdf_report import PDFReportGenerator
from src.pattern_learning import PatternLearner

app = FastAPI(
    title="Security Monitoring Agent",
    description="AI-Powered Security Log Analysis with Compression, Threat Detection, and Intelligence",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware for better frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
ip_intel = IPThreatIntelligence()
scoring_engine = ThreatScoringEngine()
ai_insights = AIInsightsEngine()
history_db = ThreatHistoryDB()
pdf_generator = PDFReportGenerator()
pattern_learner = PatternLearner()

# Request/Response Models
class AnalyzeRequest(BaseModel):
    logs: str
    prompt: str = "Identify security threats and anomalies"
    generate_pdf: bool = False
    learn_patterns: bool = False

class ThreatInfo(BaseModel):
    type: str
    severity: str
    description: str
    recommendation: str
    confidence: float
    affected: List[str]
    risk_score: Optional[float] = None
    source_ip: Optional[str] = None
    country: Optional[str] = None

class AnalyzeResponse(BaseModel):
    success: bool
    compressed_context: str
    ai_response: str
    threats: List[ThreatInfo]
    compression_stats: Dict[str, Any]
    cost_savings: Dict[str, Any]
    # New enhanced features
    overall_security: Optional[Dict[str, Any]] = None
    ip_intelligence: Optional[Dict[str, Any]] = None
    executive_summary: Optional[str] = None
    pdf_report_path: Optional[str] = None
    pattern_anomalies: Optional[List[Dict]] = None


@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve the main HTML page"""
    html_file = "frontend/index.html"
    if os.path.exists(html_file):
        with open(html_file, 'r', encoding='utf-8') as f:
            return HTMLResponse(content=f.read())
    else:
        return HTMLResponse(content="""
        <html><body><h1>Security Monitoring Agent</h1>
        <p>Frontend not found. API available at <a href="/docs">/docs</a></p>
        </body></html>
        """)


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_security_logs(request: AnalyzeRequest):
    """
    Enhanced endpoint: Compress → Detect → Score → Analyze IPs → AI Insights → Save History → Generate PDF
    """
    try:
        logger.info(f"Starting analysis - Log size: {len(request.logs)} bytes")
        
        # Step 1: Compress logs with ScaleDown
        compressor = SecurityLogCompressor()
        compression_result = compressor.compress_logs(
            logs=request.logs,
            prompt=request.prompt
        )
        logger.info(f"Compression complete - Ratio: {compression_result.get('compression_ratio', 0):.2f}x")
        
        # Step 2: Detect anomalies
        detector = SecurityLogDetector()
        anomalies = detector.detect_anomalies(
            logs=request.logs,
            compressed_context=compression_result.get('compressed_context')
        )
        
        # Step 3: IP Intelligence Analysis
        ip_data = ip_intel.analyze_logs_ips(request.logs)
        
        # Step 4: Calculate threat scores
        threat_scores = []
        threats_with_scores = []
        
        for anomaly in anomalies:
            # Calculate risk score for each threat
            score = scoring_engine.calculate_threat_score(
                threat_type=anomaly.type.value,
                threat_count=1,
                affected_resources=anomaly.affected_resources,
                confidence=anomaly.confidence
            )
            threat_scores.append(score)
            
            # Find source IP if available
            source_ip = None
            country = None
            for threat_ip in ip_data.get('threat_ips', []):
                if threat_ip['ip'] in request.logs:
                    source_ip = threat_ip['ip']
                    country = threat_ip['country']
                    break
            
            threats_with_scores.append({
                'type': anomaly.type.value,
                'severity': anomaly.severity.value,
                'description': anomaly.description,
                'recommendation': anomaly.recommendation,
                'confidence': anomaly.confidence,
                'affected': anomaly.affected_resources[:5],
                'risk_score': score.final_score,
                'source_ip': source_ip,
                'country': country
            })
        
        # Step 5: Calculate overall security score
        overall_security = scoring_engine.calculate_overall_security_score(threat_scores)
        
        # Step 6: Generate AI insights
        executive_summary = ai_insights.generate_executive_summary(
            threats_with_scores,
            overall_security,
            ip_data
        )
        
        # Step 7: Pattern learning anomalies
        pattern_anomalies = None
        if request.learn_patterns:
            pattern_anomalies = pattern_learner.detect_anomalies(request.logs)
        
        # Step 8: Calculate compression stats
        stats = compressor.get_compression_stats(compression_result)
        
        cost_savings = {
            'tokens_saved': stats['tokens_saved'],
            'percentage_saved': stats['savings_percent'],
            'compression_ratio': stats['compression_ratio'],
            'estimated_cost_saved_usd': stats['estimated_cost_saved'],
            'latency_ms': stats['latency_ms']
        }
        
        compression_stats = {
            'original_tokens': stats['original_tokens'],
            'compressed_tokens': stats['compressed_tokens'],
            'tokens_saved': stats['tokens_saved'],
            'log_lines': len(request.logs.split('\n'))
        }
        
        # Step 9: Save to history database
        history_db.save_analysis(
            threats=threats_with_scores,
            overall_stats=overall_security,
            compression_stats=compression_stats,
            ip_data=ip_data
        )
        
        # Step 10: Generate PDF report if requested
        pdf_path = None
        if request.generate_pdf:
            pdf_path = pdf_generator.generate_report(
                threats=threats_with_scores,
                overall_stats=overall_security,
                compression_stats=compression_stats,
                ip_data=ip_data,
                executive_summary=executive_summary
            )
        
        # Step 11: Format response
        formatted_threats = []
        for threat in threats_with_scores:
            formatted_threats.append(ThreatInfo(**threat))
        
        return AnalyzeResponse(
            success=True,
            compressed_context=compression_result.get('compressed_context', ''),
            ai_response=compression_result.get('content', 'Analysis complete'),
            threats=formatted_threats,
            compression_stats=compression_stats,
            cost_savings=cost_savings,
            overall_security=overall_security,
            ip_intelligence=ip_data,
            executive_summary=executive_summary,
            pdf_report_path=pdf_path,
            pattern_anomalies=pattern_anomalies
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Security Monitoring Agent",
        "version": "2.0.0",
        "features": [
            "log_compression",
            "threat_detection",
            "ip_intelligence",
            "risk_scoring",
            "ai_insights",
            "historical_analysis",
            "pdf_reports",
            "pattern_learning"
        ]
    }


@app.get("/history/trends")
async def get_threat_trends(days: int = 7):
    """Get threat trends over specified days"""
    try:
        trends = history_db.get_threat_trends(days)
        return JSONResponse(content=trends)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/history/statistics")
async def get_statistics():
    """Get overall historical statistics"""
    try:
        stats = history_db.get_statistics()
        return JSONResponse(content=stats)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/history/recent")
async def get_recent_analyses(limit: int = 10):
    """Get recent analysis sessions"""
    try:
        recent = history_db.get_recent_analyses(limit)
        return JSONResponse(content={"analyses": recent})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/baseline/summary")
async def get_baseline_summary():
    """Get learned pattern baseline summary"""
    try:
        summary = pattern_learner.get_baseline_summary()
        return JSONResponse(content=summary)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/baseline/learn")
async def learn_patterns(logs: str, is_clean: bool = True):
    """Learn patterns from clean log data"""
    try:
        pattern_learner.learn_from_logs(logs, is_clean)
        summary = pattern_learner.get_baseline_summary()
        return JSONResponse(content={
            "success": True,
            "message": "Patterns learned successfully",
            "baseline": summary
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/download/report/{filename}")
async def download_report(filename: str):
    """Download PDF report"""
    try:
        file_path = os.path.join("reports", filename)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Report not found")
        
        return FileResponse(
            file_path,
            media_type="application/pdf",
            filename=filename,
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    
    # Get host and port from environment variables (for hosting platforms)
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8001"))
    
    print(f"🚀 Starting Security Monitoring Agent v2.0")
    print(f"📡 Server: http://{host}:{port}")
    print(f"📚 API Docs: http://{host}:{port}/docs")
    print(f"🔒 Press CTRL+C to stop\n")
    
    uvicorn.run(app, host=host, port=port)
