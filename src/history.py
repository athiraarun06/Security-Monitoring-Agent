"""
Historical Threat Dashboard
Stores and analyzes threat history using SQLite
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
import os


class ThreatHistoryDB:
    """
    SQLite database for storing threat analysis history
    """
    
    def __init__(self, db_path: str = "data/threat_history.db"):
        """
        Initialize database connection
        
        Args:
            db_path: Path to SQLite database file
        """
        # Create data directory if it doesn't exist
        db_dir = Path(db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._initialize_tables()
    
    def _initialize_tables(self):
        """Create database tables if they don't exist"""
        cursor = self.conn.cursor()
        
        # Analysis sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                log_count INTEGER,
                threat_count INTEGER,
                overall_score REAL,
                health_status TEXT,
                compression_ratio REAL,
                tokens_saved INTEGER
            )
        """)
        
        # Threats table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT,
                severity TEXT,
                risk_score REAL,
                description TEXT,
                affected_resources TEXT,
                source_ip TEXT,
                country TEXT,
                FOREIGN KEY (session_id) REFERENCES analysis_sessions(id)
            )
        """)
        
        # IP threat history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                first_seen DATETIME,
                last_seen DATETIME,
                total_incidents INTEGER DEFAULT 1,
                threat_level TEXT,
                country TEXT,
                is_blocked BOOLEAN DEFAULT 0
            )
        """)
        
        # Create indexes for better performance
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threats_type 
            ON threats(threat_type)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threats_timestamp 
            ON threats(timestamp)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ip_history_ip 
            ON ip_history(ip)
        """)
        
        self.conn.commit()
    
    def save_analysis(
        self,
        threats: List[Dict],
        overall_stats: Dict,
        compression_stats: Dict,
        ip_data: Optional[Dict] = None
    ) -> int:
        """
        Save an analysis session to the database
        
        Args:
            threats: List of detected threats
            overall_stats: Overall security statistics
            compression_stats: Compression metrics
            ip_data: Optional IP intelligence data
            
        Returns:
            Session ID
        """
        cursor = self.conn.cursor()
        
        # Insert session
        cursor.execute("""
            INSERT INTO analysis_sessions 
            (log_count, threat_count, overall_score, health_status, 
             compression_ratio, tokens_saved)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            compression_stats.get('log_lines', 0),
            len(threats),
            overall_stats.get('overall_score', 0),
            overall_stats.get('health_status', 'UNKNOWN'),
            compression_stats.get('compression_ratio', 0),
            compression_stats.get('tokens_saved', 0)
        ))
        
        session_id = cursor.lastrowid
        
        # Insert threats
        for threat in threats:
            source_ip = threat.get('source_ip', '')
            country = threat.get('country', '')
            
            cursor.execute("""
                INSERT INTO threats 
                (session_id, threat_type, severity, risk_score, 
                 description, affected_resources, source_ip, country)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                threat.get('type', ''),
                threat.get('severity', ''),
                threat.get('risk_score', 0),
                threat.get('description', ''),
                json.dumps(threat.get('affected', [])),
                source_ip,
                country
            ))
            
            # Update IP history if we have IP data
            if source_ip:
                self._update_ip_history(
                    source_ip,
                    threat.get('severity', 'MEDIUM'),
                    country
                )
        
        self.conn.commit()
        return session_id
    
    def _update_ip_history(self, ip: str, threat_level: str, country: str):
        """Update or insert IP threat history"""
        cursor = self.conn.cursor()
        
        # Check if IP exists
        cursor.execute("SELECT id, total_incidents FROM ip_history WHERE ip = ?", (ip,))
        result = cursor.fetchone()
        
        if result:
            # Update existing
            cursor.execute("""
                UPDATE ip_history 
                SET last_seen = CURRENT_TIMESTAMP,
                    total_incidents = total_incidents + 1,
                    threat_level = ?
                WHERE ip = ?
            """, (threat_level, ip))
        else:
            # Insert new
            cursor.execute("""
                INSERT INTO ip_history 
                (ip, first_seen, last_seen, threat_level, country)
                VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?)
            """, (ip, threat_level, country))
    
    def get_threat_trends(self, days: int = 7) -> Dict[str, Any]:
        """
        Get threat trends over time
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Dictionary with trend data
        """
        cursor = self.conn.cursor()
        
        since_date = datetime.now() - timedelta(days=days)
        
        # Threat count by day
        cursor.execute("""
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM threats
            WHERE timestamp >= ?
            GROUP BY DATE(timestamp)
            ORDER BY date
        """, (since_date,))
        
        daily_counts = [
            {'date': row['date'], 'count': row['count']}
            for row in cursor.fetchall()
        ]
        
        # Threat types distribution
        cursor.execute("""
            SELECT threat_type, COUNT(*) as count
            FROM threats
            WHERE timestamp >= ?
            GROUP BY threat_type
            ORDER BY count DESC
        """, (since_date,))
        
        threat_types = [
            {'type': row['threat_type'], 'count': row['count']}
            for row in cursor.fetchall()
        ]
        
        # Top attacked resources
        cursor.execute("""
            SELECT affected_resources, COUNT(*) as count
            FROM threats
            WHERE timestamp >= ? AND affected_resources != '[]'
            GROUP BY affected_resources
            ORDER BY count DESC
            LIMIT 10
        """, (since_date,))
        
        top_targets = []
        for row in cursor.fetchall():
            try:
                resources = json.loads(row['affected_resources'])
                if resources:
                    top_targets.append({
                        'resource': resources[0] if resources else 'Unknown',
                        'count': row['count']
                    })
            except json.JSONDecodeError:
                pass
        
        # Most dangerous IPs
        cursor.execute("""
            SELECT ip, country, total_incidents, threat_level, last_seen
            FROM ip_history
            WHERE last_seen >= ?
            ORDER BY total_incidents DESC
            LIMIT 10
        """, (since_date,))
        
        dangerous_ips = [
            {
                'ip': row['ip'],
                'country': row['country'],
                'incidents': row['total_incidents'],
                'threat_level': row['threat_level'],
                'last_seen': row['last_seen']
            }
            for row in cursor.fetchall()
        ]
        
        return {
            'daily_counts': daily_counts,
            'threat_types': threat_types,
            'top_targets': top_targets,
            'dangerous_ips': dangerous_ips,
            'period_days': days
        }
    
    def get_recent_analyses(self, limit: int = 10) -> List[Dict]:
        """
        Get recent analysis sessions
        
        Args:
            limit: Number of sessions to return
            
        Returns:
            List of session summaries
        """
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT * FROM analysis_sessions
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall database statistics"""
        cursor = self.conn.cursor()
        
        # Total analyses
        cursor.execute("SELECT COUNT(*) as count FROM analysis_sessions")
        total_analyses = cursor.fetchone()['count']
        
        # Total threats
        cursor.execute("SELECT COUNT(*) as count FROM threats")
        total_threats = cursor.fetchone()['count']
        
        # Most common threat type
        cursor.execute("""
            SELECT threat_type, COUNT(*) as count
            FROM threats
            GROUP BY threat_type
            ORDER BY count DESC
            LIMIT 1
        """)
        most_common = cursor.fetchone()
        
        # Average threats per session
        avg_threats = total_threats / max(total_analyses, 1)
        
        # Unique malicious IPs
        cursor.execute("SELECT COUNT(DISTINCT ip) as count FROM ip_history")
        unique_ips = cursor.fetchone()['count']
        
        return {
            'total_analyses': total_analyses,
            'total_threats': total_threats,
            'average_threats_per_session': round(avg_threats, 2),
            'most_common_threat': most_common['threat_type'] if most_common else 'None',
            'unique_malicious_ips': unique_ips
        }
    
    def get_comparison(self, current_score: float) -> Dict[str, Any]:
        """
        Compare current analysis with historical average
        
        Args:
            current_score: Current overall security score
            
        Returns:
            Comparison data
        """
        cursor = self.conn.cursor()
        
        # Get historical average
        cursor.execute("""
            SELECT AVG(overall_score) as avg_score,
                   AVG(threat_count) as avg_threats
            FROM analysis_sessions
            WHERE timestamp >= datetime('now', '-30 days')
        """)
        
        result = cursor.fetchone()
        avg_score = result['avg_score'] or 0
        avg_threats = result['avg_threats'] or 0
        
        # Calculate trends
        score_trend = "improving" if current_score > avg_score else "declining"
        
        return {
            'current_score': current_score,
            'historical_avg': round(avg_score, 1),
            'score_trend': score_trend,
            'avg_threats_per_session': round(avg_threats, 1)
        }
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
    
    def __del__(self):
        """Cleanup on deletion"""
        self.close()
