# ========== CYBERSECURITY: AI-Powered Threat Response ==========
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import json
import asyncio
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import aiohttp
import redis
import threading
from collections import deque
import torch
import torch.nn as nn
import torch.optim as optim

# ========== APP SECURITY: Neural Network for Threat Detection ==========
class ThreatDetectorNN(nn.Module):
    def __init__(self, input_dim=128, hidden_dim=256, output_dim=3):
        super(ThreatDetectorNN, self).__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.bn1 = nn.BatchNorm1d(hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim // 2)
        self.bn2 = nn.BatchNorm1d(hidden_dim // 2)
        self.fc3 = nn.Linear(hidden_dim // 2, output_dim)
        self.dropout = nn.Dropout(0.3)
        self.relu = nn.ReLU()
        
    def forward(self, x):
        x = self.relu(self.bn1(self.fc1(x)))
        x = self.dropout(x)
        x = self.relu(self.bn2(self.fc2(x)))
        x = self.dropout(x)
        x = self.fc3(x)
        return torch.softmax(x, dim=1)

# ========== CYBERSECURITY: AI Threat Response System ==========
class AIThreatResponse:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
        self.threat_history = deque(maxlen=10000)
        self.blocked_ips = set()
        self.rule_engine = {
            'sql_injection': self.handle_sql_injection,
            'xss': self.handle_xss,
            'brute_force': self.handle_brute_force,
            'ddos': self.handle_ddos,
            'malware': self.handle_malware,
            'data_exfiltration': self.handle_data_exfiltration,
            'insider_threat': self.handle_insider_threat,
            'api_abuse': self.handle_api_abuse,
        }
        self.response_actions = {
            'critical': self.critical_response,
            'high': self.high_response,
            'medium': self.medium_response,
            'low': self.low_response,
        }
        
        # Load AI model if exists
        try:
            self.model = torch.load('models/threat_ai_model.pt')
            self.model.eval()
            self.scaler = joblib.load('models/scaler.pkl')
            print("✅ AI Threat Response model loaded")
        except:
            print("⚠️ No AI model found, using rule-based engine")
            self.model = None
    
    # ========== CYBERSECURITY: Threat Classification ==========
    def classify_threat(self, features: np.ndarray) -> Dict:
        """Classify threat using AI model"""
        if self.model is None:
            return {'threat_type': 'unknown', 'confidence': 0.0}
        
        try:
            # Normalize features
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            features_tensor = torch.FloatTensor(features_scaled)
            
            # Get prediction
            with torch.no_grad():
                output = self.model(features_tensor)
                probabilities = output.numpy()[0]
                predicted_class = np.argmax(probabilities)
                confidence = probabilities[predicted_class]
            
            threat_types = ['benign', 'suspicious', 'malicious']
            return {
                'threat_type': threat_types[predicted_class],
                'confidence': float(confidence),
                'probabilities': {
                    'benign': float(probabilities[0]),
                    'suspicious': float(probabilities[1]),
                    'malicious': float(probabilities[2])
                }
            }
        except Exception as e:
            print(f"AI classification error: {e}")
            return {'threat_type': 'unknown', 'confidence': 0.0}
    
    # ========== APP SECURITY: Feature Extraction ==========
    def extract_features(self, request_data: Dict) -> np.ndarray:
        """Extract features for AI model"""
        features = []
        
        # Request characteristics
        features.append(len(str(request_data)))
        features.append(len(str(request_data.get('body', {}))))
        features.append(len(str(request_data.get('headers', {}))))
        
        # URL characteristics
        url = request_data.get('path', '')
        features.append(len(url))
        features.append(url.count('/'))
        features.append(url.count('.'))
        features.append(url.count('?') + url.count('&'))
        
        # Suspicious patterns
        text = str(request_data).lower()
        sql_patterns = sum(1 for p in ['select', 'union', 'drop', 'insert'] if p in text)
        xss_patterns = sum(1 for p in ['<script', 'onerror', 'javascript:'] if p in text)
        features.append(sql_patterns)
        features.append(xss_patterns)
        
        # Rate information
        ip = request_data.get('ip', '')
        rate = self.get_request_rate(ip)
        features.append(rate)
        
        # Time features
        now = datetime.now()
        features.append(now.hour)
        features.append(now.weekday())
        features.append(1 if now.hour < 6 or now.hour > 22 else 0)  # Off-hours
        
        # User agent characteristics
        ua = request_data.get('headers', {}).get('user-agent', '')
        features.append(1 if 'bot' in ua.lower() or 'crawler' in ua.lower() else 0)
        features.append(1 if 'mozilla' in ua.lower() else 0)
        
        # Session characteristics
        session_id = request_data.get('headers', {}).get('session-id', '')
        session_age = self.get_session_age(session_id)
        features.append(session_age)
        
        return np.array(features)
    
    # ========== CYBERSECURITY: Threat Response ==========
    async def analyze_and_respond(self, request_data: Dict) -> Dict:
        """Analyze request and respond appropriately"""
        # Extract features
        features = self.extract_features(request_data)
        
        # AI classification
        ai_result = self.classify_threat(features)
        
        # Rule-based detection
        rule_result = self.rule_based_detection(request_data)
        
        # Combine results
        threat_level = self.determine_threat_level(ai_result, rule_result)
        
        # Record threat
        self.record_threat(request_data, threat_level)
        
        # Take action
        response = await self.take_action(request_data, threat_level)
        
        return {
            'threat_detected': threat_level != 'benign',
            'threat_level': threat_level,
            'ai_confidence': ai_result.get('confidence', 0),
            'threat_type': rule_result.get('type', 'unknown'),
            'action_taken': response,
            'timestamp': datetime.now().isoformat()
        }
    
    # ========== APP SECURITY: Rule-Based Detection ==========
    def rule_based_detection(self, request_data: Dict) -> Dict:
        """Rule-based threat detection"""
        threat_type = 'benign'
        severity = 'low'
        
        text = str(request_data).lower()
        ip = request_data.get('ip', '')
        
        # SQL Injection
        if any(pattern in text for pattern in ['select', 'union', 'drop', 'insert', '--', ';--']):
            threat_type = 'sql_injection'
            severity = 'critical'
            
        # XSS
        elif any(pattern in text for pattern in ['<script', 'onerror', 'javascript:', 'alert(']):
            threat_type = 'xss'
            severity = 'high'
            
        # Brute Force
        elif self.get_request_rate(ip) > 10:
            threat_type = 'brute_force'
            severity = 'high'
            
        # DDoS
        elif self.get_request_rate(ip) > 100:
            threat_type = 'ddos'
            severity = 'critical'
            
        # Data Exfiltration
        elif any(pattern in text for pattern in ['export', 'dump', 'download_all']):
            threat_type = 'data_exfiltration'
            severity = 'critical'
            
        # API Abuse
        elif self.get_api_abuse_score(request_data) > 5:
            threat_type = 'api_abuse'
            severity = 'medium'
            
        return {
            'type': threat_type,
            'severity': severity,
            'detected': threat_type != 'benign'
        }
    
    # ========== CYBERSECURITY: Threat Response Actions ==========
    async def take_action(self, request_data: Dict, threat_level: str) -> Dict:
        """Take appropriate action based on threat level"""
        action = {
            'blocked': False,
            'message': 'Request allowed',
            'action_taken': 'none'
        }
        
        if threat_level == 'critical':
            # Block immediately
            action = await self.critical_response(request_data)
        elif threat_level == 'high':
            # Block and notify
            action = await self.high_response(request_data)
        elif threat_level == 'medium':
            # Challenge and monitor
            action = await self.medium_response(request_data)
        elif threat_level == 'low':
            # Monitor only
            action = await self.low_response(request_data)
        
        return action
    
    # ========== CYBERSECURITY: Critical Response ==========
    async def critical_response(self, request_data: Dict) -> Dict:
        """Immediate blocking for critical threats"""
        ip = request_data.get('ip', '')
        self.blocked_ips.add(ip)
        self.redis_client.sadd('blocked_ips', ip)
        
        # Alert security team
        await self.send_alert({
            'severity': 'critical',
            'type': request_data.get('threat_type', 'unknown'),
            'ip': ip,
            'timestamp': datetime.now().isoformat()
        })
        
        # Log incident
        self.log_incident(request_data, 'critical')
        
        return {
            'blocked': True,
            'message': 'Critical threat detected - IP blocked',
            'action_taken': 'block_and_alert'
        }
    
    # ========== CYBERSECURITY: High Response ==========
    async def high_response(self, request_data: Dict) -> Dict:
        """Block and monitor for high threats"""
        ip = request_data.get('ip', '')
        
        # Increment block counter
        self.redis_client.incr(f'block_count_{ip}')
        block_count = int(self.redis_client.get(f'block_count_{ip}') or 0)
        
        if block_count > 5:
            # Permanently block after 5 violations
            self.blocked_ips.add(ip)
            self.redis_client.sadd('blocked_ips', ip)
            return {
                'blocked': True,
                'message': 'Persistent threat detected - IP blocked',
                'action_taken': 'permanent_block'
            }
        
        # Temporary block for 1 hour
        self.redis_client.expire(f'block_{ip}', 3600)
        self.redis_client.set(f'block_{ip}', 'true')
        
        return {
            'blocked': True,
            'message': 'High threat detected - Temporarily blocked',
            'action_taken': 'temporary_block'
        }
    
    # ========== APP SECURITY: Medium Response ==========
    async def medium_response(self, request_data: Dict) -> Dict:
        """Challenge and monitor for medium threats"""
        ip = request_data.get('ip', '')
        
        # Add CAPTCHA requirement
        captcha_required = True
        self.redis_client.set(f'captcha_{ip}', 'true', ex=3600)
        
        # Rate limit severely
        self.redis_client.setex(f'rate_limit_{ip}', 3600, 10)
        
        return {
            'blocked': False,
            'message': 'Suspicious activity detected - CAPTCHA required',
            'action_taken': 'challenge_and_monitor'
        }
    
    # ========== CYBERSECURITY: Low Response ==========
    async def low_response(self, request_data: Dict) -> Dict:
        """Monitor low threats"""
        ip = request_data.get('ip', '')
        
        # Increase monitoring
        self.redis_client.incr(f'monitor_count_{ip}')
        self.redis_client.expire(f'monitor_count_{ip}', 86400)  # 24 hours
        
        # Log for analysis
        self.log_incident(request_data, 'low')
        
        return {
            'blocked': False,
            'message': 'Low-level anomaly detected - Monitoring',
            'action_taken': 'monitor_only'
        }
    
    # ========== CYBERSECURITY: Alert System ==========
    async def send_alert(self, alert_data: Dict):
        """Send alert to security team"""
        # Webhook notification
        await self.send_webhook(alert_data)
        
        # Email alert
        await self.send_email_alert(alert_data)
        
        # SMS for critical alerts
        if alert_data.get('severity') == 'critical':
            await self.send_sms_alert(alert_data)
    
    async def send_webhook(self, data: Dict):
        """Send webhook notification"""
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(
                    'https://webhook.site/your-webhook',
                    json=data,
                    timeout=5
                )
        except:
            pass
    
    async def send_email_alert(self, data: Dict):
        """Send email alert"""
        # Integrate with SendGrid, SES, etc.
        print(f"📧 ALERT: {json.dumps(data, indent=2)}")
    
    async def send_sms_alert(self, data: Dict):
        """Send SMS alert for critical issues"""
        # Integrate with Twilio
        print(f"📱 SMS ALERT: {data['ip']} - {data['type']}")
    
    # ========== APP SECURITY: Incident Logging ==========
    def log_incident(self, request_data: Dict, severity: str):
        """Log security incident"""
        incident = {
            'timestamp': datetime.now().isoformat(),
            'ip': request_data.get('ip', ''),
            'method': request_data.get('method', ''),
            'path': request_data.get('path', ''),
            'severity': severity,
            'headers': request_data.get('headers', {}),
            'body': str(request_data.get('body', {}))[:1000],  # Truncate
            'threat_type': request_data.get('threat_type', 'unknown')
        }
        
        # Store in Redis
        self.redis_client.lpush('incidents', json.dumps(incident))
        self.redis_client.ltrim('incidents', 0, 9999)  # Keep last 10000
    
    # ========== CYBERSECURITY: Self-Learning ==========
    async def update_ai_model(self):
        """Update AI model with new threat data"""
        if not self.model:
            return
        
        # Get recent threat data
        incidents = self.redis_client.lrange('incidents', 0, 1000)
        if len(incidents) < 100:
            return
        
        # Prepare training data
        X = []
        y = []
        
        for incident_json in incidents:
            incident = json.loads(incident_json)
            features = self.extract_features(incident)
            threat_level = incident.get('severity', 'low')
            
            X.append(features)
            y.append(['benign', 'suspicious', 'malicious'].index(
                'malicious' if threat_level in ['critical', 'high'] else
                'suspicious' if threat_level == 'medium' else
                'benign'
            ))
        
        if len(X) < 50:
            return
        
        X = np.array(X)
        y = np.array(y)
        
        # Train model
        X_scaled = self.scaler.fit_transform(X)
        X_tensor = torch.FloatTensor(X_scaled)
        y_tensor = torch.LongTensor(y)
        
        # Train
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(self.model.parameters(), lr=0.001)
        
        self.model.train()
        for epoch in range(10):
            optimizer.zero_grad()
            output = self.model(X_tensor)
            loss = criterion(output, y_tensor)
            loss.backward()
            optimizer.step()
        
        # Save updated model
        torch.save(self.model, 'models/threat_ai_model.pt')
        joblib.dump(self.scaler, 'models/scaler.pkl')
        
        print(f"✅ AI model updated with {len(X)} samples")
    
    # ========== CYBERSECURITY: Incident Response Orchestration ==========
    async def orchestrate_incident_response(self, incident_data: Dict):
        """Orchestrate full incident response"""
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{int(datetime.now().timestamp())}"
        
        # Step 1: Containment
        self.contain_threat(incident_data)
        
        # Step 2: Investigation
        investigation = await self.investigate_incident(incident_data)
        
        # Step 3: Eradication
        eradication = self.eradicate_threat(incident_data, investigation)
        
        # Step 4: Recovery
        recovery = self.recover_systems(incident_data)
        
        # Step 5: Lessons Learned
        lessons = self.lessons_learned(incident_data, investigation)
        
        # Generate incident report
        report = {
            'incident_id': incident_id,
            'timestamp': datetime.now().isoformat(),
            'incident_data': incident_data,
            'investigation': investigation,
            'actions_taken': {
                'containment': containment,
                'eradication': eradication,
                'recovery': recovery
            },
            'lessons_learned': lessons,
            'status': 'resolved'
        }
        
        # Store incident report
        self.redis_client.set(f'incident_{incident_id}', json.dumps(report))
        
        return report
    
    # Helper methods
    def get_request_rate(self, ip: str) -> int:
        """Get request rate for IP"""
        key = f'rate_{ip}'
        rate = self.redis_client.get(key)
        return int(rate) if rate else 0
    
    def get_session_age(self, session_id: str) -> int:
        """Get session age in seconds"""
        if not session_id:
            return 0
        key = f'session_{session_id}'
        created = self.redis_client.get(key)
        if not created:
            return 0
        age = (datetime.now() - datetime.fromisoformat(created)).total_seconds()
        return int(age)
    
    def get_api_abuse_score(self, request_data: Dict) -> int:
        """Calculate API abuse score"""
        score = 0
        ip = request_data.get('ip', '')
        
        # Check for unusual patterns
        if 'admin' in request_data.get('path', ''):
            score += 2
        if request_data.get('method') not in ['GET', 'POST']:
            score += 1
        if len(str(request_data)) > 10000:
            score += 1
            
        # Check request rate
        rate = self.get_request_rate(ip)
        if rate > 10:
            score += 2
            
        return score
    
    def determine_threat_level(self, ai_result: Dict, rule_result: Dict) -> str:
        """Determine overall threat level"""
        if rule_result.get('detected'):
            return rule_result.get('severity', 'low')
        
        if ai_result.get('threat_type') == 'malicious':
            return 'high'
        elif ai_result.get('threat_type') == 'suspicious':
            return 'medium'
        
        return 'benign'
    
    def record_threat(self, request_data: Dict, threat_level: str):
        """Record threat for analytics"""
        self.threat_history.append({
            'timestamp': datetime.now(),
            'ip': request_data.get('ip', ''),
            'threat_level': threat_level,
            'request': str(request_data)[:500]
        })
    
    def contain_threat(self, incident_data: Dict):
        """Contain the threat"""
        ip = incident_data.get('ip', '')
        self.blocked_ips.add(ip)
        self.redis_client.sadd('blocked_ips', ip)
        
        # Isolate affected systems
        affected_services = incident_data.get('affected_services', [])
        for service in affected_services:
            self.redis_client.set(f'quarantine_{service}', 'true', ex=3600)
        
        return {'contained': True, 'actions': ['block_ip', 'quarantine_services']}
    
    async def investigate_incident(self, incident_data: Dict) -> Dict:
        """Investigate the incident"""
        investigation = {
            'root_cause': 'suspected',
            'affected_systems': [],
            'data_compromised': False,
            'attack_vectors': [],
            'timeline': []
        }
        
        # Analyze logs
        ip = incident_data.get('ip', '')
        logs = self.redis_client.lrange(f'logs_{ip}', 0, 100)
        
        for log in logs:
            investigation['timeline'].append(json.loads(log))
        
        return investigation
    
    def eradicate_threat(self, incident_data: Dict, investigation: Dict) -> Dict:
        """Eradicate the threat"""
        actions = []
        
        # Remove malware if any
        if 'malware' in incident_data.get('type', ''):
            actions.append('remove_malware')
        
        # Patch vulnerabilities
        if 'vulnerability' in incident_data.get('type', ''):
            actions.append('patch_vulnerability')
        
        # Reset compromised credentials
        if 'credential' in incident_data.get('type', ''):
            actions.append('reset_credentials')
        
        return {'completed': True, 'actions': actions}
    
    def recover_systems(self, incident_data: Dict) -> Dict:
        """Recover affected systems"""
        actions = []
        
        # Restore from backup
        if incident_data.get('data_compromised', False):
            actions.append('restore_from_backup')
        
        # Reapply security patches
        actions.append('reapply_patches')
        
        # Verify system integrity
        actions.append('verify_integrity')
        
        return {'completed': True, 'actions': actions}
    
    def lessons_learned(self, incident_data: Dict, investigation: Dict) -> Dict:
        """Extract lessons from incident"""
        lessons = {
            'improvements': [],
            'detection_gaps': [],
            'response_issues': []
        }
        
        # Analyze response time
        response_time = incident_data.get('response_time', 0)
        if response_time > 300:  # 5 minutes
            lessons['response_issues'].append('Slow response time')
        
        # Identify detection gaps
        if not incident_data.get('detected_early', False):
            lessons['detection_gaps'].append('Late detection')
        
        return lessons

# ========== CYBERSECURITY: WebSocket for Real-time Threats ==========
import asyncio
import websockets
from datetime import datetime

class ThreatMonitor:
    def __init__(self):
        self.clients = set()
        self.threat_detector = AIThreatResponse()
    
    async def handle_client(self, websocket, path):
        """Handle WebSocket client connection"""
        self.clients.add(websocket)
        try:
            async for message in websocket:
                # Process threat alert
                data = json.loads(message)
                response = await self.threat_detector.analyze_and_respond(data)
                await websocket.send(json.dumps(response))
        finally:
            self.clients.remove(websocket)
    
    async def broadcast_threat(self, threat_data: Dict):
        """Broadcast threat to all connected clients"""
        if not self.clients:
            return
        
        message = json.dumps(threat_data)
        await asyncio.gather(*[client.send(message) for client in self.clients])

# ========== API Endpoints ==========
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import uvicorn

app = FastAPI(title="AI Threat Response System")

threat_detector = AIThreatResponse()
threat_monitor = ThreatMonitor()

@app.post("/analyze-threat")
async def analyze_threat(request_data: Dict):
    """Analyze a threat using AI"""
    result = await threat_detector.analyze_and_respond(request_data)
    return result

@app.websocket("/threat-monitor")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time threat monitoring"""
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            request_data = json.loads(data)
            response = await threat_detector.analyze_and_respond(request_data)
            await websocket.send_json(response)
    except WebSocketDisconnect:
        print("Client disconnected")

@app.get("/threat-stats")
async def get_threat_stats():
    """Get threat statistics"""
    return {
        'total_threats': len(threat_detector.threat_history),
        'blocked_ips': list(threat_detector.blocked_ips)[:10],
        'recent_threats': [
            {
                'timestamp': t['timestamp'].isoformat(),
                'threat_level': t['threat_level']
            }
            for t in list(threat_detector.threat_history)[-10:]
        ]
    }

@app.post("/update-model")
async def update_model():
    """Manually trigger AI model update"""
    await threat_detector.update_ai_model()
    return {'status': 'Model update triggered'}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
