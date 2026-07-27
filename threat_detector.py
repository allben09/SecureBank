# ========== APP SECURITY: ML Threat Detection ==========
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import json
import re
from datetime import datetime
from typing import Dict, List, Tuple
import asyncio
import aiohttp
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

# ========== CYBERSECURITY: Threat Intelligence ==========
class ThreatDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.vectorizer = TfidfVectorizer(max_features=100)
        self.threat_signatures = self.load_threat_signatures()
        self.anomaly_threshold = 0.1
        
    def load_threat_signatures(self) -> Dict:
        """Load known threat patterns"""
        return {
            "sql_injection": [
                r"(\bselect\b.*\bfrom\b)",
                r"(\bunion\b.*\bselect\b)",
                r"(\bor\b.*\b=.*\b)",
                r"(--.*$)",
                r"(;.*--)"
            ],
            "xss": [
                r"<script.*?>.*?</script>",
                r"on\w+\s*=",
                r"javascript:",
                r"<.*?eval\s*\("
            ],
            "path_traversal": [
                r"\.\./",
                r"\.\.\\",
                r"/etc/passwd",
                r"windows\\system32"
            ],
            "command_injection": [
                r";\s*\w+",
                r"\|\s*\w+",
                r"&\s*\w+",
                r"`.*`"
            ]
        }
    
    def extract_features(self, data: Dict) -> np.ndarray:
        """Extract features from request data"""
        features = []
        
        # Request length
        features.append(len(str(data)))
        
        # Number of special characters
        text = str(data).lower()
        features.append(len(re.findall(r'[<>"\';]', text)))
        
        # Number of SQL keywords
        sql_keywords = ['select', 'union', 'where', 'from', 'insert', 'drop', 'table']
        features.append(sum(text.count(keyword) for keyword in sql_keywords))
        
        # Number of suspicious patterns
        suspicious_count = 0
        for category, patterns in self.threat_signatures.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    suspicious_count += 1
        features.append(suspicious_count)
        
        # Timestamp features (hour of day)
        hour = datetime.now().hour
        features.append(hour)
        
        # Day of week
        features.append(datetime.now().weekday())
        
        return np.array(features).reshape(1, -1)
    
    def train_model(self, training_data: List[Dict]):
        """Train isolation forest model"""
        features = []
        for data in training_data:
            features.append(self.extract_features(data).flatten())
        
        X = np.array(features)
        X_scaled = self.scaler.fit_transform(X)
        
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.model.fit(X_scaled)
        
        # Save model
        joblib.dump(self.model, 'models/threat_model.pkl')
        joblib.dump(self.scaler, 'models/scaler.pkl')
    
    def load_model(self):
        """Load trained model"""
        self.model = joblib.load('models/threat_model.pkl')
        self.scaler = joblib.load('models/scaler.pkl')
    
    def analyze_request(self, request_data: Dict) -> Dict:
        """
        Analyze request for threats
        Returns: {
            'is_threat': bool,
            'confidence': float,
            'threat_type': str,
            'details': str
        }
        """
        try:
            # Extract features
            features = self.extract_features(request_data)
            features_scaled = self.scaler.transform(features)
            
            # Predict anomaly
            prediction = self.model.predict(features_scaled)[0]
            score = self.model.score_samples(features_scaled)[0]
            
            # Check for known signatures
            threat_type = None
            text = str(request_data).lower()
            
            for category, patterns in self.threat_signatures.items():
                for pattern in patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        threat_type = category
                        break
                if threat_type:
                    break
            
            # Determine if threat
            is_threat = (prediction == -1) or (score < -self.anomaly_threshold)
            
            return {
                'is_threat': is_threat,
                'confidence': float(1 - abs(score) / 10) if score < 0 else float(0.5),
                'threat_type': threat_type or ('anomaly' if is_threat else 'none'),
                'details': f"Anomaly score: {score:.4f}",
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'is_threat': False,
                'confidence': 0.0,
                'threat_type': 'error',
                'details': f"Analysis error: {str(e)}"
            }
    
    def analyze_batch(self, requests: List[Dict]) -> List[Dict]:
        """Analyze multiple requests"""
        return [self.analyze_request(req) for req in requests]

# ========== WEB SECURITY: FastAPI Endpoint ==========
app = FastAPI()
detector = ThreatDetector()

# Load model if exists
try:
    detector.load_model()
    print("✅ Model loaded successfully")
except:
    print("⚠️ No model found, train first")

class RequestData(BaseModel):
    method: str
    path: str
    body: Dict = {}
    headers: Dict = {}
    ip: str
    timestamp: str

class AnalysisResponse(BaseModel):
    is_threat: bool
    confidence: float
    threat_type: str
    details: str
    timestamp: str

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_request(request: RequestData):
    """Analyze single request for threats"""
    try:
        # Convert to dict for analysis
        request_dict = request.dict()
        result = detector.analyze_request(request_dict)
        
        # Log threat
        if result['is_threat']:
            print(f"🚨 THREAT DETECTED: {result['threat_type']} - {request.ip}")
            
        return AnalysisResponse(**result)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze-batch")
async def analyze_batch(requests: List[RequestData]):
    """Analyze multiple requests"""
    request_dicts = [req.dict() for req in requests]
    results = detector.analyze_batch(request_dicts)
    return results

@app.post("/train")
async def train_model(data: List[Dict]):
    """Train the threat detection model"""
    try:
        detector.train_model(data)
        return {"message": "Model trained successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    return {"status": "OK", "model_loaded": detector.model is not None}

# ========== CYBERSECURITY: Network Scanner ==========
class NetworkScanner:
    def __init__(self):
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB"
        }
    
    async def scan_port(self, host: str, port: int) -> Dict:
        """Scan a single port"""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return {
                    "port": port,
                    "open": True,
                    "service": self.common_ports.get(port, "Unknown")
                }
            return {"port": port, "open": False}
        except:
            return {"port": port, "open": False, "error": "Scan failed"}
    
    async def scan_host(self, host: str, ports: List[int] = None) -> List[Dict]:
        """Scan multiple ports on a host"""
        if ports is None:
            ports = list(self.common_ports.keys())
        
        tasks = [self.scan_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r.get("open", False)]

@app.post("/scan")
async def scan_endpoint(host: str):
    """Scan for open ports"""
    scanner = NetworkScanner()
    results = await scanner.scan_host(host)
    return {
        "host": host,
        "open_ports": results,
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
