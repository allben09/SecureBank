#!/bin/bash
# ========== CYBERSECURITY: Deploy Complete Security Suite ==========

echo "🛡️ Deploying SecureBank Security Suite"
echo "========================================"

# 1. Create directories
mkdir -p {models,logs,reports,grafana/dashboards,prometheus}

# 2. Set up Python environment
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# 3. Train AI Model (if not exists)
if [ ! -f models/threat_ai_model.pt ]; then
    echo "🤖 Training AI Threat Detection Model..."
    python -c "from backend_python.ai_threat_response import AIThreatResponse; AIThreatResponse()"
fi

# 4. Start Docker services
echo "🐳 Starting Docker services..."
docker-compose up -d

# 5. Run initial security audit
echo "🔍 Running initial security audit..."
python scripts/pentest.py https://localhost --parallel

# 6. Configure Grafana
echo "📈 Configuring Grafana dashboards..."
curl -X POST http://localhost:3000/api/dashboards/db \
    -H "Content-Type: application/json" \
    -d @grafana/dashboards/security-dashboard.json

# 7. Start WebSocket threat monitor
echo "🔌 Starting WebSocket threat monitor..."
python -m backend_python.ai_threat_response &

# 8. Deploy React Native app
echo "📱 Building React Native app..."
cd mobile-app && npm install && npm run build && cd ..

# 9. Setup cron jobs
echo "⏰ Setting up cron jobs for regular scans..."
(crontab -l 2>/dev/null; echo "0 2 * * * cd /app && python scripts/pentest.py https://localhost") | crontab -

echo "✅ Security suite deployed successfully!"
echo ""
echo "Access the services:"
echo "  - Web App: https://localhost"
echo "  - API: https://localhost/api"
echo "  - Grafana: http://localhost:3000"
echo "  - Threat Monitor: ws://localhost:8001/threat-monitor"
echo "  - Pentest Reports: ./reports/"
echo "  - Logs: ./logs/"
