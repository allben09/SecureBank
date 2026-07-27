// ========== CYBERSECURITY: Metrics Collection ==========
const client = require('prom-client');
const logger = require('../utils/logger');

// Register default metrics
client.collectDefaultMetrics({ timeout: 5000 });

// ========== APP SECURITY: Custom Metrics ==========
const metrics = {
    // Security threats
    threatsTotal: new client.Counter({
        name: 'security_threats_total',
        help: 'Total number of security threats detected',
        labelNames: ['threat_type', 'severity', 'source_ip']
    }),

    // API requests
    apiRequestsTotal: new client.Counter({
        name: 'api_requests_total',
        help: 'Total API requests',
        labelNames: ['method', 'endpoint', 'status_code']
    }),

    apiBlockedTotal: new client.Counter({
        name: 'api_requests_blocked_total',
        help: 'Total blocked API requests',
        labelNames: ['reason']
    }),

    // Authentication
    authFailedTotal: new client.Counter({
        name: 'auth_failed_total',
        help: 'Total failed authentication attempts',
        labelNames: ['email', 'ip']
    }),

    authSuccessTotal: new client.Counter({
        name: 'auth_success_total',
        help: 'Total successful authentications',
        labelNames: ['email']
    }),

    // MFA
    mfaEnabledUsers: new client.Gauge({
        name: 'mfa_enabled_users',
        help: 'Number of users with MFA enabled'
    }),

    totalUsers: new client.Gauge({
        name: 'total_users',
        help: 'Total number of registered users'
    }),

    // SSL/TLS
    sslCertificateDaysRemaining: new client.Gauge({
        name: 'ssl_certificate_days_remaining',
        help: 'Days until SSL certificate expires'
    }),

    // Vulnerabilities
    owaspVulnerabilitiesTotal: new client.Counter({
        name: 'owasp_vulnerabilities_total',
        help: 'OWASP Top 10 vulnerabilities found',
        labelNames: ['vulnerability_type']
    }),

    // Incident response
    incidentResponseTime: new client.Histogram({
        name: 'incident_response_time_seconds',
        help: 'Incident response time in seconds',
        buckets: [5, 10, 30, 60, 120, 300, 600]
    }),

    // Security score
    securityScore: new client.Gauge({
        name: 'security_score',
        help: 'Overall security score (0-100)'
    }),

    // Rate limiting
    rateLimitHits: new client.Counter({
        name: 'rate_limit_hits_total',
        help: 'Total rate limit hits',
        labelNames: ['endpoint', 'ip']
    }),

    // Security headers
    securityHeadersConfigured: new client.Gauge({
        name: 'security_headers_configured',
        help: 'Number of security headers configured'
    }),

    // Input validation
    invalidInputsTotal: new client.Counter({
        name: 'invalid_inputs_total',
        help: 'Total invalid inputs detected',
        labelNames: ['input_type']
    }),

    // Sessions
    activeSessions: new client.Gauge({
        name: 'active_sessions_total',
        help: 'Number of active user sessions'
    }),
};

// ========== APP SECURITY: Update Metrics ==========
class MetricsService {
    constructor() {
        // Update security score every 5 minutes
        setInterval(() => this.updateSecurityScore(), 300000);
        
        // Update SSL certificate expiry
        setInterval(() => this.updateSSLCertificateExpiry(), 3600000);
        
        // Update user metrics
        setInterval(() => this.updateUserMetrics(), 600000);
    }

    // ========== CYBERSECURITY: Update Security Score ==========
    async updateSecurityScore() {
        try {
            // Calculate score based on various factors
            let score = 100;
            
            // Deduct for vulnerabilities
            const vulnerabilities = await this.getVulnerabilities();
            score -= vulnerabilities.critical * 15;
            score -= vulnerabilities.high * 8;
            score -= vulnerabilities.medium * 3;
            score -= vulnerabilities.low * 1;
            
            // Deduct for missing security headers
            const headers = await this.getSecurityHeaders();
            const configured = Object.values(headers).filter(v => v).length;
            metrics.securityHeadersConfigured.set(configured);
            score += configured * 2; // Bonus for configured headers
            
            // Deduct for SSL issues
            const sslDays = metrics.sslCertificateDaysRemaining.get();
            if (sslDays < 30) score -= 10;
            if (sslDays < 7) score -= 20;
            
            // Deduct for high rate of blocked requests (potential attacks)
            const blockedRate = await this.getBlockedRequestRate();
            if (blockedRate > 0.1) score -= 10; // >10% blocked requests
            
            // Deduct for failed auth attempts
            const failedRate = await this.getFailedAuthRate();
            if (failedRate > 0.2) score -= 10; // >20% failed attempts
            
            // Keep score between 0-100
            score = Math.max(0, Math.min(100, score));
            metrics.securityScore.set(score);
            
            logger.info(`Security score updated: ${score}/100`);
        } catch (error) {
            logger.error(`Failed to update security score: ${error.message}`);
        }
    }

    // ========== INTERNET SECURITY: Update SSL Certificate ==========
    async updateSSLCertificateExpiry() {
        try {
            const https = require('https');
            const url = new URL(process.env.API_URL || 'https://localhost');
            
            const req = https.request({
                hostname: url.hostname,
                port: 443,
                method: 'GET',
                path: '/',
                rejectUnauthorized: false,
                agent: false,
                timeout: 5000
            }, (res) => {
                const cert = res.connection.getPeerCertificate();
                if (cert && cert.valid_to) {
                    const expiryDate = new Date(cert.valid_to);
                    const now = new Date();
                    const days = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
                    metrics.sslCertificateDaysRemaining.set(days);
                    logger.info(`SSL certificate expires in ${days} days`);
                }
            });
            
            req.on('error', () => {
                metrics.sslCertificateDaysRemaining.set(-1);
            });
            
            req.end();
        } catch (error) {
            logger.error(`SSL update failed: ${error.message}`);
        }
    }

    // ========== APP SECURITY: Update User Metrics ==========
    async updateUserMetrics() {
        try {
            // In production, query database
            const total = 1000; // Mock total users
            const mfaEnabled = 650; // Mock MFA users
            
            metrics.totalUsers.set(total);
            metrics.mfaEnabledUsers.set(mfaEnabled);
            
            logger.info(`User metrics: ${total} total, ${mfaEnabled} MFA enabled`);
        } catch (error) {
            logger.error(`Failed to update user metrics: ${error.message}`);
        }
    }

    // ========== CYBERSECURITY: Record Threat ==========
    recordThreat(threatType, severity, sourceIp) {
        metrics.threatsTotal.inc({
            threat_type: threatType,
            severity: severity,
            source_ip: sourceIp
        });
    }

    // ========== APP SECURITY: Record API Request ==========
    recordAPIRequest(method, endpoint, statusCode) {
        metrics.apiRequestsTotal.inc({
            method,
            endpoint,
            status_code: statusCode
        });
    }

    // ========== INTERNET SECURITY: Record Blocked Request ==========
    recordBlockedRequest(reason) {
        metrics.apiBlockedTotal.inc({ reason });
    }

    // ========== WEB SECURITY: Record Failed Auth ==========
    recordFailedAuth(email, ip) {
        metrics.authFailedTotal.inc({ email, ip });
    }

    // ========== APP SECURITY: Record Successful Auth ==========
    recordSuccessfulAuth(email) {
        metrics.authSuccessTotal.inc({ email });
    }

    // ========== APP SECURITY: Record Vulnerability ==========
    recordVulnerability(type) {
        metrics.owaspVulnerabilitiesTotal.inc({ vulnerability_type: type });
    }

    // ========== CYBERSECURITY: Record Incident ==========
    recordIncident(responseTime) {
        metrics.incidentResponseTime.observe(responseTime);
    }

    // ========== INTERNET SECURITY: Record Rate Limit Hit ==========
    recordRateLimitHit(endpoint, ip) {
        metrics.rateLimitHits.inc({ endpoint, ip });
    }

    // ========== APP SECURITY: Record Invalid Input ==========
    recordInvalidInput(inputType) {
        metrics.invalidInputsTotal.inc({ input_type: inputType });
    }

    // Helper methods (mock implementations)
    async getVulnerabilities() {
        return {
            critical: 0,
            high: 2,
            medium: 5,
            low: 10
        };
    }

    async getSecurityHeaders() {
        return {
            'X-Frame-Options': true,
            'X-Content-Type-Options': true,
            'X-XSS-Protection': true,
            'Strict-Transport-Security': true,
            'Content-Security-Policy': true,
            'Referrer-Policy': true
        };
    }

    async getBlockedRequestRate() {
        // Mock: get from database/Redis
        return 0.05;
    }

    async getFailedAuthRate() {
        // Mock: get from database/Redis
        return 0.15;
    }
}

// Export singleton
const metricsService = new MetricsService();
module.exports = { metrics, metricsService };
