// ========== APP SECURITY: Memory-safe Scanner ==========
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub severity: Severity,
    pub description: String,
    pub location: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

// ========== WEB SECURITY: XSS Scanner ==========
pub struct XSSScanner {
    patterns: Vec<Regex>,
    blacklist: HashSet<String>,
}

impl XSSScanner {
    pub fn new() -> Self {
        let patterns = vec![
            Regex::new(r"<script.*?>.*?</script>").unwrap(),
            Regex::new(r"on\w+\s*=").unwrap(),
            Regex::new(r"javascript:").unwrap(),
            Regex::new(r"<.*?eval\s*\(").unwrap(),
            Regex::new(r"<.*?alert\s*\(").unwrap(),
        ];
        
        let mut blacklist = HashSet::new();
        blacklist.insert("javascript".to_string());
        blacklist.insert("vbscript".to_string());
        blacklist.insert("onerror".to_string());
        blacklist.insert("onload".to_string());
        
        XSSScanner { patterns, blacklist }
    }
    
    // ========== WEB SECURITY: Scan for XSS ==========
    pub fn scan(&self, input: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for pattern in &self.patterns {
            if pattern.is_match(input) {
                vulnerabilities.push(Vulnerability {
                    id: "XSS-001".to_string(),
                    severity: Severity::High,
                    description: format!("Potential XSS found: {}", pattern.as_str()),
                    location: "User input".to_string(),
                    recommendation: "Use output encoding and input validation".to_string(),
                });
                break;
            }
        }
        
        // Check for blacklisted attributes
        for word in &self.blacklist {
            if input.to_lowercase().contains(word) {
                vulnerabilities.push(Vulnerability {
                    id: "XSS-002".to_string(),
                    severity: Severity::Medium,
                    description: format!("Suspicious attribute: {}", word),
                    location: "HTML attribute".to_string(),
                    recommendation: "Use safe HTML attributes and CSP".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}

// ========== APP SECURITY: SQL Injection Scanner ==========
pub struct SQLiScanner {
    patterns: Vec<Regex>,
}

impl SQLiScanner {
    pub fn new() -> Self {
        let patterns = vec![
            Regex::new(r"(?i)(union\s+select)").unwrap(),
            Regex::new(r"(?i)(or\s+1\s*=\s*1)").unwrap(),
            Regex::new(r"(?i)(drop\s+table)").unwrap(),
            Regex::new(r"(?i)(--\s*$)").unwrap(),
            Regex::new(r"(?i)(;\s*--)").unwrap(),
            Regex::new(r"(?i)('|\")\s*or\s*('|\")\s*=\s*('|\")").unwrap(),
        ];
        SQLiScanner { patterns }
    }
    
    pub fn scan(&self, input: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for pattern in &self.patterns {
            if pattern.is_match(input) {
                vulnerabilities.push(Vulnerability {
                    id: "SQL-001".to_string(),
                    severity: Severity::Critical,
                    description: format!("SQL Injection pattern detected: {}", pattern.as_str()),
                    location: "SQL query".to_string(),
                    recommendation: "Use parameterized queries/prepared statements".to_string(),
                });
                break;
            }
        }
        
        vulnerabilities
    }
}

// ========== INTERNET SECURITY: SSL/TLS Scanner ==========
pub struct TLSScanner {
    weak_ciphers: HashSet<String>,
}

impl TLSScanner {
    pub fn new() -> Self {
        let mut weak = HashSet::new();
        weak.insert("TLSv1.0".to_string());
        weak.insert("TLSv1.1".to_string());
        weak.insert("SSLv3".to_string());
        weak.insert("RC4".to_string());
        weak.insert("3DES".to_string());
        TLSScanner { weak_ciphers }
    }
    
    pub async fn scan_endpoint(&self, host: &str) -> Vec<Vulnerability> {
        // Simulate TLS scan
        let mut vulns = Vec::new();
        
        // Check for weak protocols
        for cipher in &self.weak_ciphers {
            vulns.push(Vulnerability {
                id: "TLS-001".to_string(),
                severity: Severity::High,
                description: format!("Weak cipher/protocol supported: {}", cipher),
                location: host.to_string(),
                recommendation: "Disable old TLS versions and weak ciphers".to_string(),
            });
        }
        
        // Check for missing HSTS
        vulns.push(Vulnerability {
            id: "TLS-002".to_string(),
            severity: Severity::Medium,
            description: "HSTS header not detected".to_string(),
            location: host.to_string(),
            recommendation: "Enable HSTS to enforce HTTPS".to_string(),
        });
        
        vulns
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_xss_scanner() {
        let scanner = XSSScanner::new();
        let input = "<script>alert('xss')</script>";
        let vulns = scanner.scan(input);
        assert!(!vulns.is_empty());
    }
    
    #[test]
    fn test_sqli_scanner() {
        let scanner = SQLiScanner::new();
        let input = "' OR '1'='1' --";
        let vulns = scanner.scan(input);
        assert!(!vulns.is_empty());
    }
                       }
