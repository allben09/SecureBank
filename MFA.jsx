import React, { useState, useEffect } from 'react';
import api from '../services/api';
import { QRCodeCanvas } from 'qrcode.react';
import './MFA.css';

const MFAComponent = () => {
    const [mfaStatus, setMfaStatus] = useState({ enabled: false, backupCodesRemaining: 0 });
    const [qrCode, setQrCode] = useState(null);
    const [backupCodes, setBackupCodes] = useState([]);
    const [verificationCode, setVerificationCode] = useState('');
    const [message, setMessage] = useState('');
    const [loading, setLoading] = useState(false);
    const [showBackupCodes, setShowBackupCodes] = useState(false);

    useEffect(() => {
        fetchMFAStatus();
    }, []);

    const fetchMFAStatus = async () => {
        try {
            const response = await api.get('/api/mfa/status');
            setMfaStatus(response.data);
        } catch (error) {
            console.error('Failed to fetch MFA status:', error);
        }
    };

    const enableMFA = async () => {
        setLoading(true);
        try {
            const response = await api.post('/api/mfa/enable');
            setQrCode(response.data.qrCode);
            setBackupCodes(response.data.backupCodes);
            setShowBackupCodes(true);
            setMessage({ type: 'success', text: 'Scan QR code with your authenticator app' });
        } catch (error) {
            setMessage({ type: 'error', text: 'Failed to enable MFA' });
        } finally {
            setLoading(false);
        }
    };

    const verifyMFA = async () => {
        if (!verificationCode) {
            setMessage({ type: 'error', text: 'Please enter verification code' });
            return;
        }

        setLoading(true);
        try {
            await api.post('/api/mfa/verify-setup', { token: verificationCode });
            setMessage({ type: 'success', text: 'MFA enabled successfully!' });
            setQrCode(null);
            setShowBackupCodes(false);
            fetchMFAStatus();
        } catch (error) {
            setMessage({ type: 'error', text: error.response?.data?.error || 'Invalid code' });
        } finally {
            setLoading(false);
        }
    };

    const disableMFA = async () => {
        if (!window.confirm('Are you sure you want to disable MFA?')) return;

        try {
            await api.post('/api/mfa/disable');
            setMessage({ type: 'success', text: 'MFA disabled successfully' });
            fetchMFAStatus();
        } catch (error) {
            setMessage({ type: 'error', text: 'Failed to disable MFA' });
        }
    };

    return (
        <div className="mfa-container">
            <h2>🔐 Two-Factor Authentication</h2>
            
            {message && (
                <div className={`message ${message.type}`}>
                    {message.text}
                </div>
            )}

            <div className="mfa-status">
                <p>Status: <strong>{mfaStatus.enabled ? '✅ Enabled' : '❌ Disabled'}</strong></p>
                {mfaStatus.enabled && (
                    <p>Backup codes remaining: <strong>{mfaStatus.backupCodesRemaining}</strong></p>
                )}
            </div>

            {!mfaStatus.enabled ? (
                <div className="mfa-setup">
                    <button onClick={enableMFA} disabled={loading}>
                        {loading ? 'Generating...' : 'Enable 2FA'}
                    </button>

                    {qrCode && (
                        <div className="qr-section">
                            <h3>Scan with Authenticator App</h3>
                            <QRCodeCanvas value={qrCode} size={250} level="H" />
                            <p>Use Google Authenticator, Authy, or Microsoft Authenticator</p>
                            
                            {showBackupCodes && (
                                <div className="backup-codes">
                                    <h4>⚠️ Save these backup codes!</h4>
                                    <p>Use these if you lose access to your authenticator app.</p>
                                    <div className="codes-grid">
                                        {backupCodes.map((code, index) => (
                                            <span key={index} className="backup-code">{code}</span>
                                        ))}
                                    </div>
                                    <button onClick={() => {
                                        navigator.clipboard.writeText(backupCodes.join('\n'));
                                        setMessage({ type: 'success', text: 'Backup codes copied!' });
                                    }}>
                                        Copy Codes
                                    </button>
                                </div>
                            )}

                            <div className="verify-section">
                                <h4>Verify Setup</h4>
                                <input
                                    type="text"
                                    placeholder="Enter 6-digit code"
                                    value={verificationCode}
                                    onChange={(e) => setVerificationCode(e.target.value)}
                                    maxLength="6"
                                />
                                <button onClick={verifyMFA} disabled={loading}>
                                    {loading ? 'Verifying...' : 'Verify & Enable'}
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            ) : (
                <div className="mfa-actions">
                    <button onClick={disableMFA} className="danger">
                        Disable 2FA
                    </button>
                    <button onClick={() => {
                        setShowBackupCodes(!showBackupCodes);
                    }}>
                        {showBackupCodes ? 'Hide' : 'Show'} Backup Codes
                    </button>
                </div>
            )}
        </div>
    );
};

export default MFAComponent;
