const express = require('express');
const mfaService = require('../services/mfa');
const { authenticate } = require('../middleware/auth');
const { body, validationResult } = require('express-validator');
const logger = require('../utils/logger');
const router = express.Router();

// ========== APP SECURITY: Enable MFA ==========
router.post('/enable', authenticate, async (req, res) => {
    try {
        const email = req.user.email;
        const secret = mfaService.generateSecret(email);
        const qrData = await mfaService.generateQRCode(email);
        const backupCodes = mfaService.generateBackupCodes(email);

        res.json({
            success: true,
            secret: secret.base32,
            qrCode: qrData.qrCode,
            backupCodes: backupCodes,
            message: 'Scan QR code with authenticator app'
        });
    } catch (error) {
        logger.error(`MFA enable error: ${error.message}`);
        res.status(500).json({ error: 'Failed to enable MFA' });
    }
});

// ========== APP SECURITY: Verify MFA Setup ==========
router.post('/verify-setup', authenticate, [
    body('token').isLength({ min: 6, max: 6 }).isNumeric()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const email = req.user.email;
        const { token } = req.body;
        
        const result = mfaService.verifyTOTP(email, token);
        if (!result.valid) {
            return res.status(401).json({ error: result.error });
        }

        // In production: Update user record in DB
        res.json({
            success: true,
            message: 'MFA enabled successfully'
        });
    } catch (error) {
        logger.error(`MFA verification error: ${error.message}`);
        res.status(500).json({ error: 'Verification failed' });
    }
});

// ========== APP SECURITY: Login with MFA ==========
router.post('/verify-login', [
    body('email').isEmail(),
    body('token').isLength({ min: 6, max: 6 }).isNumeric()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { email, token, backupCode } = req.body;
        let verified = false;
        let method = '';

        // Try TOTP first
        const totpResult = mfaService.verifyTOTP(email, token);
        if (totpResult.valid) {
            verified = true;
            method = 'TOTP';
        }

        // Try backup code if TOTP failed
        if (!verified && backupCode) {
            const backupResult = mfaService.verifyBackupCode(email, backupCode);
            if (backupResult.valid) {
                verified = true;
                method = 'Backup Code';
            }
        }

        if (!verified) {
            return res.status(401).json({ 
                error: 'Invalid MFA code. Check authenticator app or use backup code.' 
            });
        }

        // Generate JWT after MFA verification
        const jwt = require('jsonwebtoken');
        const token_jwt = jwt.sign(
            { email, mfa_verified: true },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({
            success: true,
            token: token_jwt,
            method: method,
            message: 'MFA verification successful'
        });
    } catch (error) {
        logger.error(`MFA login error: ${error.message}`);
        res.status(500).json({ error: 'MFA verification failed' });
    }
});

// ========== APP SECURITY: Disable MFA ==========
router.post('/disable', authenticate, async (req, res) => {
    try {
        const email = req.user.email;
        const result = mfaService.disableMFA(email);
        res.json(result);
    } catch (error) {
        logger.error(`MFA disable error: ${error.message}`);
        res.status(500).json({ error: 'Failed to disable MFA' });
    }
});

// ========== APP SECURITY: Get MFA Status ==========
router.get('/status', authenticate, async (req, res) => {
    try {
        const email = req.user.email;
        const hasMFA = mfaService.secrets.has(email);
        const backupCount = mfaService.backupCodes.get(email)?.remaining || 0;
        
        res.json({
            enabled: hasMFA,
            backupCodesRemaining: backupCount,
            email: email
        });
    } catch (error) {
        logger.error(`MFA status error: ${error.message}`);
        res.status(500).json({ error: 'Failed to get MFA status' });
    }
});

module.exports = router;
