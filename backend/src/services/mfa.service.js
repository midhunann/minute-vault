/**
 * MFA Service
 * Handles TOTP-based multi-factor authentication
 */
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

class MFAService {
    /**
     * Generate a new TOTP secret for a user
     */
    static generateSecret(email) {
        const secret = speakeasy.generateSecret({
            length: 20,
            name: `MinuteVault:${email}`,
            issuer: 'MinuteVault'
        });

        return {
            base32: secret.base32,
            otpauth_url: secret.otpauth_url
        };
    }

    /**
     * Generate QR code from otpauth URL
     */
    static async generateQRCode(otpauthUrl) {
        try {
            const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);
            return qrCodeDataUrl;
        } catch (error) {
            throw new Error('Failed to generate QR code');
        }
    }

    /**
     * Verify a TOTP token
     */
    static verifyToken(secret, token) {
        return speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token,
            window: 1 // Allow 1 step before/after for clock drift
        });
    }

    /**
     * Generate current TOTP (for testing purposes)
     */
    static generateToken(secret) {
        return speakeasy.totp({
            secret: secret,
            encoding: 'base32'
        });
    }
}

module.exports = MFAService;
