/**
 * Authentication Routes
 * Register, login (SFA + MFA), and MFA setup
 */
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const CryptoService = require('../services/crypto.service');
const MFAService = require('../services/mfa.service');
const { authMiddleware } = require('../middleware/auth.middleware');

const SALT_ROUNDS = 12;

/**
 * POST /api/auth/register
 * Register new user with RSA keypair generation
 */
router.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Name, email, and password are required' });
        }

        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }

        // Check if user already exists
        const existingUser = await req.prisma.user.findUnique({
            where: { email }
        });

        if (existingUser) {
            return res.status(409).json({ error: 'Email already registered' });
        }

        // Hash password with bcrypt
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        // Generate RSA keypair
        const { publicKey, privateKey } = CryptoService.generateKeyPair();

        // Encrypt private key with password-derived key
        const encryptedKeyData = CryptoService.encryptPrivateKey(privateKey, password);

        // Create user
        const user = await req.prisma.user.create({
            data: {
                name,
                email,
                passwordHash,
                publicKeyPem: publicKey,
                encryptedPrivateKey: encryptedKeyData.encryptedPrivateKey,
                privateKeySalt: encryptedKeyData.salt,
                privateKeyIv: encryptedKeyData.iv,
                privateKeyTag: encryptedKeyData.tag,
                role: 'user'
            },
            select: {
                id: true,
                name: true,
                email: true,
                role: true,
                createdAt: true
            }
        });

        // Generate JWT token
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
        );

        res.status(201).json({
            message: 'Registration successful',
            user,
            token
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

/**
 * POST /api/auth/login
 * Single-factor login (password only)
 */
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        // Find user
        const user = await req.prisma.user.findUnique({
            where: { email }
        });

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password
        const passwordValid = await bcrypt.compare(password, user.passwordHash);
        if (!passwordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check if MFA is enabled
        if (user.totpEnabled) {
            // Return partial token for MFA step
            const partialToken = jwt.sign(
                { userId: user.id, requiresMFA: true },
                process.env.JWT_SECRET,
                { expiresIn: '5m' }
            );

            return res.json({
                requiresMFA: true,
                partialToken,
                message: 'MFA verification required'
            });
        }

        // Generate full JWT token
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
        );

        res.json({
            message: 'Login successful',
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            },
            token
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

/**
 * POST /api/auth/login/mfa
 * Complete login with MFA code
 */
router.post('/login/mfa', async (req, res) => {
    try {
        const { partialToken, totpCode } = req.body;

        if (!partialToken || !totpCode) {
            return res.status(400).json({ error: 'Partial token and TOTP code are required' });
        }

        // Verify partial token
        let decoded;
        try {
            decoded = jwt.verify(partialToken, process.env.JWT_SECRET);
        } catch (err) {
            return res.status(401).json({ error: 'Invalid or expired partial token' });
        }

        if (!decoded.requiresMFA) {
            return res.status(400).json({ error: 'Invalid partial token' });
        }

        // Get user
        const user = await req.prisma.user.findUnique({
            where: { id: decoded.userId }
        });

        if (!user || !user.totpSecret) {
            return res.status(401).json({ error: 'MFA not configured' });
        }

        // Verify TOTP code
        const isValid = MFAService.verifyToken(user.totpSecret, totpCode);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid TOTP code' });
        }

        // Generate full JWT token
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
        );

        res.json({
            message: 'MFA verification successful',
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            },
            token
        });
    } catch (error) {
        console.error('MFA login error:', error);
        res.status(500).json({ error: 'MFA verification failed' });
    }
});

/**
 * POST /api/auth/mfa/setup
 * Generate TOTP secret and QR code for MFA setup
 */
router.post('/mfa/setup', authMiddleware, async (req, res) => {
    try {
        const user = await req.prisma.user.findUnique({
            where: { id: req.user.id }
        });

        if (user.totpEnabled) {
            return res.status(400).json({ error: 'MFA is already enabled' });
        }

        // Generate TOTP secret
        const { base32, otpauth_url } = MFAService.generateSecret(user.email);

        // Store secret temporarily (will be confirmed on verify)
        await req.prisma.user.update({
            where: { id: req.user.id },
            data: { totpSecret: base32 }
        });

        // Generate QR code
        const qrCode = await MFAService.generateQRCode(otpauth_url);

        res.json({
            message: 'Scan this QR code with your authenticator app',
            secret: base32,
            qrCode
        });
    } catch (error) {
        console.error('MFA setup error:', error);
        res.status(500).json({ error: 'MFA setup failed' });
    }
});

/**
 * POST /api/auth/mfa/verify
 * Verify TOTP code and enable MFA
 */
router.post('/mfa/verify', authMiddleware, async (req, res) => {
    try {
        const { totpCode } = req.body;

        if (!totpCode) {
            return res.status(400).json({ error: 'TOTP code is required' });
        }

        const user = await req.prisma.user.findUnique({
            where: { id: req.user.id }
        });

        if (!user.totpSecret) {
            return res.status(400).json({ error: 'MFA setup not initiated' });
        }

        // Verify code
        const isValid = MFAService.verifyToken(user.totpSecret, totpCode);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid TOTP code' });
        }

        // Enable MFA
        await req.prisma.user.update({
            where: { id: req.user.id },
            data: { totpEnabled: true }
        });

        res.json({
            message: 'MFA enabled successfully',
            totpEnabled: true
        });
    } catch (error) {
        console.error('MFA verify error:', error);
        res.status(500).json({ error: 'MFA verification failed' });
    }
});

/**
 * POST /api/auth/mfa/disable
 * Disable MFA (requires password)
 */
router.post('/mfa/disable', authMiddleware, async (req, res) => {
    try {
        const { password } = req.body;

        if (!password) {
            return res.status(400).json({ error: 'Password is required' });
        }

        const user = await req.prisma.user.findUnique({
            where: { id: req.user.id }
        });

        // Verify password
        const passwordValid = await bcrypt.compare(password, user.passwordHash);
        if (!passwordValid) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Disable MFA
        await req.prisma.user.update({
            where: { id: req.user.id },
            data: {
                totpEnabled: false,
                totpSecret: null
            }
        });

        res.json({
            message: 'MFA disabled successfully',
            totpEnabled: false
        });
    } catch (error) {
        console.error('MFA disable error:', error);
        res.status(500).json({ error: 'Failed to disable MFA' });
    }
});

module.exports = router;
