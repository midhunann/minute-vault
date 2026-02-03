/**
 * User Routes
 * User profile and public key access
 */
const express = require('express');
const router = express.Router();
const { authMiddleware } = require('../middleware/auth.middleware');

/**
 * GET /api/users/me
 * Get current user profile
 */
router.get('/me', authMiddleware, async (req, res) => {
    try {
        const user = await req.prisma.user.findUnique({
            where: { id: req.user.id },
            select: {
                id: true,
                name: true,
                email: true,
                role: true,
                publicKeyPem: true,
                totpEnabled: true,
                createdAt: true
            }
        });

        res.json(user);
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ error: 'Failed to get profile' });
    }
});

/**
 * GET /api/users/:id/public-key
 * Get user's public key (for encryption/verification)
 */
router.get('/:id/public-key', authMiddleware, async (req, res) => {
    try {
        const user = await req.prisma.user.findUnique({
            where: { id: req.params.id },
            select: {
                id: true,
                name: true,
                email: true,
                publicKeyPem: true
            }
        });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            id: user.id,
            name: user.name,
            email: user.email,
            publicKey: user.publicKeyPem
        });
    } catch (error) {
        console.error('Get public key error:', error);
        res.status(500).json({ error: 'Failed to get public key' });
    }
});

/**
 * GET /api/users
 * List all users (for adding participants)
 */
router.get('/', authMiddleware, async (req, res) => {
    try {
        const users = await req.prisma.user.findMany({
            where: {
                id: { not: req.user.id }
            },
            select: {
                id: true,
                name: true,
                email: true,
                role: true
            },
            orderBy: { name: 'asc' }
        });

        res.json(users);
    } catch (error) {
        console.error('List users error:', error);
        res.status(500).json({ error: 'Failed to list users' });
    }
});

/**
 * PUT /api/users/me
 * Update current user profile
 */
router.put('/me', authMiddleware, async (req, res) => {
    try {
        const { name } = req.body;

        const updatedUser = await req.prisma.user.update({
            where: { id: req.user.id },
            data: { name },
            select: {
                id: true,
                name: true,
                email: true,
                role: true
            }
        });

        res.json(updatedUser);
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

module.exports = router;
