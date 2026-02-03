/**
 * Meeting Routes
 * Create and list meetings
 */
const express = require('express');
const router = express.Router();
const { authMiddleware } = require('../middleware/auth.middleware');

/**
 * GET /api/meetings
 * List all meetings user has access to
 */
router.get('/', authMiddleware, async (req, res) => {
    try {
        // Get meetings user created
        const ownMeetings = await req.prisma.meeting.findMany({
            where: { createdById: req.user.id },
            include: {
                createdBy: {
                    select: { id: true, name: true, email: true }
                },
                minutes: {
                    select: { id: true, status: true, createdAt: true }
                }
            },
            orderBy: { createdAt: 'desc' }
        });

        // Get meetings user has ACL access to
        const aclEntries = await req.prisma.aCL.findMany({
            where: {
                subjectId: req.user.id,
                objectType: 'meeting'
            }
        });

        const aclMeetingIds = aclEntries.map(acl => acl.objectId);

        const sharedMeetings = await req.prisma.meeting.findMany({
            where: {
                id: { in: aclMeetingIds },
                createdById: { not: req.user.id }
            },
            include: {
                createdBy: {
                    select: { id: true, name: true, email: true }
                },
                minutes: {
                    select: { id: true, status: true, createdAt: true }
                }
            },
            orderBy: { createdAt: 'desc' }
        });

        res.json({
            ownMeetings,
            sharedMeetings
        });
    } catch (error) {
        console.error('List meetings error:', error);
        res.status(500).json({ error: 'Failed to list meetings' });
    }
});

/**
 * GET /api/meetings/:id
 * Get single meeting details
 */
router.get('/:id', authMiddleware, async (req, res) => {
    try {
        const meeting = await req.prisma.meeting.findUnique({
            where: { id: req.params.id },
            include: {
                createdBy: {
                    select: { id: true, name: true, email: true }
                },
                minutes: {
                    include: {
                        createdBy: {
                            select: { id: true, name: true, email: true }
                        },
                        approvals: {
                            include: {
                                approver: {
                                    select: { id: true, name: true, email: true }
                                }
                            }
                        }
                    }
                }
            }
        });

        if (!meeting) {
            return res.status(404).json({ error: 'Meeting not found' });
        }

        // Check access
        const hasAccess = meeting.createdById === req.user.id ||
            req.user.role === 'admin' ||
            await req.prisma.aCL.findFirst({
                where: {
                    subjectId: req.user.id,
                    objectType: 'meeting',
                    objectId: meeting.id
                }
            });

        if (!hasAccess) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Get participants (users with ACL access)
        const participants = await req.prisma.aCL.findMany({
            where: {
                objectType: 'meeting',
                objectId: meeting.id
            },
            include: {
                subject: {
                    select: { id: true, name: true, email: true }
                }
            }
        });

        res.json({
            ...meeting,
            participants: participants.map(p => ({
                ...p.subject,
                rights: p.rights
            }))
        });
    } catch (error) {
        console.error('Get meeting error:', error);
        res.status(500).json({ error: 'Failed to get meeting' });
    }
});

/**
 * POST /api/meetings
 * Create a new meeting
 */
router.post('/', authMiddleware, async (req, res) => {
    try {
        const { title, description, participants } = req.body;

        if (!title) {
            return res.status(400).json({ error: 'Title is required' });
        }

        // Create meeting
        const meeting = await req.prisma.meeting.create({
            data: {
                title,
                description: description || '',
                createdById: req.user.id
            }
        });

        // Create ACL entry for creator (full access)
        await req.prisma.aCL.create({
            data: {
                subjectId: req.user.id,
                objectType: 'meeting',
                objectId: meeting.id,
                rights: 'read,write,approve,delete'
            }
        });

        // Add participants if provided
        if (participants && Array.isArray(participants)) {
            for (const participant of participants) {
                const user = await req.prisma.user.findUnique({
                    where: { email: participant.email }
                });

                if (user && user.id !== req.user.id) {
                    await req.prisma.aCL.create({
                        data: {
                            subjectId: user.id,
                            objectType: 'meeting',
                            objectId: meeting.id,
                            rights: participant.rights || 'read'
                        }
                    });
                }
            }
        }

        res.status(201).json({
            message: 'Meeting created successfully',
            meeting
        });
    } catch (error) {
        console.error('Create meeting error:', error);
        res.status(500).json({ error: 'Failed to create meeting' });
    }
});

/**
 * DELETE /api/meetings/:id
 * Delete a meeting
 */
router.delete('/:id', authMiddleware, async (req, res) => {
    try {
        const meeting = await req.prisma.meeting.findUnique({
            where: { id: req.params.id }
        });

        if (!meeting) {
            return res.status(404).json({ error: 'Meeting not found' });
        }

        // Check ownership or admin
        if (meeting.createdById !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Only the owner can delete this meeting' });
        }

        // Delete related ACL entries
        await req.prisma.aCL.deleteMany({
            where: {
                objectType: 'meeting',
                objectId: req.params.id
            }
        });

        // Delete meeting (cascades to minutes, wrapped keys, approvals)
        await req.prisma.meeting.delete({
            where: { id: req.params.id }
        });

        res.json({ message: 'Meeting deleted successfully' });
    } catch (error) {
        console.error('Delete meeting error:', error);
        res.status(500).json({ error: 'Failed to delete meeting' });
    }
});

module.exports = router;
