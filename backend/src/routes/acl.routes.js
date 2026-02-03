/**
 * ACL Routes
 * View and manage Access Control Lists
 */
const express = require('express');
const router = express.Router();
const { authMiddleware } = require('../middleware/auth.middleware');

/**
 * GET /api/acl/:objectType/:objectId
 * Get ACL entries for an object
 */
router.get('/:objectType/:objectId', authMiddleware, async (req, res) => {
    try {
        const { objectType, objectId } = req.params;

        if (!['meeting', 'minutes'].includes(objectType)) {
            return res.status(400).json({ error: 'Invalid object type' });
        }

        // Check if user has access to view ACL
        let hasAccess = req.user.role === 'admin';

        if (!hasAccess) {
            if (objectType === 'meeting') {
                const meeting = await req.prisma.meeting.findUnique({
                    where: { id: objectId }
                });
                hasAccess = meeting?.createdById === req.user.id;
            } else if (objectType === 'minutes') {
                const minutes = await req.prisma.minutes.findUnique({
                    where: { id: objectId }
                });
                hasAccess = minutes?.createdById === req.user.id;
            }
        }

        if (!hasAccess) {
            return res.status(403).json({ error: 'Only owner or admin can view ACL' });
        }

        const aclEntries = await req.prisma.aCL.findMany({
            where: {
                objectType,
                objectId
            },
            include: {
                subject: {
                    select: { id: true, name: true, email: true, role: true }
                }
            }
        });

        // Format as matrix
        const subjects = [...new Set(aclEntries.map(e => e.subject.email))];
        const rightsTypes = ['read', 'write', 'approve', 'delete'];

        const matrix = aclEntries.map(entry => ({
            subject: entry.subject,
            subjectRole: entry.subjectRole,
            rights: entry.rights.split(','),
            rightsMatrix: rightsTypes.reduce((acc, right) => {
                acc[right] = entry.rights.includes(right);
                return acc;
            }, {})
        }));

        res.json({
            objectType,
            objectId,
            entries: aclEntries,
            matrix,
            rightsTypes
        });
    } catch (error) {
        console.error('Get ACL error:', error);
        res.status(500).json({ error: 'Failed to get ACL' });
    }
});

/**
 * POST /api/acl
 * Create or update ACL entry
 */
router.post('/', authMiddleware, async (req, res) => {
    try {
        const { subjectEmail, subjectRole, objectType, objectId, rights } = req.body;

        if (!objectType || !objectId || !rights) {
            return res.status(400).json({ error: 'Object type, object ID, and rights are required' });
        }

        if (!subjectEmail && !subjectRole) {
            return res.status(400).json({ error: 'Subject email or role is required' });
        }

        if (!['meeting', 'minutes'].includes(objectType)) {
            return res.status(400).json({ error: 'Invalid object type' });
        }

        // Check if user has permission to modify ACL
        let hasAccess = req.user.role === 'admin';

        if (!hasAccess) {
            if (objectType === 'meeting') {
                const meeting = await req.prisma.meeting.findUnique({
                    where: { id: objectId }
                });
                hasAccess = meeting?.createdById === req.user.id;
            } else if (objectType === 'minutes') {
                const minutes = await req.prisma.minutes.findUnique({
                    where: { id: objectId }
                });
                hasAccess = minutes?.createdById === req.user.id;
            }
        }

        if (!hasAccess) {
            return res.status(403).json({ error: 'Only owner or admin can modify ACL' });
        }

        // Get subject user
        let subjectId = null;
        if (subjectEmail) {
            const subject = await req.prisma.user.findUnique({
                where: { email: subjectEmail }
            });

            if (!subject) {
                return res.status(404).json({ error: 'Subject user not found' });
            }

            subjectId = subject.id;
        }

        // Validate rights
        const validRights = ['read', 'write', 'approve', 'delete'];
        const rightsArray = Array.isArray(rights) ? rights : rights.split(',');
        const invalidRights = rightsArray.filter(r => !validRights.includes(r.trim()));

        if (invalidRights.length > 0) {
            return res.status(400).json({ error: `Invalid rights: ${invalidRights.join(', ')}` });
        }

        const rightsString = rightsArray.map(r => r.trim()).join(',');

        // Upsert ACL entry
        if (subjectId) {
            const aclEntry = await req.prisma.aCL.upsert({
                where: {
                    subjectId_objectType_objectId: {
                        subjectId,
                        objectType,
                        objectId
                    }
                },
                update: {
                    rights: rightsString,
                    subjectRole
                },
                create: {
                    subjectId,
                    subjectRole,
                    objectType,
                    objectId,
                    rights: rightsString
                },
                include: {
                    subject: {
                        select: { id: true, name: true, email: true }
                    }
                }
            });

            res.json({
                message: 'ACL entry saved',
                entry: aclEntry
            });
        } else {
            // Role-based ACL (without specific user)
            res.status(400).json({ error: 'Role-based ACL without subject not yet implemented' });
        }
    } catch (error) {
        console.error('Create ACL error:', error);
        res.status(500).json({ error: 'Failed to create ACL entry' });
    }
});

/**
 * DELETE /api/acl/:id
 * Remove ACL entry
 */
router.delete('/:id', authMiddleware, async (req, res) => {
    try {
        const aclEntry = await req.prisma.aCL.findUnique({
            where: { id: req.params.id }
        });

        if (!aclEntry) {
            return res.status(404).json({ error: 'ACL entry not found' });
        }

        // Check permission to delete
        let hasAccess = req.user.role === 'admin';

        if (!hasAccess) {
            if (aclEntry.objectType === 'meeting') {
                const meeting = await req.prisma.meeting.findUnique({
                    where: { id: aclEntry.objectId }
                });
                hasAccess = meeting?.createdById === req.user.id;
            } else if (aclEntry.objectType === 'minutes') {
                const minutes = await req.prisma.minutes.findUnique({
                    where: { id: aclEntry.objectId }
                });
                hasAccess = minutes?.createdById === req.user.id;
            }
        }

        if (!hasAccess) {
            return res.status(403).json({ error: 'Only owner or admin can remove ACL entries' });
        }

        await req.prisma.aCL.delete({
            where: { id: req.params.id }
        });

        res.json({ message: 'ACL entry removed' });
    } catch (error) {
        console.error('Delete ACL error:', error);
        res.status(500).json({ error: 'Failed to delete ACL entry' });
    }
});

/**
 * GET /api/acl/matrix/:objectType/:objectId
 * Get ACL as a visual matrix format
 */
router.get('/matrix/:objectType/:objectId', authMiddleware, async (req, res) => {
    try {
        const { objectType, objectId } = req.params;

        const aclEntries = await req.prisma.aCL.findMany({
            where: {
                objectType,
                objectId
            },
            include: {
                subject: {
                    select: { name: true, email: true, role: true }
                }
            }
        });

        const rightsTypes = ['read', 'write', 'approve', 'delete'];

        // Build matrix
        const matrix = {
            headers: ['Subject', 'Role', ...rightsTypes],
            rows: aclEntries.map(entry => ({
                subject: entry.subject.name,
                email: entry.subject.email,
                role: entry.subject.role,
                rights: rightsTypes.map(right => entry.rights.includes(right))
            }))
        };

        res.json(matrix);
    } catch (error) {
        console.error('Get ACL matrix error:', error);
        res.status(500).json({ error: 'Failed to get ACL matrix' });
    }
});

module.exports = router;
