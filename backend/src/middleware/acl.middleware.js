/**
 * ACL Middleware
 * Enforces Access Control List permissions
 */

/**
 * Check if user has required rights on an object
 */
const checkACL = (objectType, requiredRights) => {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                return res.status(401).json({ error: 'Authentication required' });
            }

            // Admin bypass - admins have full access
            if (req.user.role === 'admin') {
                return next();
            }

            const objectId = req.params.id || req.params.objectId;

            if (!objectId) {
                return res.status(400).json({ error: 'Object ID required' });
            }

            // Check ACL entry for this user + object
            const aclEntry = await req.prisma.aCL.findFirst({
                where: {
                    subjectId: req.user.id,
                    objectType: objectType,
                    objectId: objectId
                }
            });

            // Also check role-based ACL
            const roleACL = await req.prisma.aCL.findFirst({
                where: {
                    subjectRole: req.user.role,
                    objectType: objectType,
                    objectId: objectId
                }
            });

            const userRights = aclEntry?.rights?.split(',') || [];
            const roleRights = roleACL?.rights?.split(',') || [];
            const allRights = [...new Set([...userRights, ...roleRights])];

            // Check if user has all required rights
            const hasAllRights = requiredRights.every(right => allRights.includes(right));

            if (!hasAllRights) {
                return res.status(403).json({
                    error: 'Access denied',
                    required: requiredRights,
                    available: allRights
                });
            }

            req.userRights = allRights;
            next();
        } catch (error) {
            console.error('ACL middleware error:', error);
            res.status(500).json({ error: 'Authorization check failed' });
        }
    };
};

/**
 * Check ownership - user must be the creator of the object
 */
const checkOwnership = (objectType) => {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                return res.status(401).json({ error: 'Authentication required' });
            }

            // Admin bypass
            if (req.user.role === 'admin') {
                return next();
            }

            const objectId = req.params.id;
            let isOwner = false;

            if (objectType === 'meeting') {
                const meeting = await req.prisma.meeting.findUnique({
                    where: { id: objectId }
                });
                isOwner = meeting?.createdById === req.user.id;
            } else if (objectType === 'minutes') {
                const minutes = await req.prisma.minutes.findUnique({
                    where: { id: objectId }
                });
                isOwner = minutes?.createdById === req.user.id;
            }

            if (!isOwner) {
                return res.status(403).json({ error: 'Only the owner can perform this action' });
            }

            next();
        } catch (error) {
            console.error('Ownership check error:', error);
            res.status(500).json({ error: 'Ownership check failed' });
        }
    };
};

module.exports = { checkACL, checkOwnership };
