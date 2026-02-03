#!/bin/bash

# Commit each file individually with conventional commit messages
# Run after: git init && git add -A

git reset

# Documentation
git add README && git commit -m "docs: add project documentation and overview"
git add .gitignore && git commit -m "chore: add gitignore for node modules and environment files"

# Backend - Configuration
git add backend/package.json && git commit -m "chore(backend): add dependencies and project configuration"
git add backend/prisma/schema.prisma && git commit -m "feat(backend): add database schema with User, Meeting, Minutes, ACL, WrappedKey, and Approval models"
git add backend/prisma/migrations/migration_lock.toml && git commit -m "chore(backend): add prisma migration lock file"
git add backend/prisma/migrations/20260202153433_init/migration.sql && git commit -m "feat(backend): add initial database migration script"

# Backend - Core Services
git add backend/src/services/crypto.service.js && git commit -m "feat(backend): implement cryptography service with RSA-2048, AES-256-GCM, PBKDF2, and RSA-PSS signatures"
git add backend/src/services/mfa.service.js && git commit -m "feat(backend): implement TOTP-based multi-factor authentication with QR code generation"

# Backend - Middleware
git add backend/src/middleware/auth.middleware.js && git commit -m "feat(backend): add JWT authentication middleware"
git add backend/src/middleware/acl.middleware.js && git commit -m "feat(backend): implement Access Control List middleware for authorization"

# Backend - Routes
git add backend/src/routes/auth.routes.js && git commit -m "feat(backend): add authentication routes with SFA, MFA, registration, and login"
git add backend/src/routes/user.routes.js && git commit -m "feat(backend): add user management routes"
git add backend/src/routes/meeting.routes.js && git commit -m "feat(backend): add meeting CRUD routes with ACL support"
git add backend/src/routes/acl.routes.js && git commit -m "feat(backend): add ACL management routes for access control matrix"
git add backend/src/routes/minutes.routes.js && git commit -m "feat(backend): implement encrypted minutes with hybrid encryption, digital signatures, approval workflow, and public verification"

# Backend - Main
git add backend/src/index.js && git commit -m "feat(backend): configure Express server with security middleware, CORS, rate limiting, and API routes"

# Frontend - Configuration
git add frontend/package.json && git commit -m "chore(frontend): add React dependencies and build configuration"
git add frontend/vite.config.js && git commit -m "chore(frontend): configure Vite build tool"
git add frontend/eslint.config.js && git commit -m "chore(frontend): add ESLint configuration"
git add frontend/index.html && git commit -m "chore(frontend): add HTML entry point"
git add frontend/README.md && git commit -m "docs(frontend): add React frontend documentation"

# Frontend - Core
git add frontend/src/main.jsx && git commit -m "feat(frontend): configure React application entry point"
git add frontend/src/App.jsx && git commit -m "feat(frontend): add main App component with routing"
git add frontend/src/index.css && git commit -m "style(frontend): add global CSS styles"

# Frontend - Context
git add frontend/src/context/AuthContext.jsx && git commit -m "feat(frontend): implement authentication context with JWT and user state management"

# Frontend - Services
git add frontend/src/services/api.js && git commit -m "feat(frontend): add API service with Axios for backend communication"

# Frontend - Layout
git add frontend/src/components/Layout/Layout.jsx && git commit -m "feat(frontend): add layout component with navigation"
git add frontend/src/components/Layout/Layout.css && git commit -m "style(frontend): add layout styles"

# Frontend - Auth Pages
git add frontend/src/pages/Auth/Login.jsx && git commit -m "feat(frontend): add login page with SFA and MFA support"
git add frontend/src/pages/Auth/Register.jsx && git commit -m "feat(frontend): add user registration page"
git add frontend/src/pages/Auth/Auth.css && git commit -m "style(frontend): add authentication page styles"

# Frontend - Dashboard
git add frontend/src/pages/Dashboard/Dashboard.jsx && git commit -m "feat(frontend): add dashboard with meetings overview"
git add frontend/src/pages/Dashboard/Dashboard.css && git commit -m "style(frontend): add dashboard styles"

# Frontend - Meeting Pages
git add frontend/src/pages/Meeting/CreateMeeting.jsx && git commit -m "feat(frontend): add meeting creation with ACL participant management"
git add frontend/src/pages/Meeting/MeetingDetail.jsx && git commit -m "feat(frontend): add meeting detail view with ACL matrix display"
git add frontend/src/pages/Meeting/Meeting.css && git commit -m "style(frontend): add meeting page styles"

# Frontend - Minutes Pages
git add frontend/src/pages/Minutes/CreateMinutes.jsx && git commit -m "feat(frontend): add encrypted minutes creation with hybrid cryptography"
git add frontend/src/pages/Minutes/MinutesDetail.jsx && git commit -m "feat(frontend): add minutes detail view with decryption and approval"
git add frontend/src/pages/Minutes/VerifyMinutes.jsx && git commit -m "feat(frontend): add public minutes verification with QR code support"
git add frontend/src/pages/Minutes/Minutes.css && git commit -m "style(frontend): add minutes page styles"

# Frontend - Profile
git add frontend/src/pages/Profile/Profile.jsx && git commit -m "feat(frontend): add user profile with MFA setup and QR code display"
git add frontend/src/pages/Profile/Profile.css && git commit -m "style(frontend): add profile page styles"

# Testing & Documentation
git add test-all.sh && git commit -m "test: add comprehensive automated test suite with 42 security tests"
git add demo.sh && git commit -m "docs: add interactive demonstration script for lab evaluation"
git add TESTING_GUIDE.md && git commit -m "docs: add comprehensive testing guide with 50+ test cases"
git add VIVA_PREPARATION.md && git commit -m "docs: add viva preparation guide with Q&A and attack scenarios"
git add TEST_RESULTS.md && git commit -m "docs: add test results documentation with 100% pass rate"

# Final commit script
git add commit-all.sh && git commit -m "chore: add conventional commit automation script"

echo ""
echo "✓ All files committed individually with conventional commit messages"
echo ""
echo "Next steps:"
echo "  1. git remote add origin <your-github-repo-url>"
echo "  2. git branch -M main"
echo "  3. git push -u origin main"
