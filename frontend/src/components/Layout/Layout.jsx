import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import './Layout.css';

export default function Layout({ children }) {
    const { user, logout } = useAuth();
    const navigate = useNavigate();

    const handleLogout = () => {
        logout();
        navigate('/login');
    };

    return (
        <div className="layout">
            <nav className="navbar">
                <div className="container navbar-content">
                    <Link to="/" className="navbar-brand">
                        <div className="brand-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M12 2L2 7l10 5 10-5-10-5z" />
                                <path d="M2 17l10 5 10-5" />
                                <path d="M2 12l10 5 10-5" />
                            </svg>
                        </div>
                        <span className="brand-text">MinuteVault</span>
                    </Link>

                    {user && (
                        <div className="navbar-nav">
                            <Link to="/dashboard" className="nav-link">Dashboard</Link>
                            <Link to="/meetings/new" className="nav-link">New Meeting</Link>
                            <Link to="/profile" className="nav-link">Profile</Link>
                        </div>
                    )}

                    <div className="navbar-actions">
                        {user ? (
                            <div className="user-menu">
                                <span className="user-name">{user.name}</span>
                                <span className={`role-badge ${user.role}`}>{user.role}</span>
                                <button onClick={handleLogout} className="btn btn-ghost btn-sm">
                                    Logout
                                </button>
                            </div>
                        ) : (
                            <div className="auth-buttons">
                                <Link to="/login" className="btn btn-ghost btn-sm">Login</Link>
                                <Link to="/register" className="btn btn-primary btn-sm">Sign Up</Link>
                            </div>
                        )}
                    </div>
                </div>
            </nav>

            <main className="main-content">
                {children}
            </main>

            <footer className="footer">
                <div className="container footer-content">
                    <p>&copy; 2026 MinuteVault. Secure Digital Meeting Minutes.</p>
                    <div className="footer-badges">
                        <span className="encryption-indicator">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                            </svg>
                            AES-256-GCM Encrypted
                        </span>
                        <span className="encryption-indicator">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            </svg>
                            RSA-2048 Signed
                        </span>
                    </div>
                </div>
            </footer>
        </div>
    );
}
