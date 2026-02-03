import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { authAPI } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import './Auth.css';

export default function Login() {
    const navigate = useNavigate();
    const { login } = useAuth();
    const [formData, setFormData] = useState({ email: '', password: '' });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [mfaRequired, setMfaRequired] = useState(false);
    const [partialToken, setPartialToken] = useState('');
    const [totpCode, setTotpCode] = useState('');

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
        setError('');
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            const res = await authAPI.login(formData);

            if (res.data.requiresMFA) {
                setMfaRequired(true);
                setPartialToken(res.data.partialToken);
            } else {
                login(res.data.user, res.data.token);
                navigate('/dashboard');
            }
        } catch (err) {
            setError(err.response?.data?.error || 'Login failed');
        } finally {
            setLoading(false);
        }
    };

    const handleMFASubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            const res = await authAPI.loginMFA({ partialToken, totpCode });
            login(res.data.user, res.data.token);
            navigate('/dashboard');
        } catch (err) {
            setError(err.response?.data?.error || 'MFA verification failed');
        } finally {
            setLoading(false);
        }
    };

    if (mfaRequired) {
        return (
            <div className="auth-page">
                <div className="auth-container">
                    <div className="auth-card glass-card">
                        <div className="auth-header">
                            <div className="auth-icon mfa">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                                </svg>
                            </div>
                            <h1>Two-Factor Authentication</h1>
                            <p>Enter the code from your authenticator app</p>
                        </div>

                        {error && <div className="alert alert-error">{error}</div>}

                        <form onSubmit={handleMFASubmit}>
                            <div className="form-group">
                                <label className="form-label">Authentication Code</label>
                                <input
                                    type="text"
                                    name="totpCode"
                                    value={totpCode}
                                    onChange={(e) => setTotpCode(e.target.value)}
                                    className="form-input totp-input"
                                    placeholder="000000"
                                    maxLength={6}
                                    pattern="[0-9]*"
                                    autoComplete="one-time-code"
                                    autoFocus
                                    required
                                />
                            </div>

                            <button type="submit" className="btn btn-primary btn-lg btn-full" disabled={loading}>
                                {loading ? <span className="spinner spinner-sm" /> : 'Verify'}
                            </button>
                        </form>

                        <div className="auth-footer">
                            <button onClick={() => setMfaRequired(false)} className="btn btn-ghost btn-sm">
                                ← Back to login
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="auth-page">
            <div className="auth-container">
                <div className="auth-card glass-card">
                    <div className="auth-header">
                        <div className="auth-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" />
                                <polyline points="10 17 15 12 10 7" />
                                <line x1="15" y1="12" x2="3" y2="12" />
                            </svg>
                        </div>
                        <h1>Welcome Back</h1>
                        <p>Sign in to access your secure meeting minutes</p>
                    </div>

                    {error && <div className="alert alert-error">{error}</div>}

                    <form onSubmit={handleSubmit}>
                        <div className="form-group">
                            <label className="form-label">Email Address</label>
                            <input
                                type="email"
                                name="email"
                                value={formData.email}
                                onChange={handleChange}
                                className="form-input"
                                placeholder="you@example.com"
                                required
                            />
                        </div>

                        <div className="form-group">
                            <label className="form-label">Password</label>
                            <input
                                type="password"
                                name="password"
                                value={formData.password}
                                onChange={handleChange}
                                className="form-input"
                                placeholder="••••••••"
                                required
                            />
                        </div>

                        <button type="submit" className="btn btn-primary btn-lg btn-full" disabled={loading}>
                            {loading ? <span className="spinner spinner-sm" /> : 'Sign In'}
                        </button>
                    </form>

                    <div className="auth-divider">
                        <span>New to MinuteVault?</span>
                    </div>

                    <Link to="/register" className="btn btn-secondary btn-lg btn-full">
                        Create Account
                    </Link>
                </div>

                <div className="auth-features">
                    <div className="feature-item">
                        <div className="feature-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                            </svg>
                        </div>
                        <div className="feature-text">
                            <h4>End-to-End Encrypted</h4>
                            <p>AES-256-GCM encryption</p>
                        </div>
                    </div>
                    <div className="feature-item">
                        <div className="feature-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            </svg>
                        </div>
                        <div className="feature-text">
                            <h4>Digital Signatures</h4>
                            <p>RSA-PSS verification</p>
                        </div>
                    </div>
                    <div className="feature-item">
                        <div className="feature-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M12 2L2 7l10 5 10-5-10-5z" />
                                <path d="M2 17l10 5 10-5" />
                                <path d="M2 12l10 5 10-5" />
                            </svg>
                        </div>
                        <div className="feature-text">
                            <h4>Access Control</h4>
                            <p>Role-based permissions</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
