import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { authAPI } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import './Auth.css';

export default function Register() {
    const navigate = useNavigate();
    const { login } = useAuth();
    const [step, setStep] = useState(1); // 1: form, 2: MFA setup
    const [formData, setFormData] = useState({
        name: '',
        email: '',
        password: '',
        confirmPassword: ''
    });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [mfaData, setMfaData] = useState(null);
    const [totpCode, setTotpCode] = useState('');

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
        setError('');
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (formData.password !== formData.confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        if (formData.password.length < 8) {
            setError('Password must be at least 8 characters');
            return;
        }

        setLoading(true);
        setError('');

        try {
            const res = await authAPI.register({
                name: formData.name,
                email: formData.email,
                password: formData.password
            });

            // Login the user
            login(res.data.user, res.data.token);

            // Setup MFA
            const mfaRes = await authAPI.setupMFA();
            setMfaData(mfaRes.data);
            setStep(2);
        } catch (err) {
            setError(err.response?.data?.error || 'Registration failed');
        } finally {
            setLoading(false);
        }
    };

    const handleMFAVerify = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            await authAPI.verifyMFA({ totpCode });
            navigate('/dashboard');
        } catch (err) {
            setError(err.response?.data?.error || 'MFA verification failed');
        } finally {
            setLoading(false);
        }
    };

    const skipMFA = () => {
        navigate('/dashboard');
    };

    if (step === 2 && mfaData) {
        return (
            <div className="auth-page">
                <div className="auth-container">
                    <div className="auth-card glass-card mfa-setup">
                        <div className="auth-header">
                            <div className="auth-icon success">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                    <polyline points="9 12 11 14 15 10" />
                                </svg>
                            </div>
                            <h1>Secure Your Account</h1>
                            <p>Enable two-factor authentication for enhanced security</p>
                        </div>

                        {error && <div className="alert alert-error">{error}</div>}

                        <div className="mfa-instructions">
                            <div className="step-indicator">
                                <span className="step-number">1</span>
                                <span className="step-text">Scan this QR code with your authenticator app</span>
                            </div>

                            <div className="qr-container">
                                <img src={mfaData.qrCode} alt="MFA QR Code" />
                            </div>

                            <div className="secret-fallback">
                                <span>Or enter this code manually:</span>
                                <code className="secret-code">{mfaData.secret}</code>
                            </div>
                        </div>

                        <div className="mfa-instructions">
                            <div className="step-indicator">
                                <span className="step-number">2</span>
                                <span className="step-text">Enter the 6-digit code from your app</span>
                            </div>
                        </div>

                        <form onSubmit={handleMFAVerify}>
                            <div className="form-group">
                                <input
                                    type="text"
                                    value={totpCode}
                                    onChange={(e) => setTotpCode(e.target.value)}
                                    className="form-input totp-input"
                                    placeholder="000000"
                                    maxLength={6}
                                    pattern="[0-9]*"
                                    autoComplete="one-time-code"
                                    required
                                />
                            </div>

                            <button type="submit" className="btn btn-success btn-lg btn-full" disabled={loading}>
                                {loading ? <span className="spinner spinner-sm" /> : 'Enable MFA'}
                            </button>
                        </form>

                        <button onClick={skipMFA} className="btn btn-ghost btn-full mt-md">
                            Skip for now (not recommended)
                        </button>
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
                        <div className="auth-icon register">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                                <circle cx="8.5" cy="7" r="4" />
                                <line x1="20" y1="8" x2="20" y2="14" />
                                <line x1="23" y1="11" x2="17" y2="11" />
                            </svg>
                        </div>
                        <h1>Create Account</h1>
                        <p>Join MinuteVault to secure your meeting minutes</p>
                    </div>

                    {error && <div className="alert alert-error">{error}</div>}

                    <form onSubmit={handleSubmit}>
                        <div className="form-group">
                            <label className="form-label">Full Name</label>
                            <input
                                type="text"
                                name="name"
                                value={formData.name}
                                onChange={handleChange}
                                className="form-input"
                                placeholder="John Doe"
                                required
                            />
                        </div>

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
                                placeholder="Min. 8 characters"
                                minLength={8}
                                required
                            />
                        </div>

                        <div className="form-group">
                            <label className="form-label">Confirm Password</label>
                            <input
                                type="password"
                                name="confirmPassword"
                                value={formData.confirmPassword}
                                onChange={handleChange}
                                className="form-input"
                                placeholder="••••••••"
                                required
                            />
                        </div>

                        <div className="security-notice">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            </svg>
                            <span>Your password encrypts your private signing key</span>
                        </div>

                        <button type="submit" className="btn btn-primary btn-lg btn-full" disabled={loading}>
                            {loading ? <span className="spinner spinner-sm" /> : 'Create Account & Setup MFA'}
                        </button>
                    </form>

                    <div className="auth-divider">
                        <span>Already have an account?</span>
                    </div>

                    <Link to="/login" className="btn btn-secondary btn-lg btn-full">
                        Sign In
                    </Link>
                </div>
            </div>
        </div>
    );
}
