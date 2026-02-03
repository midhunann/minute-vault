import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { authAPI, usersAPI } from '../../services/api';
import './Profile.css';

export default function Profile() {
    const navigate = useNavigate();
    const { user, updateUser, logout } = useAuth();
    const [profile, setProfile] = useState(null);
    const [loading, setLoading] = useState(true);
    const [mfaData, setMfaData] = useState(null);
    const [totpCode, setTotpCode] = useState('');
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [settingUpMfa, setSettingUpMfa] = useState(false);
    const [verifyingMfa, setVerifyingMfa] = useState(false);
    const [disablingMfa, setDisablingMfa] = useState(false);
    const [password, setPassword] = useState('');

    useEffect(() => {
        fetchProfile();
    }, []);

    const fetchProfile = async () => {
        try {
            const res = await usersAPI.getMe();
            setProfile(res.data);
        } catch (err) {
            setError('Failed to load profile');
        } finally {
            setLoading(false);
        }
    };

    const handleSetupMFA = async () => {
        setSettingUpMfa(true);
        setError('');

        try {
            const res = await authAPI.setupMFA();
            setMfaData(res.data);
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to setup MFA');
        } finally {
            setSettingUpMfa(false);
        }
    };

    const handleVerifyMFA = async (e) => {
        e.preventDefault();
        setVerifyingMfa(true);
        setError('');

        try {
            await authAPI.verifyMFA({ totpCode });
            setMfaData(null);
            setTotpCode('');
            setSuccess('MFA enabled successfully!');
            fetchProfile();
            updateUser({ ...user, totpEnabled: true });
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to verify MFA');
        } finally {
            setVerifyingMfa(false);
        }
    };

    const handleDisableMFA = async (e) => {
        e.preventDefault();
        setDisablingMfa(true);
        setError('');

        try {
            await authAPI.disableMFA({ password });
            setPassword('');
            setSuccess('MFA disabled successfully');
            fetchProfile();
            updateUser({ ...user, totpEnabled: false });
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to disable MFA');
        } finally {
            setDisablingMfa(false);
        }
    };

    const handleLogout = () => {
        logout();
        navigate('/login');
    };

    if (loading) {
        return (
            <div className="page container">
                <div className="loading-state">
                    <div className="spinner"></div>
                    <p>Loading profile...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="page container">
            <div className="profile-page">
                <div className="profile-header glass-card">
                    <div className="profile-avatar">
                        {profile?.name?.charAt(0).toUpperCase()}
                    </div>
                    <div className="profile-info">
                        <h1>{profile?.name}</h1>
                        <p>{profile?.email}</p>
                        <span className={`role-badge ${profile?.role}`}>{profile?.role}</span>
                    </div>
                </div>

                {error && <div className="alert alert-error">{error}</div>}
                {success && <div className="alert alert-success">{success}</div>}

                <div className="profile-sections">
                    <div className="section-card glass-card">
                        <h2>
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            </svg>
                            Two-Factor Authentication
                        </h2>

                        <div className="mfa-status">
                            <span className={`status-indicator ${profile?.totpEnabled ? 'enabled' : 'disabled'}`}>
                                <span className={`status-dot ${profile?.totpEnabled ? 'status-dot-success' : 'status-dot-warning'}`}></span>
                                {profile?.totpEnabled ? 'Enabled' : 'Not Enabled'}
                            </span>
                        </div>

                        {profile?.totpEnabled ? (
                            <div className="mfa-enabled">
                                <p className="text-sm text-muted mb-md">
                                    Your account is protected with two-factor authentication using an authenticator app.
                                </p>
                                <form onSubmit={handleDisableMFA} className="disable-mfa-form">
                                    <div className="form-group">
                                        <label className="form-label">Enter password to disable MFA</label>
                                        <input
                                            type="password"
                                            value={password}
                                            onChange={(e) => setPassword(e.target.value)}
                                            className="form-input"
                                            placeholder="Your password"
                                            required
                                        />
                                    </div>
                                    <button type="submit" className="btn btn-danger" disabled={disablingMfa}>
                                        {disablingMfa ? <span className="spinner spinner-sm" /> : 'Disable MFA'}
                                    </button>
                                </form>
                            </div>
                        ) : mfaData ? (
                            <div className="mfa-setup">
                                <div className="qr-section">
                                    <p className="text-sm mb-md">
                                        Scan this QR code with your authenticator app
                                    </p>
                                    <div className="qr-container">
                                        <img src={mfaData.qrCode} alt="MFA QR Code" />
                                    </div>
                                    <div className="secret-fallback">
                                        <span>Or enter manually:</span>
                                        <code className="secret-code">{mfaData.secret}</code>
                                    </div>
                                </div>

                                <form onSubmit={handleVerifyMFA} className="verify-mfa-form">
                                    <div className="form-group">
                                        <label className="form-label">Enter the 6-digit code</label>
                                        <input
                                            type="text"
                                            value={totpCode}
                                            onChange={(e) => setTotpCode(e.target.value)}
                                            className="form-input totp-input"
                                            placeholder="000000"
                                            maxLength={6}
                                            required
                                        />
                                    </div>
                                    <button type="submit" className="btn btn-success" disabled={verifyingMfa}>
                                        {verifyingMfa ? <span className="spinner spinner-sm" /> : 'Enable MFA'}
                                    </button>
                                </form>
                            </div>
                        ) : (
                            <div className="mfa-disabled">
                                <p className="text-sm text-muted mb-md">
                                    Add an extra layer of security to your account by enabling two-factor authentication.
                                </p>
                                <button onClick={handleSetupMFA} className="btn btn-primary" disabled={settingUpMfa}>
                                    {settingUpMfa ? <span className="spinner spinner-sm" /> : 'Setup MFA'}
                                </button>
                            </div>
                        )}
                    </div>

                    <div className="section-card glass-card">
                        <h2>
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                            </svg>
                            Encryption Keys
                        </h2>

                        <div className="key-info">
                            <div className="key-item">
                                <span className="key-label">Public Key</span>
                                <span className="key-status valid">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14">
                                        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                                        <polyline points="22 4 12 14.01 9 11.01" />
                                    </svg>
                                    RSA-2048
                                </span>
                            </div>
                            <div className="key-item">
                                <span className="key-label">Private Key</span>
                                <span className="key-status valid">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14">
                                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                                    </svg>
                                    Encrypted with AES-256
                                </span>
                            </div>
                        </div>

                        <p className="text-sm text-muted mt-md">
                            Your private key is encrypted with your password and stored securely.
                            It's used to sign documents and decrypt meeting minutes.
                        </p>
                    </div>

                    <div className="section-card glass-card">
                        <h2>
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
                                <circle cx="12" cy="12" r="3" />
                                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                            </svg>
                            Account
                        </h2>

                        <div className="account-info">
                            <div className="info-row">
                                <span className="info-label">Member since</span>
                                <span className="info-value">
                                    {new Date(profile?.createdAt).toLocaleDateString('en-US', {
                                        year: 'numeric',
                                        month: 'long',
                                        day: 'numeric'
                                    })}
                                </span>
                            </div>
                        </div>

                        <button onClick={handleLogout} className="btn btn-ghost btn-full mt-lg">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="18" height="18">
                                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                                <polyline points="16 17 21 12 16 7" />
                                <line x1="21" y1="12" x2="9" y2="12" />
                            </svg>
                            Logout
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}
