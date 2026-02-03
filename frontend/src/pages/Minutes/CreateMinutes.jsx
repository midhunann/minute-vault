import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { minutesAPI } from '../../services/api';
import './Minutes.css';

export default function CreateMinutes() {
    const { meetingId } = useParams();
    const navigate = useNavigate();
    const [content, setContent] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!content.trim()) {
            setError('Content is required');
            return;
        }

        if (!password) {
            setError('Password is required to sign the minutes');
            return;
        }

        setLoading(true);
        setError('');

        try {
            const res = await minutesAPI.create(meetingId, { content, password });
            navigate(`/minutes/${res.data.minutes.id}`);
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to create minutes');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="page container">
            <div className="create-minutes-page">
                <div className="page-header">
                    <button onClick={() => navigate(-1)} className="btn btn-ghost btn-sm">
                        ← Back
                    </button>
                </div>

                <div className="create-minutes-container glass-card">
                    <div className="section-header">
                        <div className="section-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                                <polyline points="14 2 14 8 20 8" />
                                <line x1="16" y1="13" x2="8" y2="13" />
                                <line x1="16" y1="17" x2="8" y2="17" />
                            </svg>
                        </div>
                        <div>
                            <h1>Create Meeting Minutes</h1>
                            <p>Your minutes will be encrypted and digitally signed</p>
                        </div>
                    </div>

                    {error && <div className="alert alert-error">{error}</div>}

                    <form onSubmit={handleSubmit}>
                        <div className="form-group">
                            <label className="form-label">Minutes Content *</label>
                            <textarea
                                value={content}
                                onChange={(e) => setContent(e.target.value)}
                                className="form-input minutes-textarea"
                                placeholder="Enter the meeting minutes content...&#10;&#10;Attendees:&#10;- ...&#10;&#10;Discussion Points:&#10;- ...&#10;&#10;Action Items:&#10;- ...&#10;&#10;Decisions Made:&#10;- ..."
                                rows={15}
                                required
                            />
                            <span className="char-count">{content.length} characters</span>
                        </div>

                        <div className="security-section glass-card">
                            <h3>
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
                                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                                </svg>
                                Security & Signing
                            </h3>
                            <p className="text-sm text-muted mb-md">
                                Your password is needed to unlock your private key for signing. The minutes will be:
                            </p>
                            <ul className="security-list">
                                <li>
                                    <span className="check-icon">✓</span>
                                    Encrypted with AES-256-GCM
                                </li>
                                <li>
                                    <span className="check-icon">✓</span>
                                    Signed with your RSA private key
                                </li>
                                <li>
                                    <span className="check-icon">✓</span>
                                    Shared only with authorized participants
                                </li>
                            </ul>

                            <div className="form-group mt-md">
                                <label className="form-label">Your Password *</label>
                                <input
                                    type="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    className="form-input"
                                    placeholder="Enter your account password"
                                    required
                                />
                                <span className="form-hint">Required to sign the minutes with your private key</span>
                            </div>
                        </div>

                        <div className="form-actions">
                            <button type="button" onClick={() => navigate(-1)} className="btn btn-secondary">
                                Cancel
                            </button>
                            <button type="submit" className="btn btn-success" disabled={loading}>
                                {loading ? (
                                    <><span className="spinner spinner-sm" /> Encrypting & Signing...</>
                                ) : (
                                    <>
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="18" height="18">
                                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                            <polyline points="9 12 11 14 15 10" />
                                        </svg>
                                        Create & Sign Minutes
                                    </>
                                )}
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    );
}
