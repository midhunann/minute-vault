import { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { minutesAPI } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import './Minutes.css';

export default function MinutesDetail() {
    const { id } = useParams();
    const navigate = useNavigate();
    const { user } = useAuth();
    const [minutes, setMinutes] = useState(null);
    const [decryptedContent, setDecryptedContent] = useState(null);
    const [loading, setLoading] = useState(true);
    const [decrypting, setDecrypting] = useState(false);
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [signatureValid, setSignatureValid] = useState(null);
    const [showApproveModal, setShowApproveModal] = useState(false);
    const [approvalStatus, setApprovalStatus] = useState('approved');
    const [approvalComment, setApprovalComment] = useState('');
    const [approving, setApproving] = useState(false);

    useEffect(() => {
        fetchMinutes();
    }, [id]);

    const fetchMinutes = async () => {
        try {
            const res = await minutesAPI.getById(id);
            setMinutes(res.data);
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to load minutes');
        } finally {
            setLoading(false);
        }
    };

    const handleDecrypt = async (e) => {
        e.preventDefault();
        setDecrypting(true);
        setError('');

        try {
            const res = await minutesAPI.decrypt(id, { password });
            setDecryptedContent(res.data.content);
            setSignatureValid(res.data.signatureValid);
            setPassword('');
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to decrypt');
        } finally {
            setDecrypting(false);
        }
    };

    const handleApprove = async (e) => {
        e.preventDefault();
        setApproving(true);
        setError('');

        try {
            await minutesAPI.approve(id, {
                status: approvalStatus,
                comment: approvalComment,
                password
            });
            setShowApproveModal(false);
            setApprovalComment('');
            setPassword('');
            fetchMinutes(); // Refresh to show new approval
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to submit approval');
        } finally {
            setApproving(false);
        }
    };

    const getStatusBadge = (status) => {
        const badges = {
            pending: 'badge-warning',
            approved: 'badge-success',
            rejected: 'badge-danger'
        };
        return badges[status] || 'badge-info';
    };

    const hasUserApproved = minutes?.minutes?.approvals?.some(a => a.approver?.id === user?.id);

    if (loading) {
        return (
            <div className="page container">
                <div className="loading-state">
                    <div className="spinner"></div>
                    <p>Loading minutes...</p>
                </div>
            </div>
        );
    }

    if (error && !minutes) {
        return (
            <div className="page container">
                <div className="alert alert-error">{error}</div>
                <button onClick={() => navigate(-1)} className="btn btn-secondary">Go Back</button>
            </div>
        );
    }

    return (
        <div className="page container">
            <div className="minutes-detail-page">
                <div className="page-header">
                    <button onClick={() => navigate(-1)} className="btn btn-ghost btn-sm">
                        ← Back
                    </button>
                    <Link to={`/minutes/${id}/verify`} className="btn btn-secondary btn-sm">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="16" height="16">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                            <polyline points="22 4 12 14.01 9 11.01" />
                        </svg>
                        Verify
                    </Link>
                </div>

                {error && <div className="alert alert-error mb-lg">{error}</div>}

                <div className="minutes-detail-header glass-card">
                    <div className="header-info">
                        <h1>Meeting Minutes</h1>
                        <span className={`badge ${getStatusBadge(minutes?.minutes?.status)}`}>
                            {minutes?.minutes?.status}
                        </span>
                    </div>
                    <div className="header-meta">
                        <span>
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="16" height="16">
                                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                                <circle cx="9" cy="7" r="4" />
                            </svg>
                            Created by {minutes?.minutes?.createdBy?.name}
                        </span>
                        <span>
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="16" height="16">
                                <rect x="3" y="4" width="18" height="18" rx="2" ry="2" />
                                <line x1="16" y1="2" x2="16" y2="6" />
                                <line x1="8" y1="2" x2="8" y2="6" />
                                <line x1="3" y1="10" x2="21" y2="10" />
                            </svg>
                            {new Date(minutes?.minutes?.createdAt).toLocaleString()}
                        </span>
                        <span className="encryption-indicator">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                            </svg>
                            AES-256-GCM Encrypted
                        </span>
                    </div>
                </div>

                <div className="minutes-content-section">
                    {!decryptedContent ? (
                        <div className="decrypt-prompt glass-card">
                            <div className="decrypt-icon">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                                </svg>
                            </div>
                            <h2>Minutes are Encrypted</h2>
                            <p>Enter your password to decrypt and view the content</p>

                            <form onSubmit={handleDecrypt} className="decrypt-form">
                                <div className="form-group">
                                    <input
                                        type="password"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        className="form-input"
                                        placeholder="Your account password"
                                        required
                                    />
                                </div>
                                <button type="submit" className="btn btn-primary" disabled={decrypting}>
                                    {decrypting ? <span className="spinner spinner-sm" /> : 'Decrypt Minutes'}
                                </button>
                            </form>
                        </div>
                    ) : (
                        <div className="decrypted-content glass-card">
                            <div className="content-header">
                                <h2>Decrypted Content</h2>
                                <div className="signature-status">
                                    {signatureValid ? (
                                        <span className="verified-badge">
                                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="16" height="16">
                                                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                                                <polyline points="22 4 12 14.01 9 11.01" />
                                            </svg>
                                            Signature Verified
                                        </span>
                                    ) : (
                                        <span className="badge badge-danger">Signature Invalid</span>
                                    )}
                                </div>
                            </div>
                            <pre className="content-text">{decryptedContent}</pre>
                        </div>
                    )}
                </div>

                <div className="minutes-sidebar">
                    <div className="approvals-section glass-card">
                        <h3>Approvals</h3>

                        {minutes?.minutes?.approvals && minutes.minutes.approvals.length > 0 ? (
                            <div className="approvals-list">
                                {minutes.minutes.approvals.map(approval => (
                                    <div key={approval.id} className="approval-item">
                                        <div className="approval-header">
                                            <span className="approver-name">{approval.approver?.name}</span>
                                            <span className={`badge ${getStatusBadge(approval.status)}`}>
                                                {approval.status}
                                            </span>
                                        </div>
                                        {approval.comment && (
                                            <p className="approval-comment">{approval.comment}</p>
                                        )}
                                        <span className="approval-date">
                                            {new Date(approval.createdAt).toLocaleString()}
                                        </span>
                                        <span className="signature-tag">
                                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="12" height="12">
                                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                            </svg>
                                            Digitally Signed
                                        </span>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <p className="text-muted text-sm">No approvals yet</p>
                        )}

                        {decryptedContent && !hasUserApproved && (
                            <button
                                onClick={() => setShowApproveModal(true)}
                                className="btn btn-success btn-full mt-md"
                            >
                                Submit Approval
                            </button>
                        )}
                    </div>

                    <div className="verification-section glass-card">
                        <h3>Verification</h3>
                        <p className="text-sm text-muted mb-md">
                            Verify the authenticity and integrity of these minutes
                        </p>
                        <Link to={`/minutes/${id}/verify`} className="btn btn-secondary btn-full">
                            View Verification Details
                        </Link>
                    </div>
                </div>
            </div>

            {/* Approve Modal */}
            {showApproveModal && (
                <div className="modal-backdrop" onClick={() => setShowApproveModal(false)}>
                    <div className="modal" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>Submit Approval</h3>
                            <button onClick={() => setShowApproveModal(false)} className="btn btn-ghost btn-sm">✕</button>
                        </div>
                        <form onSubmit={handleApprove}>
                            <div className="modal-body">
                                <div className="form-group">
                                    <label className="form-label">Decision</label>
                                    <select
                                        value={approvalStatus}
                                        onChange={(e) => setApprovalStatus(e.target.value)}
                                        className="form-input form-select"
                                    >
                                        <option value="approved">Approve</option>
                                        <option value="rejected">Reject</option>
                                    </select>
                                </div>

                                <div className="form-group">
                                    <label className="form-label">Comment (optional)</label>
                                    <textarea
                                        value={approvalComment}
                                        onChange={(e) => setApprovalComment(e.target.value)}
                                        className="form-input"
                                        placeholder="Add a comment..."
                                        rows={3}
                                    />
                                </div>

                                <div className="form-group">
                                    <label className="form-label">Your Password *</label>
                                    <input
                                        type="password"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        className="form-input"
                                        placeholder="Required to sign your approval"
                                        required
                                    />
                                    <span className="form-hint">Your approval will be digitally signed</span>
                                </div>
                            </div>
                            <div className="modal-footer">
                                <button type="button" onClick={() => setShowApproveModal(false)} className="btn btn-secondary">
                                    Cancel
                                </button>
                                <button type="submit" className={`btn ${approvalStatus === 'approved' ? 'btn-success' : 'btn-danger'}`} disabled={approving}>
                                    {approving ? <span className="spinner spinner-sm" /> : `Submit ${approvalStatus === 'approved' ? 'Approval' : 'Rejection'}`}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}
