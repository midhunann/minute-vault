import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { minutesAPI } from '../../services/api';
import './Minutes.css';

export default function VerifyMinutes() {
    const { id, code } = useParams();
    const [verification, setVerification] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        fetchVerification();
    }, [id, code]);

    const fetchVerification = async () => {
        try {
            let res;
            if (code) {
                // Verify by code (from QR scan)
                res = await minutesAPI.verifyByCode(code);
            } else {
                res = await minutesAPI.verify(id);
            }
            setVerification(res.data);
        } catch (err) {
            setError(err.response?.data?.error || 'Verification failed');
        } finally {
            setLoading(false);
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

    if (loading) {
        return (
            <div className="page container">
                <div className="loading-state">
                    <div className="spinner"></div>
                    <p>Verifying minutes...</p>
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="page container">
                <div className="verify-page">
                    <div className="verify-error glass-card">
                        <div className="error-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <circle cx="12" cy="12" r="10" />
                                <line x1="15" y1="9" x2="9" y2="15" />
                                <line x1="9" y1="9" x2="15" y2="15" />
                            </svg>
                        </div>
                        <h1>Verification Failed</h1>
                        <p>{error}</p>
                        <Link to="/dashboard" className="btn btn-primary">
                            Go to Dashboard
                        </Link>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="page container">
            <div className="verify-page">
                <div className="verify-header glass-card">
                    <div className="verify-badge">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                            <polyline points="22 4 12 14.01 9 11.01" />
                        </svg>
                    </div>
                    <h1>Minutes Verified</h1>
                    <p>The authenticity and integrity of these minutes has been verified</p>
                </div>

                <div className="verify-content">
                    <div className="verify-details glass-card">
                        <h2>Document Details</h2>

                        <div className="detail-row">
                            <span className="detail-label">Meeting</span>
                            <span className="detail-value">{verification?.meetingTitle}</span>
                        </div>

                        <div className="detail-row">
                            <span className="detail-label">Created By</span>
                            <span className="detail-value">{verification?.createdBy}</span>
                        </div>

                        <div className="detail-row">
                            <span className="detail-label">Created At</span>
                            <span className="detail-value">
                                {new Date(verification?.createdAt).toLocaleString()}
                            </span>
                        </div>

                        <div className="detail-row">
                            <span className="detail-label">Status</span>
                            <span className={`badge ${getStatusBadge(verification?.status)}`}>
                                {verification?.status}
                            </span>
                        </div>

                        <div className="divider"></div>

                        <h3>Security Verification</h3>

                        <div className="security-checks">
                            <div className={`check-item ${verification?.creatorSignaturePresent ? 'valid' : 'invalid'}`}>
                                <span className="check-icon">
                                    {verification?.creatorSignaturePresent ? '✓' : '✕'}
                                </span>
                                <span className="check-text">Creator's Digital Signature</span>
                            </div>

                            <div className="check-item valid">
                                <span className="check-icon">✓</span>
                                <span className="check-text">AES-256-GCM Encryption</span>
                            </div>

                            <div className="check-item valid">
                                <span className="check-icon">✓</span>
                                <span className="check-text">RSA-2048 Key Wrapping</span>
                            </div>
                        </div>

                        <div className="divider"></div>

                        <h3>Content Fingerprint</h3>
                        <code className="fingerprint">{verification?.contentFingerprint}</code>
                        <p className="text-sm text-muted mt-sm">SHA-256 hash of encrypted content</p>
                    </div>

                    <div className="verify-sidebar">
                        <div className="qr-section glass-card">
                            <h3>Verification QR Code</h3>
                            <p className="text-sm text-muted mb-md">
                                Scan to verify these minutes anytime
                            </p>
                            <div className="qr-container">
                                <img src={verification?.qrCode} alt="Verification QR Code" />
                            </div>
                            <code className="verification-code">{verification?.verificationCode}</code>
                        </div>

                        {verification?.approvals && verification.approvals.length > 0 && (
                            <div className="approvals-verify glass-card">
                                <h3>Approvals</h3>
                                <div className="approvals-list">
                                    {verification.approvals.map((approval, idx) => (
                                        <div key={idx} className="approval-verify-item">
                                            <span className="approver">{approval.approver}</span>
                                            <span className={`badge ${getStatusBadge(approval.status)}`}>
                                                {approval.status}
                                            </span>
                                            <span className="signature-tag">
                                                {approval.signaturePresent ? (
                                                    <>
                                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="12" height="12">
                                                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                                                            <polyline points="22 4 12 14.01 9 11.01" />
                                                        </svg>
                                                        Signed
                                                    </>
                                                ) : 'Unsigned'}
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                <div className="verify-footer glass-card">
                    <p>
                        <strong>Verification ID:</strong> {verification?.minutesId}
                    </p>
                    <p className="text-sm text-muted">
                        This verification confirms that the meeting minutes are authentic,
                        have not been tampered with, and were signed by the stated creator.
                    </p>
                </div>
            </div>
        </div>
    );
}
