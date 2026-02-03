import { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { meetingsAPI } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import './Meeting.css';

export default function MeetingDetail() {
    const { id } = useParams();
    const navigate = useNavigate();
    const { user } = useAuth();
    const [meeting, setMeeting] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [deleting, setDeleting] = useState(false);

    useEffect(() => {
        fetchMeeting();
    }, [id]);

    const fetchMeeting = async () => {
        try {
            const res = await meetingsAPI.getById(id);
            setMeeting(res.data);
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to load meeting');
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async () => {
        setDeleting(true);
        try {
            await meetingsAPI.delete(id);
            navigate('/dashboard');
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to delete meeting');
        } finally {
            setDeleting(false);
            setShowDeleteModal(false);
        }
    };

    const isOwner = meeting?.createdById === user?.id;

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
                    <p>Loading meeting details...</p>
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="page container">
                <div className="alert alert-error">{error}</div>
                <button onClick={() => navigate('/dashboard')} className="btn btn-secondary">
                    Back to Dashboard
                </button>
            </div>
        );
    }

    return (
        <div className="page container">
            <div className="meeting-detail-page">
                <div className="page-header">
                    <button onClick={() => navigate('/dashboard')} className="btn btn-ghost btn-sm">
                        ← Back to Dashboard
                    </button>
                </div>

                <div className="meeting-header glass-card">
                    <div className="meeting-header-content">
                        <div className="meeting-info">
                            <h1>{meeting.title}</h1>
                            <p className="meeting-description">
                                {meeting.description || 'No description provided'}
                            </p>
                            <div className="meeting-meta">
                                <span className="meta-item">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="16" height="16">
                                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                                        <circle cx="12" cy="7" r="4" />
                                    </svg>
                                    Created by {meeting.createdBy?.name}
                                </span>
                                <span className="meta-item">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="16" height="16">
                                        <rect x="3" y="4" width="18" height="18" rx="2" ry="2" />
                                        <line x1="16" y1="2" x2="16" y2="6" />
                                        <line x1="8" y1="2" x2="8" y2="6" />
                                        <line x1="3" y1="10" x2="21" y2="10" />
                                    </svg>
                                    {new Date(meeting.createdAt).toLocaleDateString('en-US', {
                                        year: 'numeric',
                                        month: 'long',
                                        day: 'numeric'
                                    })}
                                </span>
                            </div>
                        </div>

                        <div className="meeting-actions">
                            <Link to={`/meetings/${id}/minutes/new`} className="btn btn-primary">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="18" height="18">
                                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                                    <polyline points="14 2 14 8 20 8" />
                                    <line x1="12" y1="18" x2="12" y2="12" />
                                    <line x1="9" y1="15" x2="15" y2="15" />
                                </svg>
                                Create Minutes
                            </Link>
                            {isOwner && (
                                <button onClick={() => setShowDeleteModal(true)} className="btn btn-ghost btn-sm">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="16" height="16">
                                        <polyline points="3 6 5 6 21 6" />
                                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                                    </svg>
                                </button>
                            )}
                        </div>
                    </div>
                </div>

                <div className="meeting-content">
                    <div className="minutes-section">
                        <h2>Meeting Minutes</h2>

                        {meeting.minutes && meeting.minutes.length > 0 ? (
                            <div className="minutes-list">
                                {meeting.minutes.map((min, index) => (
                                    <Link key={min.id} to={`/minutes/${min.id}`} className="minutes-item glass-card glass-card-hover">
                                        <div className="minutes-item-header">
                                            <span className="minutes-number">#{meeting.minutes.length - index}</span>
                                            <span className={`badge ${getStatusBadge(min.status)}`}>{min.status}</span>
                                        </div>

                                        <div className="minutes-item-info">
                                            <span className="created-by">
                                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14">
                                                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                                                    <circle cx="12" cy="7" r="4" />
                                                </svg>
                                                {min.createdBy?.name}
                                            </span>
                                            <span className="created-at">
                                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14">
                                                    <circle cx="12" cy="12" r="10" />
                                                    <polyline points="12 6 12 12 16 14" />
                                                </svg>
                                                {new Date(min.createdAt).toLocaleString()}
                                            </span>
                                        </div>

                                        <div className="minutes-item-footer">
                                            <span className="encryption-indicator">
                                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="12" height="12">
                                                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                                                </svg>
                                                Encrypted
                                            </span>
                                            {min.approvals && min.approvals.length > 0 && (
                                                <span className="approvals-count">
                                                    {min.approvals.length} approval{min.approvals.length !== 1 ? 's' : ''}
                                                </span>
                                            )}
                                        </div>
                                    </Link>
                                ))}
                            </div>
                        ) : (
                            <div className="empty-minutes glass-card">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" width="48" height="48">
                                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                                    <polyline points="14 2 14 8 20 8" />
                                </svg>
                                <h3>No minutes yet</h3>
                                <p>Create the first minutes for this meeting</p>
                                <Link to={`/meetings/${id}/minutes/new`} className="btn btn-primary">
                                    Create Minutes
                                </Link>
                            </div>
                        )}
                    </div>

                    <div className="participants-section">
                        <h2>Participants</h2>
                        <div className="participants-card glass-card">
                            {meeting.participants && meeting.participants.length > 0 ? (
                                <div className="participants-grid">
                                    {meeting.participants.map(p => (
                                        <div key={p.id} className="participant-row">
                                            <div className="participant-avatar">
                                                {p.name?.charAt(0).toUpperCase()}
                                            </div>
                                            <div className="participant-details">
                                                <span className="participant-name">{p.name}</span>
                                                <span className="participant-email">{p.email}</span>
                                            </div>
                                            <div className="participant-badges">
                                                {p.rights?.split(',').map(r => (
                                                    <span key={r} className="badge badge-primary">{r}</span>
                                                ))}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <p className="text-muted text-center">No additional participants</p>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            {/* Delete Modal */}
            {showDeleteModal && (
                <div className="modal-backdrop" onClick={() => setShowDeleteModal(false)}>
                    <div className="modal" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>Delete Meeting</h3>
                            <button onClick={() => setShowDeleteModal(false)} className="btn btn-ghost btn-sm">✕</button>
                        </div>
                        <div className="modal-body">
                            <p>Are you sure you want to delete this meeting? This action cannot be undone and all associated minutes will be permanently deleted.</p>
                        </div>
                        <div className="modal-footer">
                            <button onClick={() => setShowDeleteModal(false)} className="btn btn-secondary">Cancel</button>
                            <button onClick={handleDelete} className="btn btn-danger" disabled={deleting}>
                                {deleting ? <span className="spinner spinner-sm" /> : 'Delete'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
