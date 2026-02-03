import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { meetingsAPI } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import './Dashboard.css';

export default function Dashboard() {
    const { user } = useAuth();
    const [meetings, setMeetings] = useState({ ownMeetings: [], sharedMeetings: [] });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        fetchMeetings();
    }, []);

    const fetchMeetings = async () => {
        try {
            const res = await meetingsAPI.getAll();
            setMeetings(res.data);
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to load meetings');
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
                    <p>Loading your meetings...</p>
                </div>
            </div>
        );
    }

    const allMeetings = [...meetings.ownMeetings, ...meetings.sharedMeetings];

    return (
        <div className="page container">
            <div className="dashboard-header">
                <div className="header-content">
                    <h1>Welcome back, {user?.name?.split(' ')[0]}! 👋</h1>
                    <p>Manage your secure meeting minutes</p>
                </div>
                <Link to="/meetings/new" className="btn btn-primary">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="18" height="18">
                        <line x1="12" y1="5" x2="12" y2="19" />
                        <line x1="5" y1="12" x2="19" y2="12" />
                    </svg>
                    New Meeting
                </Link>
            </div>

            {error && <div className="alert alert-error">{error}</div>}

            <div className="dashboard-stats">
                <div className="stat-card glass-card">
                    <div className="stat-icon blue">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                            <circle cx="9" cy="7" r="4" />
                            <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                            <path d="M16 3.13a4 4 0 0 1 0 7.75" />
                        </svg>
                    </div>
                    <div className="stat-content">
                        <span className="stat-value">{meetings.ownMeetings.length}</span>
                        <span className="stat-label">Your Meetings</span>
                    </div>
                </div>

                <div className="stat-card glass-card">
                    <div className="stat-icon green">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                            <polyline points="14 2 14 8 20 8" />
                            <line x1="16" y1="13" x2="8" y2="13" />
                            <line x1="16" y1="17" x2="8" y2="17" />
                            <polyline points="10 9 9 9 8 9" />
                        </svg>
                    </div>
                    <div className="stat-content">
                        <span className="stat-value">
                            {allMeetings.reduce((sum, m) => sum + (m.minutes?.length || 0), 0)}
                        </span>
                        <span className="stat-label">Total Minutes</span>
                    </div>
                </div>

                <div className="stat-card glass-card">
                    <div className="stat-icon purple">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                            <polyline points="22 4 12 14.01 9 11.01" />
                        </svg>
                    </div>
                    <div className="stat-content">
                        <span className="stat-value">
                            {allMeetings.reduce((sum, m) =>
                                sum + (m.minutes?.filter(min => min.status === 'approved').length || 0), 0)}
                        </span>
                        <span className="stat-label">Approved</span>
                    </div>
                </div>

                <div className="stat-card glass-card">
                    <div className="stat-icon orange">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <circle cx="12" cy="12" r="10" />
                            <polyline points="12 6 12 12 16 14" />
                        </svg>
                    </div>
                    <div className="stat-content">
                        <span className="stat-value">
                            {allMeetings.reduce((sum, m) =>
                                sum + (m.minutes?.filter(min => min.status === 'pending').length || 0), 0)}
                        </span>
                        <span className="stat-label">Pending</span>
                    </div>
                </div>
            </div>

            {allMeetings.length === 0 ? (
                <div className="empty-state glass-card">
                    <div className="empty-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                            <polyline points="14 2 14 8 20 8" />
                            <line x1="12" y1="18" x2="12" y2="12" />
                            <line x1="9" y1="15" x2="15" y2="15" />
                        </svg>
                    </div>
                    <h3>No meetings yet</h3>
                    <p>Create your first meeting to start managing secure minutes</p>
                    <Link to="/meetings/new" className="btn btn-primary">
                        Create Meeting
                    </Link>
                </div>
            ) : (
                <div className="meetings-section">
                    {meetings.ownMeetings.length > 0 && (
                        <>
                            <h2 className="section-title">Your Meetings</h2>
                            <div className="meetings-grid">
                                {meetings.ownMeetings.map(meeting => (
                                    <MeetingCard key={meeting.id} meeting={meeting} isOwner={true} getStatusBadge={getStatusBadge} />
                                ))}
                            </div>
                        </>
                    )}

                    {meetings.sharedMeetings.length > 0 && (
                        <>
                            <h2 className="section-title mt-xl">Shared With You</h2>
                            <div className="meetings-grid">
                                {meetings.sharedMeetings.map(meeting => (
                                    <MeetingCard key={meeting.id} meeting={meeting} isOwner={false} getStatusBadge={getStatusBadge} />
                                ))}
                            </div>
                        </>
                    )}
                </div>
            )}
        </div>
    );
}

function MeetingCard({ meeting, isOwner, getStatusBadge }) {
    return (
        <Link to={`/meetings/${meeting.id}`} className="meeting-card glass-card glass-card-hover">
            <div className="meeting-card-header">
                <h3>{meeting.title}</h3>
                {isOwner && <span className="owner-badge">Owner</span>}
            </div>

            <p className="meeting-description">
                {meeting.description || 'No description'}
            </p>

            <div className="meeting-meta">
                <span className="meta-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14">
                        <rect x="3" y="4" width="18" height="18" rx="2" ry="2" />
                        <line x1="16" y1="2" x2="16" y2="6" />
                        <line x1="8" y1="2" x2="8" y2="6" />
                        <line x1="3" y1="10" x2="21" y2="10" />
                    </svg>
                    {new Date(meeting.createdAt).toLocaleDateString()}
                </span>
                <span className="meta-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                        <polyline points="14 2 14 8 20 8" />
                    </svg>
                    {meeting.minutes?.length || 0} minutes
                </span>
            </div>

            {meeting.minutes && meeting.minutes.length > 0 && (
                <div className="minutes-preview">
                    {meeting.minutes.slice(0, 3).map(min => (
                        <span key={min.id} className={`badge ${getStatusBadge(min.status)}`}>
                            {min.status}
                        </span>
                    ))}
                </div>
            )}

            <div className="card-footer">
                <span className="view-link">View Details →</span>
            </div>
        </Link>
    );
}
