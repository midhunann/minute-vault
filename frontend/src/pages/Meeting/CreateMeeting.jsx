import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { meetingsAPI, usersAPI } from '../../services/api';
import './Meeting.css';

export default function CreateMeeting() {
    const navigate = useNavigate();
    const [formData, setFormData] = useState({
        title: '',
        description: ''
    });
    const [participants, setParticipants] = useState([]);
    const [users, setUsers] = useState([]);
    const [selectedUser, setSelectedUser] = useState('');
    const [selectedRights, setSelectedRights] = useState('read');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    useEffect(() => {
        fetchUsers();
    }, []);

    const fetchUsers = async () => {
        try {
            const res = await usersAPI.getAll();
            setUsers(res.data);
        } catch (err) {
            console.error('Failed to fetch users');
        }
    };

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
        setError('');
    };

    const addParticipant = () => {
        if (!selectedUser) return;

        const user = users.find(u => u.email === selectedUser);
        if (!user) return;

        if (participants.some(p => p.email === selectedUser)) {
            setError('User already added');
            return;
        }

        setParticipants([
            ...participants,
            { email: selectedUser, name: user.name, rights: selectedRights }
        ]);
        setSelectedUser('');
        setSelectedRights('read');
        setError('');
    };

    const removeParticipant = (email) => {
        setParticipants(participants.filter(p => p.email !== email));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!formData.title.trim()) {
            setError('Title is required');
            return;
        }

        setLoading(true);
        setError('');

        try {
            const res = await meetingsAPI.create({
                ...formData,
                participants
            });
            navigate(`/meetings/${res.data.meeting.id}`);
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to create meeting');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="page container">
            <div className="create-meeting-page">
                <div className="page-header">
                    <button onClick={() => navigate(-1)} className="btn btn-ghost btn-sm">
                        ← Back
                    </button>
                </div>

                <div className="create-meeting-container">
                    <div className="form-section glass-card">
                        <div className="section-header">
                            <div className="section-icon">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                                    <circle cx="9" cy="7" r="4" />
                                    <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                                    <path d="M16 3.13a4 4 0 0 1 0 7.75" />
                                </svg>
                            </div>
                            <div>
                                <h1>Create New Meeting</h1>
                                <p>Set up a meeting to manage secure minutes</p>
                            </div>
                        </div>

                        {error && <div className="alert alert-error">{error}</div>}

                        <form onSubmit={handleSubmit}>
                            <div className="form-group">
                                <label className="form-label">Meeting Title *</label>
                                <input
                                    type="text"
                                    name="title"
                                    value={formData.title}
                                    onChange={handleChange}
                                    className="form-input"
                                    placeholder="Q4 Planning Session"
                                    required
                                />
                            </div>

                            <div className="form-group">
                                <label className="form-label">Description</label>
                                <textarea
                                    name="description"
                                    value={formData.description}
                                    onChange={handleChange}
                                    className="form-input"
                                    placeholder="Brief description of the meeting..."
                                    rows={3}
                                />
                            </div>

                            <div className="divider"></div>

                            <div className="participants-section">
                                <h3>Add Participants</h3>
                                <p className="text-muted text-sm mb-md">
                                    Participants will have access to meeting minutes based on their rights
                                </p>

                                <div className="participant-form">
                                    <select
                                        value={selectedUser}
                                        onChange={(e) => setSelectedUser(e.target.value)}
                                        className="form-input form-select"
                                    >
                                        <option value="">Select a user...</option>
                                        {users.filter(u => !participants.some(p => p.email === u.email)).map(user => (
                                            <option key={user.id} value={user.email}>
                                                {user.name} ({user.email})
                                            </option>
                                        ))}
                                    </select>

                                    <select
                                        value={selectedRights}
                                        onChange={(e) => setSelectedRights(e.target.value)}
                                        className="form-input form-select rights-select"
                                    >
                                        <option value="read">Read</option>
                                        <option value="read,write">Read & Write</option>
                                        <option value="read,approve">Read & Approve</option>
                                        <option value="read,write,approve">Full Access</option>
                                    </select>

                                    <button type="button" onClick={addParticipant} className="btn btn-secondary">
                                        Add
                                    </button>
                                </div>

                                {participants.length > 0 && (
                                    <div className="participants-list">
                                        {participants.map(p => (
                                            <div key={p.email} className="participant-item">
                                                <div className="participant-info">
                                                    <span className="participant-name">{p.name}</span>
                                                    <span className="participant-email">{p.email}</span>
                                                </div>
                                                <div className="participant-rights">
                                                    {p.rights.split(',').map(right => (
                                                        <span key={right} className="badge badge-info">{right}</span>
                                                    ))}
                                                </div>
                                                <button
                                                    type="button"
                                                    onClick={() => removeParticipant(p.email)}
                                                    className="btn btn-ghost btn-sm"
                                                >
                                                    ✕
                                                </button>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>

                            <div className="form-actions">
                                <button type="button" onClick={() => navigate(-1)} className="btn btn-secondary">
                                    Cancel
                                </button>
                                <button type="submit" className="btn btn-primary" disabled={loading}>
                                    {loading ? <span className="spinner spinner-sm" /> : 'Create Meeting'}
                                </button>
                            </div>
                        </form>
                    </div>

                    <div className="info-section">
                        <div className="info-card glass-card">
                            <h4>🔐 Security Features</h4>
                            <ul>
                                <li>All minutes are encrypted with AES-256-GCM</li>
                                <li>Only authorized participants can decrypt</li>
                                <li>Digital signatures verify authenticity</li>
                                <li>ACL controls who can read/write/approve</li>
                            </ul>
                        </div>

                        <div className="info-card glass-card">
                            <h4>📋 Access Rights</h4>
                            <ul>
                                <li><strong>Read:</strong> View decrypted minutes</li>
                                <li><strong>Write:</strong> Create/edit minutes</li>
                                <li><strong>Approve:</strong> Sign approval decisions</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
