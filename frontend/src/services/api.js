import axios from 'axios';

const API_BASE_URL = 'http://localhost:3001/api';

const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json'
    }
});

// Add auth token to requests
api.interceptors.request.use((config) => {
    const token = localStorage.getItem('token');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});

// Handle auth errors
api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            if (!window.location.pathname.includes('/login') &&
                !window.location.pathname.includes('/register') &&
                !window.location.pathname.includes('/verify')) {
                window.location.href = '/login';
            }
        }
        return Promise.reject(error);
    }
);

// Auth API
export const authAPI = {
    register: (data) => api.post('/auth/register', data),
    login: (data) => api.post('/auth/login', data),
    loginMFA: (data) => api.post('/auth/login/mfa', data),
    setupMFA: () => api.post('/auth/mfa/setup'),
    verifyMFA: (data) => api.post('/auth/mfa/verify', data),
    disableMFA: (data) => api.post('/auth/mfa/disable', data)
};

// Users API
export const usersAPI = {
    getMe: () => api.get('/users/me'),
    getAll: () => api.get('/users'),
    getPublicKey: (id) => api.get(`/users/${id}/public-key`),
    updateProfile: (data) => api.put('/users/me', data)
};

// Meetings API
export const meetingsAPI = {
    getAll: () => api.get('/meetings'),
    getById: (id) => api.get(`/meetings/${id}`),
    create: (data) => api.post('/meetings', data),
    delete: (id) => api.delete(`/meetings/${id}`)
};

// Minutes API
export const minutesAPI = {
    create: (meetingId, data) => api.post(`/minutes/meeting/${meetingId}`, data),
    getById: (id) => api.get(`/minutes/${id}`),
    decrypt: (id, data) => api.post(`/minutes/${id}/decrypt`, data),
    approve: (id, data) => api.post(`/minutes/${id}/approve`, data),
    verify: (id) => api.get(`/minutes/${id}/verify`),
    verifyByCode: (code) => api.get(`/minutes/verify/code/${code}`)
};

// ACL API
export const aclAPI = {
    get: (objectType, objectId) => api.get(`/acl/${objectType}/${objectId}`),
    getMatrix: (objectType, objectId) => api.get(`/acl/matrix/${objectType}/${objectId}`),
    create: (data) => api.post('/acl', data),
    delete: (id) => api.delete(`/acl/${id}`)
};

export default api;
