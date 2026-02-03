import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Layout from './components/Layout/Layout';
import Login from './pages/Auth/Login';
import Register from './pages/Auth/Register';
import Dashboard from './pages/Dashboard/Dashboard';
import CreateMeeting from './pages/Meeting/CreateMeeting';
import MeetingDetail from './pages/Meeting/MeetingDetail';
import CreateMinutes from './pages/Minutes/CreateMinutes';
import MinutesDetail from './pages/Minutes/MinutesDetail';
import VerifyMinutes from './pages/Minutes/VerifyMinutes';
import Profile from './pages/Profile/Profile';

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="loading-state" style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div className="spinner"></div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return <Layout>{children}</Layout>;
}

function PublicRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="loading-state" style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div className="spinner"></div>
      </div>
    );
  }

  if (user) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
}

function App() {
  return (
    <AuthProvider>
      <Routes>
        {/* Public routes */}
        <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
        <Route path="/register" element={<PublicRoute><Register /></PublicRoute>} />

        {/* Public verification (no auth required) */}
        <Route path="/verify/:code" element={<Layout><VerifyMinutes /></Layout>} />

        {/* Protected routes */}
        <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/meetings/new" element={<ProtectedRoute><CreateMeeting /></ProtectedRoute>} />
        <Route path="/meetings/:id" element={<ProtectedRoute><MeetingDetail /></ProtectedRoute>} />
        <Route path="/meetings/:meetingId/minutes/new" element={<ProtectedRoute><CreateMinutes /></ProtectedRoute>} />
        <Route path="/minutes/:id" element={<ProtectedRoute><MinutesDetail /></ProtectedRoute>} />
        <Route path="/minutes/:id/verify" element={<ProtectedRoute><VerifyMinutes /></ProtectedRoute>} />
        <Route path="/profile" element={<ProtectedRoute><Profile /></ProtectedRoute>} />

        {/* Redirect root to dashboard or login */}
        <Route path="/" element={<Navigate to="/dashboard" replace />} />

        {/* 404 */}
        <Route path="*" element={
          <Layout>
            <div className="page container" style={{ textAlign: 'center', paddingTop: '4rem' }}>
              <h1>404</h1>
              <p>Page not found</p>
            </div>
          </Layout>
        } />
      </Routes>
    </AuthProvider>
  );
}

export default App;
