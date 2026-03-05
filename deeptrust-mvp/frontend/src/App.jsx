import { Navigate, Route, Routes } from 'react-router-dom';
import Login from './pages/Login';
import FaceAuth from './pages/FaceAuth';
import Dashboard from './pages/Dashboard';

function ProtectedRoute({ children }) {
  const token = localStorage.getItem('deeptrust_token');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/login" replace />} />
      <Route path="/login" element={<Login />} />
      <Route path="/face-auth" element={<FaceAuth />} />
      <Route
        path="/dashboard"
        element={(
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        )}
      />
    </Routes>
  );
}
