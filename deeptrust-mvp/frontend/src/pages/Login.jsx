import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import client from '../api/client';
import LoginForm from '../components/LoginForm';
import SecurityInfo from '../components/SecurityInfo';
import StatsPanel from '../components/StatsPanel';

function getFingerprint() {
  return [navigator.userAgent, navigator.language, navigator.platform, window.screen.width].join('|');
}

export default function Login() {
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [attempts, setAttempts] = useState(Number(localStorage.getItem('deeptrust_attempts') || 0));
  const navigate = useNavigate();

  const handleSubmit = async (form, emailValid) => {
    if (!emailValid) {
      setMessage('Enter a valid email address.');
      return;
    }

    try {
      setLoading(true);
      setMessage('');

      const { data } = await client.post('/auth/login', {
        email: form.email,
        password: form.password,
        role: form.role,
        rememberMe: form.rememberMe,
        deviceFingerprint: getFingerprint(),
      });

      if (data.status === 'face_auth_required') {
        sessionStorage.setItem('deeptrust_pending_email', form.email);
        sessionStorage.setItem('deeptrust_pending_fp', getFingerprint());
        navigate('/face-auth');
        return;
      }

      localStorage.setItem('deeptrust_token', data.token);
      localStorage.setItem('deeptrust_user_name', data.user.fullName);
      localStorage.setItem('deeptrust_user_role', data.user.role);
      localStorage.setItem('deeptrust_attempts', '0');
      setAttempts(0);
      navigate('/dashboard');
    } catch (error) {
      const nextAttempts = attempts + 1;
      setAttempts(nextAttempts);
      localStorage.setItem('deeptrust_attempts', String(nextAttempts));
      setMessage(error.response?.data?.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="grid-bg min-h-screen px-4 py-8">
      <div className="mx-auto grid max-w-6xl grid-cols-1 overflow-hidden rounded-2xl border border-cyan-500/20 bg-slate-900/75 shadow-2xl md:grid-cols-5">
        <section className="space-y-4 bg-gradient-to-br from-slate-900 to-blue-900 p-6 md:col-span-2">
          <h1 className="text-3xl font-bold">DeepTrust AI</h1>
          <p className="text-cyan-200">Verifying Digital Reality</p>
          <p className="text-sm text-slate-300">Protecting institutions from AI-generated misinformation.</p>
          <div className="space-y-1 text-sm text-slate-200">
            <p>✔ Prevents deepfake fraud</p>
            <p>✔ Protects digital identity</p>
            <p>✔ Enables forensic authentication</p>
            <p>✔ Supports judicial integrity</p>
          </div>
          <StatsPanel />
          <SecurityInfo />
        </section>

        <section className="p-6 md:col-span-3">
          <h2 className="text-2xl font-semibold">Secure Account Access</h2>
          <p className="mb-4 text-sm text-slate-400">Enter your credentials to access AI forensic dashboard.</p>
          {message && <div className="mb-3 rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-sm text-rose-200">{message}</div>}
          <LoginForm onSubmit={handleSubmit} loading={loading} attempts={attempts} />
        </section>
      </div>
    </main>
  );
}
