import { useState } from 'react';
import type AuthService from '../auth/AuthService';
import LoginForm, { type LoginCredentials } from './LoginForm';
import './LoginPage.css';

type LoginPageProps = {
  authService: AuthService;
};

function LoginPage({ authService }: LoginPageProps) {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  async function handleLogin(credentials: LoginCredentials) {
    if (isSubmitting) return;
    setIsSubmitting(true);
    setMessage('');
    setError('');

    try {
      await authService.authenticate(credentials);

      setMessage('Login successful.');
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to log in. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <main className="login-page">
      <LoginForm
        onLogin={handleLogin}
        buttonLabel={isSubmitting ? 'Logging in…' : 'Log in'}
        disabled={isSubmitting}
        error={error}
        message={message}
      />
    </main>
  )
}

export default LoginPage;
