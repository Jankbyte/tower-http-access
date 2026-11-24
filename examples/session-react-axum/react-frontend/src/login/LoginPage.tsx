import { useState } from 'react';
import { Navigate, useLocation } from 'react-router';
import type AuthStore from '../auth/AuthStore';
import useAuth from '../auth/useAuth';
import AuthStatus from '../auth/AuthStatus';
import { returnPath } from '../auth/navigation';
import LoginForm, { type LoginCredentials } from './LoginForm';
import CenteredPage from '../components/centered/CenteredPage';

type LoginPageProps = {
  authStore: AuthStore;
};

function LoginPage({ authStore }: LoginPageProps) {
  const auth = useAuth(authStore);
  const location = useLocation();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');

  async function handleLogin(credentials: LoginCredentials) {
    if (isSubmitting) return;
    setIsSubmitting(true);
    setError('');

    try {
      await authStore.authenticate(credentials);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to log in. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  }

  switch (auth.status) {
    case 'loading':
    case 'error':
      return <AuthStatus authStore={authStore} />;

    case 'authenticated':
      return <Navigate to={returnPath(location.search)} replace />;

    case 'unauthenticated':
      return (
        <CenteredPage>
          <LoginForm
            onLogin={handleLogin}
            buttonLabel={isSubmitting ? 'Logging in…' : 'Log in'}
            disabled={isSubmitting}
            error={error}
          />
        </CenteredPage>
      );
  }
}

export default LoginPage;
