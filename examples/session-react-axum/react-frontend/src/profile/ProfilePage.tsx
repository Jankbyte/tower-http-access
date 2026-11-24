import { useEffect, useState } from 'react';
import type AuthStore from '../auth/AuthStore';
import type { CurrentUser } from '../auth/AuthService';
import CenteredPage from '../components/centered/CenteredPage';
import CardPane from '../components/card/CardPane';
import RetryErrorMessage from '../components/retry/RetryErrorMessage';

export default function ProfilePage({ authStore }: { authStore: AuthStore }) {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let ignore = false;
    authStore.getCurrentUser().then(user => {
      if (!ignore) setUser(user);
    }, error => {
      if (!ignore) setLoadError(error instanceof Error ? error.message : 'Unable to load profile.');
    }).finally(() => { if (!ignore) setLoading(false); });
    return () => { ignore = true; };
  }, [authStore, attempt]);
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const [error, setError] = useState('');

  async function logout() {
    setIsLoggingOut(true);
    setError('');
    try {
      await authStore.logout();
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to log out.');
    } finally {
      setIsLoggingOut(false);
    }
  }

  return (
    <CenteredPage>
      <CardPane>
      <h1>Profile</h1>
      {loading ? <p role="status">Loading profile…</p> : loadError ? (
        <RetryErrorMessage message={loadError} onRetry={() => {
          setLoading(true);
          setLoadError('');
          setAttempt(attempt => attempt + 1);
        }} />
      ) : user && <>
      <p>Username: {user.username}</p>
      <p>Roles: {user.authorities.length > 0 ? user.authorities.join(', ') : 'None'}</p>
      <button type="button" disabled={isLoggingOut} onClick={logout}>
        {isLoggingOut ? 'Logging out…' : 'Log out'}
      </button>
      {error && <p role="alert">{error}</p>}
      </>}
      </CardPane>
    </CenteredPage>
  );
}
