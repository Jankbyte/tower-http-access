import type AuthStore from './AuthStore';
import useAuth from './useAuth';
import { useRevalidator } from 'react-router';
import RetryErrorMessage from '../components/retry/RetryErrorMessage';

export default function AuthStatus({ authStore }: { authStore: AuthStore }) {
  const auth = useAuth(authStore);
  const revalidator = useRevalidator();
  async function retry() {
    await authStore.refresh();
    await revalidator.revalidate();
  }
  if (auth.status === 'error') {
    return (
      <RetryErrorMessage
        message="Unable to check your session. Please try again."
        onRetry={retry}
        retryDisabled={revalidator.state === 'loading'}
      />
    );
  }
  return <p role="status">Checking your session…</p>;
}
