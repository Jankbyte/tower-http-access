import { useRevalidator } from 'react-router';
import RetryErrorMessage from '../components/retry/RetryErrorMessage';
import type AuthStore from './AuthStore';

export default function AuthRouteError({ authStore }: { authStore: AuthStore }) {
  const revalidator = useRevalidator();

  async function retry() {
    await authStore.refresh();
    await revalidator.revalidate();
  }

  return (
    <RetryErrorMessage
      message="Unable to open this page. Please try again."
      onRetry={retry}
      retryDisabled={revalidator.state === 'loading'}
    />
  );
}
