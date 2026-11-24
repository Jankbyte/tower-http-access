import styles from './RetryErrorMessage.module.css';

type RetryErrorMessageProps = {
  message: string;
  onRetry: () => void | Promise<void>;
  retryDisabled?: boolean;
};

export default function RetryErrorMessage({
  message,
  onRetry,
  retryDisabled = false,
}: RetryErrorMessageProps) {
  return (
    <div className={styles.error} role="alert">
      <p className={styles.message}>{message}</p>
      <button className={styles.retry} type="button" disabled={retryDisabled} onClick={onRetry}>Retry</button>
    </div>
  );
}
