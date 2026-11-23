import { useId, type SubmitEvent } from 'react';
import type { LoginCredentials } from '../auth/AuthService';
import styles from './LoginForm.module.css';

type LoginFormProps = {
  onLogin: (credentials: LoginCredentials) => void | Promise<void>;
  buttonLabel?: string;
  disabled?: boolean;
  error?: string;
  message?: string;
};

export default function LoginForm({
  onLogin,
  buttonLabel = 'Log in',
  disabled = false,
  error,
  message,
}: LoginFormProps) {
  const titleId = useId();

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (disabled) return;
    const data = new FormData(event.currentTarget);
    void onLogin({
      username: String(data.get('username') ?? ''),
      password: String(data.get('password') ?? ''),
      rememberme: data.get('rememberme') === 'on',
    });
  }

  return (
    <form className={styles.form} onSubmit={handleSubmit} aria-busy={disabled} aria-labelledby={titleId}>
      <header className={styles.header}>
        <h1 id={titleId}>Please, login</h1>
        <p>Enter your details to log in.</p>
      </header>
      <fieldset disabled={disabled}>
        <label className={styles.field}>
          Username
          <input name="username" type="text" autoComplete="username" required />
        </label>
        <label className={styles.field}>
          Password
          <input name="password" type="password" autoComplete="current-password" required />
        </label>
        <label className={styles.remember}>
          <input name="rememberme" type="checkbox" />
          Remember me
        </label>
      </fieldset>
      {error && <p className={styles.error} role="alert">{error}</p>}
      {message && <p className={styles.success} role="status">{message}</p>}
      <button className={styles.submit} type="submit" disabled={disabled}>
        {buttonLabel}
      </button>
    </form>
  );
}
