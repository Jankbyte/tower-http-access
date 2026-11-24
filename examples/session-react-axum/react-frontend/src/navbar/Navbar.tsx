import { Link } from 'react-router';
import { StickyNote } from 'lucide-react';
import { BASE_PATH } from '../context';
import styles from './Navbar.module.css';

type NavbarProps = {
  user?: { username: string } | null;
};

export default function Navbar({ user = null }: NavbarProps) {
  return (
    <nav className={styles.navbar} aria-label="Main navigation">
      <Link className={styles.brand} to={`${BASE_PATH}notes`}>
        <StickyNote size={24} aria-hidden="true" />
        Notes
      </Link>
      {user ? (
        <Link className={styles.profile} to={`${BASE_PATH}profile`}>
          <span className={styles.avatar} aria-hidden="true">
            {user.username.slice(0, 1).toUpperCase()}
          </span>
          <span className={styles.username}>{user.username}</span>
        </Link>
      ) : (
        <Link className={styles.login} to={`${BASE_PATH}login`}>Log In</Link>
      )}
    </nav>
  );
}
