import type { ReactNode } from 'react';
import styles from './CenteredPage.module.css';

export default function CenteredPage({ children }: { children: ReactNode }) {
  return <main className={styles.page}>{children}</main>;
}
