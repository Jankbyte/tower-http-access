import type { ReactNode } from 'react';
import styles from './CardPane.module.css';

export default function CardPane({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`${styles.pane} ${className}`}>{children}</div>;
}
