import { Link } from 'react-router';
import type { NoteSummary } from './NoteClient';
import styles from './NoteList.module.css';

export default function NoteList({ notes }: { notes: NoteSummary[] }) {
  if (notes.length === 0) return <p>No notes yet.</p>;
  return (
    <ul className={styles.list}>
      {notes.map(note => (
        <li className={styles.row} key={note.id}>
          <Link className={styles.link} to={String(note.id)}>
            <span className={styles.id}>#{note.id}</span>
            <span className={styles.title}>{note.title}</span>
          </Link>
        </li>
      ))}
    </ul>
  );
}
