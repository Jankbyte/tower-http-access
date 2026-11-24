import { useEffect, useState } from 'react';
import CenteredPage from '../components/centered/CenteredPage';
import CardPane from '../components/card/CardPane';
import RetryErrorMessage from '../components/retry/RetryErrorMessage';
import type NoteClient from './NoteClient';
import type { NoteSummary } from './NoteClient';
import NoteList from './NoteList';
import styles from './NotesPage.module.css';

export default function NotesPage({ noteClient }: { noteClient: NoteClient }) {
  const [notes, setNotes] = useState<NoteSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let ignore = false;
    noteClient.list().then(notes => {
      if (!ignore) setNotes(notes);
    }, error => {
      if (!ignore) setError(error instanceof Error ? error.message : 'Unable to load notes.');
    }).finally(() => { if (!ignore) setLoading(false); });
    return () => { ignore = true; };
  }, [noteClient, attempt]);

  return (
    <CenteredPage>
      <CardPane className={styles.card}>
        <h1>Notes</h1>
        {loading ? <p role="status">Loading notes…</p> : error ? (
          <RetryErrorMessage message={error} onRetry={() => { setLoading(true); setError(''); setAttempt(attempt => attempt + 1); }} />
        ) : <NoteList notes={notes} />}
      </CardPane>
    </CenteredPage>
  );
}
