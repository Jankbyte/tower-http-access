import { Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router';
import type NoteClient from './NoteClient';
import type { Note } from './NoteClient';
import CenteredPage from '../components/centered/CenteredPage';
import CardPane from '../components/card/CardPane';
import RetryErrorMessage from '../components/retry/RetryErrorMessage';
import { useParams } from 'react-router';
import styles from './NotesPage.module.css';

export default function NotePage({ noteClient }: { noteClient: NoteClient }) {
  const { id } = useParams();
  const navigate = useNavigate();
  const [removing, setRemoving] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<{ id: string | undefined; note?: Note; error?: string } | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let ignore = false;
    noteClient.read(Number(id)).then(note => {
      if (!ignore) setResult({ id, note });
    }, error => {
      if (!ignore) setResult({ id, error: error instanceof Error ? error.message : 'Unable to load note.' });
    });
    return () => { ignore = true; };
  }, [noteClient, id, attempt]);

  const current = result?.id === id ? result : null;
  const note = current?.note;

  async function remove() {
    if (removing) return;
    setRemoving(true);
    setError('');
    try {
      await noteClient.delete(Number(id));
      await navigate('..', { relative: 'path', replace: true });
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to remove note.');
      setRemoving(false);
    }
  }

  return (
    <CenteredPage>
      <CardPane className={styles.card}>
        <div className={styles.toolbar}>
          <Link to=".." relative="path">Back to notes</Link>
          {note && <button className={styles.remove} type="button" disabled={removing}
            aria-label={`Remove note: ${note.title}`} onClick={remove}>
            {removing ? '…' : <Trash2 size={18} aria-hidden="true" />}
          </button>}
        </div>
        {!current ? <p role="status">Loading note…</p> : current.error ? (
          <RetryErrorMessage message={current.error} onRetry={() => {
            setResult(null);
            setAttempt(attempt => attempt + 1);
          }} />
        ) : note && (
          <>
            <h1>{note.title}</h1>
            <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{note.content}</p>
          </>
        )}
        {error && <p role="alert">{error}</p>}
      </CardPane>
    </CenteredPage>
  );
}
