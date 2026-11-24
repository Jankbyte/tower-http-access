import { useEffect, useSyncExternalStore } from 'react';
import type AuthStore from './AuthStore';

/** Subscribe to the same store instance used by services and router middleware. */
export default function useAuth(store: AuthStore) {
  const state = useSyncExternalStore(store.subscribe, store.getSnapshot);

  useEffect(() => {
    store.initialize();
  }, [store]);

  return state;
}
