import assert from 'node:assert/strict';
import { test } from 'node:test';
import AuthStore from '../src/auth/AuthStore.ts';

const user = { username: 'alex', authorities: [] };
const credentials = { username: 'alex', password: 'password', rememberme: false };
const service = (overrides = {}) => ({
  getCurrentUser: async () => null,
  authenticate: async () => {},
  logout: async () => {},
  ...overrides,
});

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

test('components and middleware share one initialization and a stable snapshot', async () => {
  const response = deferred();
  let calls = 0;
  const store = new AuthStore(service({ getCurrentUser: () => { calls++; return response.promise; } }));
  assert.equal(store.getSnapshot().status, 'loading');
  const first = store.initialize();
  assert.equal(store.initialize(), first);
  await Promise.resolve();
  assert.equal(calls, 1);
  response.resolve(user);
  await first;
  const snapshot = store.getSnapshot();
  assert.deepEqual(snapshot, { status: 'authenticated', user });
  await store.initialize();
  assert.equal(store.getSnapshot(), snapshot);
  assert.equal(calls, 1);
});

test('initialization errors stay distinct from anonymous sessions and support explicit retry', async () => {
  let calls = 0;
  const store = new AuthStore(service({ getCurrentUser: async () => {
    if (++calls === 1) throw new Error('offline');
    return null;
  } }));
  await store.initialize();
  assert.equal(store.getSnapshot().status, 'error');
  await store.initialize();
  assert.equal(calls, 1);
  await store.refresh();
  assert.equal(store.getSnapshot().status, 'unauthenticated');
});

test('login waits for initialization and publishes the server user to every subscriber', async () => {
  let loggedIn = false;
  const store = new AuthStore(service({
    getCurrentUser: async () => loggedIn ? user : null,
    authenticate: async () => { loggedIn = true; },
  }));
  let firstUpdates = 0;
  let secondUpdates = 0;
  const unsubscribe = store.subscribe(() => { firstUpdates++; });
  store.subscribe(() => { secondUpdates++; });
  await store.authenticate(credentials);
  assert.deepEqual(store.getSnapshot(), { status: 'authenticated', user });
  assert.equal(firstUpdates, secondUpdates);
  unsubscribe();
  const previous = firstUpdates;
  store.invalidate();
  assert.equal(firstUpdates, previous);
  assert.equal(store.getSnapshot().status, 'unauthenticated');
});

test('invalid credentials leave the session anonymous and reject to the form', async () => {
  const store = new AuthStore(service({ authenticate: async () => { throw new Error('bad credentials'); } }));
  await assert.rejects(store.authenticate(credentials), /bad credentials/);
  assert.equal(store.getSnapshot().status, 'unauthenticated');
});

test('failure to load the user after login is retryable and does not claim authentication', async () => {
  let calls = 0;
  const store = new AuthStore(service({ getCurrentUser: async () => {
    if (++calls === 1) return null;
    if (calls === 2) throw new Error('server unavailable');
    return user;
  } }));
  await assert.rejects(store.authenticate(credentials), /server unavailable/);
  assert.equal(store.getSnapshot().status, 'error');
  await store.refresh();
  assert.equal(store.getSnapshot().status, 'authenticated');
});

test('login rejects when the server does not establish a session', async () => {
  const store = new AuthStore(service());
  await assert.rejects(store.authenticate(credentials), /No authenticated session/);
  assert.equal(store.getSnapshot().status, 'unauthenticated');
});

test('a stale user response cannot restore authentication after invalidation', async () => {
  const response = deferred();
  const store = new AuthStore(service({ getCurrentUser: () => response.promise }));
  const pending = store.initialize();
  store.invalidate();
  response.resolve(user);
  await pending;
  assert.equal(store.getSnapshot().status, 'unauthenticated');
});

test('logout clears authentication and prevents an older refresh from restoring it', async () => {
  const response = deferred();
  let calls = 0;
  const store = new AuthStore(service({ getCurrentUser: async () => ++calls === 1 ? user : response.promise }));
  await store.initialize();
  const pending = store.refresh();
  await store.logout();
  response.resolve(user);
  await pending;
  assert.equal(store.getSnapshot().status, 'unauthenticated');
});

test('logout failure preserves the current user', async () => {
  const store = new AuthStore(service({ getCurrentUser: async () => user,
    logout: async () => { throw new Error('offline'); } }));
  await store.initialize();
  await assert.rejects(store.logout(), /offline/);
  assert.equal(store.getSnapshot().status, 'authenticated');
});

test('logout failure during a refresh reports an error instead of staying loading', async () => {
  const response = deferred();
  const store = new AuthStore(service({ getCurrentUser: () => response.promise,
    logout: async () => { throw new Error('offline'); } }));
  const pending = store.initialize();
  await assert.rejects(store.logout(), /offline/);
  response.resolve(user);
  await pending;
  assert.equal(store.getSnapshot().status, 'error');
});

test('an authentication response cannot undo a newer invalidation', async () => {
  const response = deferred();
  const store = new AuthStore(service({ authenticate: () => response.promise }));
  await store.initialize();
  const pending = store.authenticate(credentials);
  await Promise.resolve();
  store.invalidate();
  response.resolve();
  await pending;
  assert.equal(store.getSnapshot().status, 'unauthenticated');
});

test('concurrent login operations are rejected instead of racing server sessions', async () => {
  const response = deferred();
  let loggedIn = false;
  const store = new AuthStore(service({
    getCurrentUser: async () => loggedIn ? user : null,
    authenticate: async () => { await response.promise; loggedIn = true; },
  }));
  await store.initialize();
  const pending = store.authenticate(credentials);
  await assert.rejects(store.authenticate(credentials), /already in progress/);
  response.resolve();
  await pending;
  assert.equal(store.getSnapshot().status, 'authenticated');
});


test('refresh keeps authenticated routes mounted and publishes fresh server roles', async () => {
  const response = deferred();
  let calls = 0;
  const store = new AuthStore(service({
    getCurrentUser: () => ++calls === 1 ? Promise.resolve(user) : response.promise,
  }));
  await store.initialize();
  const snapshot = store.getSnapshot();
  const pending = store.refresh();
  assert.equal(store.getSnapshot(), snapshot);
  const updated = { ...user, authorities: ['ROLE_ADMIN'] };
  response.resolve(updated);
  await pending;
  assert.deepEqual(store.getSnapshot(), { status: 'authenticated', user: updated });
  assert.equal(calls, 2);
});

test('profile fetch failures stay local while expired sessions invalidate authentication', async () => {
  let mode = 'ok';
  const store = new AuthStore(service({ getCurrentUser: async () => {
    if (mode === 'error') throw new Error('offline');
    return mode === 'expired' ? null : user;
  } }));
  await store.initialize();
  const snapshot = store.getSnapshot();
  mode = 'error';
  await assert.rejects(store.getCurrentUser(), /offline/);
  assert.equal(store.getSnapshot(), snapshot);
  mode = 'ok';
  assert.deepEqual(await store.getCurrentUser(), user);
  mode = 'expired';
  assert.equal(await store.getCurrentUser(), null);
  assert.equal(store.getSnapshot().status, 'unauthenticated');
});
