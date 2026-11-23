import assert from 'node:assert/strict';
import { afterEach, beforeEach, test } from 'node:test';
import ApiClient from '../src/api/ApiClient.ts';

const originalFetch = globalThis.fetch;
const originalWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
const originalDocument = Object.getOwnPropertyDescriptor(globalThis, 'document');
let calls;

beforeEach(() => {
  calls = [];
  Object.defineProperty(globalThis, 'window', {
    configurable: true, value: { location: { origin: 'https://localhost:5173' } },
  });
  Object.defineProperty(globalThis, 'document', {
    configurable: true, value: { cookie: '' },
  });
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return new Response(null, { status: 204 });
  };
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  for (const [name, descriptor] of [['window', originalWindow], ['document', originalDocument]]) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else delete globalThis[name];
  }
});

test('safe requests do not initialize CSRF or send a supplied CSRF header', async () => {
  await new ApiClient().request('/v1/notes', { headers: { 'x-xsrf-token': 'stale' } });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.headers.has('x-xsrf-token'), false);
});

test('unsafe requests read the current cookie and preserve encoded form data', async () => {
  const client = new ApiClient();
  document.cookie = 'other=value; XSRF-TOKEN=first';
  const body = new URLSearchParams({ password: 'a+b &c' });
  await client.post('/v1/ui/auth/login', body);
  document.cookie = 'XSRF-TOKEN=second';
  await client.request('/v1/notes/1', { method: 'DELETE' });
  assert.equal(calls[0].options.headers.get('x-xsrf-token'), 'first');
  assert.equal(calls[1].options.headers.get('x-xsrf-token'), 'second');
  assert.equal(calls[0].options.credentials, 'same-origin');
  assert.equal(calls[0].options.redirect, 'error');
  const request = new Request(calls[0].url, calls[0].options);
  assert.match(request.headers.get('content-type'), /^application\/x-www-form-urlencoded/);
  assert.equal(new URLSearchParams(await request.text()).get('password'), 'a+b &c');
});

test('concurrent unsafe requests share one CSRF initialization', async () => {
  let finishInitialization;
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    if (url.pathname === '/v1/ui/auth/me') {
      await new Promise(resolve => { finishInitialization = resolve; });
      document.cookie = 'XSRF-TOKEN=initialized';
    }
    return new Response(null, { status: 204 });
  };
  const client = new ApiClient();
  const first = client.post('/v1/notes', 'first');
  const second = client.post('/v1/notes', 'second');
  assert.equal(calls.length, 1);
  finishInitialization();
  await Promise.all([first, second]);
  assert.equal(calls.length, 3);
  assert.equal(calls[1].options.headers.get('x-xsrf-token'), 'initialized');
  assert.equal(calls[2].options.headers.get('x-xsrf-token'), 'initialized');
});

test('failed initialization can be retried without sending the unsafe request', async () => {
  const client = new ApiClient();
  globalThis.fetch = async () => new Response(null, { status: 500 });
  await assert.rejects(client.post('/v1/notes', ''), /Unable to initialize/);
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    if (url.pathname === '/v1/ui/auth/me') document.cookie = 'XSRF-TOKEN=retry';
    return new Response(null, { status: 204 });
  };
  await client.post('/v1/notes', '');
  assert.equal(calls.length, 2);
});

test('an anonymous /me response initializes CSRF before login', async () => {
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    if (url.pathname === '/v1/ui/auth/me') {
      document.cookie = 'XSRF-TOKEN=anonymous';
      return new Response(null, { status: 401 });
    }
    return new Response(null, { status: 200 });
  };
  await new ApiClient().post('/v1/ui/auth/login', new URLSearchParams());
  assert.equal(calls.length, 2);
  assert.equal(calls[0].url.pathname, '/v1/ui/auth/me');
  assert.equal(calls[1].options.headers.get('x-xsrf-token'), 'anonymous');
});

test('missing cookies after initialization and foreign destinations are rejected', async () => {
  const client = new ApiClient();
  await assert.rejects(client.post('/v1/notes', ''), /CSRF token is missing/);
  assert.equal(calls.length, 1);
  await assert.rejects(client.post('https://external.example/v1/notes', ''), /must target/);
  await assert.rejects(client.request('/ui/login'), /must target/);
  assert.equal(calls.length, 1);
});
