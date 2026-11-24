import assert from 'node:assert/strict';
import { afterEach, beforeEach, test } from 'node:test';
import AuthService from '../src/auth/AuthService.ts';
import CookieService from '../src/service/cookie.service.ts';

const originalFetch = globalThis.fetch;
const originalDocument = Object.getOwnPropertyDescriptor(globalThis, 'document');
const credentials = { username: 'alex', password: 'a+b &c', rememberme: true };
let calls;

beforeEach(() => {
  calls = [];
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
  if (originalDocument) Object.defineProperty(globalThis, 'document', originalDocument);
  else delete globalThis.document;
});

test('current-user lookup returns the user or null for an anonymous session', async () => {
  const service = new AuthService(new CookieService());
  globalThis.fetch = async () => Response.json({ username: 'alex', authorities: [] });
  assert.deepEqual(await service.getCurrentUser(), { username: 'alex', authorities: [] });
  globalThis.fetch = async () => new Response(null, { status: 401 });
  assert.equal(await service.getCurrentUser(), null);
  globalThis.fetch = async () => new Response(null, { status: 500 });
  await assert.rejects(service.getCurrentUser(), /Unable to load/);
});

test('login sends encoded credentials and reads the current token on each attempt', async () => {
  const service = new AuthService(new CookieService());
  document.cookie = 'other=value; XSRF-TOKEN=first';
  await service.authenticate(credentials);
  document.cookie = 'XSRF-TOKEN=second';
  await service.authenticate(credentials);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, '/v1/ui/auth/login');
  assert.equal(calls[0].options.headers['x-xsrf-token'], 'first');
  assert.equal(calls[1].options.headers['x-xsrf-token'], 'second');
  assert.equal(calls[0].options.credentials, 'same-origin');
  assert.equal(calls[0].options.redirect, 'error');
  const request = new Request('https://localhost' + calls[0].url, calls[0].options);
  assert.match(request.headers.get('content-type'), /^application\/x-www-form-urlencoded/);
  const body = new URLSearchParams(await request.text());
  assert.equal(body.get('password'), credentials.password);
  assert.equal(body.get('username'), 'alex');
  assert.equal(body.get('remember_me'), 'true');
});

test('missing CSRF cookies prevent login without sending an initialization request', async () => {
  const service = new AuthService(new CookieService());
  await assert.rejects(service.authenticate(credentials), /CSRF token is missing/);
  assert.equal(calls.length, 0);
  document.cookie = 'XSRF-TOKEN=available';
  await service.authenticate(credentials);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, '/v1/ui/auth/login');
});

test('login uses the cookie received by the initial current-user request', async () => {
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    if (url === '/v1/ui/auth/me') {
      document.cookie = 'XSRF-TOKEN=initialized';
      return new Response(null, { status: 401 });
    }
    return new Response(null, { status: 200 });
  };
  const service = new AuthService(new CookieService());
  assert.equal(await service.getCurrentUser(), null);
  await service.authenticate(credentials);
  assert.equal(calls.length, 2);
  assert.equal(calls[1].url, '/v1/ui/auth/login');
  assert.equal(calls[1].options.headers['x-xsrf-token'], 'initialized');
});

test('rejected credentials propagate a login error', async () => {
  document.cookie = 'XSRF-TOKEN=valid';
  globalThis.fetch = async () => new Response(null, { status: 401 });
  await assert.rejects(new AuthService(new CookieService()).authenticate(credentials), /Login failed/);
});

test('logout submits CSRF, accepts an expired session, and reports server failures', async () => {
  const auth = new AuthService(new CookieService());
  document.cookie = 'XSRF-TOKEN=valid';
  await auth.logout();
  assert.equal(calls[0].url, '/v1/ui/auth/logout');
  assert.equal(calls[0].options.headers['x-xsrf-token'], 'valid');
  globalThis.fetch = async () => new Response(null, { status: 401 });
  await auth.logout();
  globalThis.fetch = async () => new Response(null, { status: 500 });
  await assert.rejects(auth.logout(), /Unable to log out/);
});
