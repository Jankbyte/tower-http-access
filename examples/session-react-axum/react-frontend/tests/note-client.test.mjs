import assert from 'node:assert/strict';
import { test } from 'node:test';
import NoteClient from '../src/notes/NoteClient.ts';

test('note CRUD matches backend routes, JSON bodies, CSRF and empty responses', async () => {
  const original = globalThis.fetch;
  const calls = [];
  let token = 'first';
  const note = { title: 'Title', content: 'Content' };
  globalThis.fetch = async (url, options) => {
    calls.push({ url, ...options });
    if (options.method === 'GET') return Response.json(note);
    if (options.method === 'POST') return Response.json({ id: 7 });
    return new Response(null, { status: 200 });
  };
  try {
    const client = new NoteClient({ invalidate() { assert.fail('unexpected invalidation'); } }, { getCookie: () => token });
    assert.deepEqual(await client.read(7), note);
    assert.equal(await client.create(note), 7);
    token = 'second';
    await client.replace(7, note);
    await client.delete(7);
    assert.deepEqual(calls.map(call => [call.url, call.method]), [
      ['/v1/notes/7', 'GET'], ['/v1/notes/', 'POST'],
      ['/v1/notes/7', 'PUT'], ['/v1/notes/7', 'DELETE'],
    ]);
    assert.equal(calls[1].body, JSON.stringify(note));
    assert.equal(calls[1].headers['Content-Type'], 'application/json');
    assert.equal(calls[1].headers['x-xsrf-token'], 'first');
    assert.equal(calls[2].headers['x-xsrf-token'], 'second');
    assert.equal(calls[0].headers['x-xsrf-token'], undefined);
    for (const call of calls) {
      assert.equal(call.credentials, 'same-origin');
      assert.equal(call.redirect, 'error');
    }
  } finally { globalThis.fetch = original; }
});

test('only 401 invalidates authentication; invalid writes never reach the server', async () => {
  const original = globalThis.fetch;
  let invalidations = 0;
  let calls = 0;
  let status = 401;
  globalThis.fetch = async () => { calls++; return new Response(null, { status }); };
  const client = new NoteClient({ invalidate() { invalidations++; } }, { getCookie: () => null });
  try {
    await assert.rejects(client.read(1), /session has expired/);
    for (status of [403, 404, 500]) await assert.rejects(client.read(1));
    assert.equal(invalidations, 1);
    const before = calls;
    await assert.rejects(client.create({ title: '', content: '' }), /CSRF/);
    await assert.rejects(client.read(-1), /Note ID/);
    assert.equal(calls, before);
  } finally { globalThis.fetch = original; }
});

test('list loads note IDs and titles from the collection endpoint', async () => {
  const original = globalThis.fetch;
  const notes = [{ id: 1, title: 'First' }, { id: 5, title: 'Second' }];
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/v1/notes/');
    assert.equal(options.method, 'GET');
    return Response.json(notes);
  };
  try {
    const client = new NoteClient({ invalidate() {} }, { getCookie: () => null });
    assert.deepEqual(await client.list(), notes);
  } finally { globalThis.fetch = original; }
});
