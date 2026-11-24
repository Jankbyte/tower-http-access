import type AuthStore from '../auth/AuthStore';
import type CookieService from '../service/cookie.service';

export type Note = {
  title: string;
  content: string;
};

export type NoteSummary = { id: number; title: string };

export default class NoteClient {
  private readonly authStore: Pick<AuthStore, 'invalidate'>;
  private readonly cookieService: Pick<CookieService, 'getCookie'>;

  constructor(authStore: Pick<AuthStore, 'invalidate'>, cookieService: Pick<CookieService, 'getCookie'>) {
    this.authStore = authStore;
    this.cookieService = cookieService;
  }

  async list(): Promise<NoteSummary[]> {
    const response = await this.request('/v1/notes/', 'GET');
    return response.json();
  }

  async read(id: number): Promise<Note> {
    const response = await this.request(this.path(id), 'GET');
    return response.json();
  }

  async create(note: Note): Promise<number> {
    const response = await this.request('/v1/notes/', 'POST', note);
    const result: { id: number } = await response.json();
    return result.id;
  }

  async replace(id: number, note: Note): Promise<void> {
    await this.request(this.path(id), 'PUT', note);
  }

  async delete(id: number): Promise<void> {
    await this.request(this.path(id), 'DELETE');
  }

  private path(id: number): string {
    if (!Number.isInteger(id) || id < 0 || id > 0xffffffff) {
      throw new Error('Note ID must be an unsigned 32-bit integer.');
    }
    return `/v1/notes/${id}`;
  }

  private async request(path: string, method: string, note?: Note): Promise<Response> {
    const headers: Record<string, string> = {};
    if (method !== 'GET') {
      const token = this.cookieService.getCookie('XSRF-TOKEN');
      if (!token) throw new Error('CSRF token is missing. Please reload the page and try again.');
      headers['x-xsrf-token'] = token;
    }
    if (note) headers['Content-Type'] = 'application/json';
    const response = await fetch(path, {
      method,
      headers,
      body: note ? JSON.stringify(note) : undefined,
      credentials: 'same-origin',
      redirect: 'error',
      cache: 'no-store',
    });
    if (response.status === 401) {
      this.authStore.invalidate();
      throw new Error('Your session has expired. Please log in again.');
    }
    if (response.status === 403) throw new Error('You do not have permission to perform this action.');
    if (response.status === 404) throw new Error('Note not found.');
    if (!response.ok) throw new Error('Unable to complete the note request. Please try again.');
    return response;
  }
}
