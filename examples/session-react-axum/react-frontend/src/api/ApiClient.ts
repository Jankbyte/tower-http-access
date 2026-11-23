export default class ApiClient {
  private csrfInitialization: Promise<void> | null = null;

  async request(path: string, options: RequestInit = {}): Promise<Response> {
    const url = new URL(path, window.location.origin);
    if (url.origin !== window.location.origin || !url.pathname.startsWith('/v1/')) {
      throw new Error('API requests must target this application’s /v1/ endpoints.');
    }

    const method = (options.method ?? 'GET').toUpperCase();
    const headers = new Headers(options.headers);
    // The client owns this header; never forward a caller-supplied stale token.
    headers.delete('x-xsrf-token');
    if (!['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method)) {
      headers.set('x-xsrf-token', await this.getCsrfToken());
    }

    return fetch(url, {
      ...options,
      method,
      headers,
      credentials: 'same-origin',
      // Do not forward the CSRF header to a redirect destination.
      redirect: 'error',
    });
  }

  post(path: string, body: BodyInit, options: Omit<RequestInit, 'method' | 'body'> = {}) {
    return this.request(path, { ...options, method: 'POST', body });
  }

  private async getCsrfToken(): Promise<string> {
    const existing = this.readCsrfToken();
    if (existing) return existing;

    if (!this.csrfInitialization) {
      this.csrfInitialization = this.initializeCsrf().finally(() => {
        this.csrfInitialization = null;
      });
    }
    await this.csrfInitialization;

    const token = this.readCsrfToken();
    if (!token) {
      throw new Error('CSRF token is missing. Please reload the page and try again.');
    }
    return token;
  }

  private readCsrfToken(): string | undefined {
    const name = 'XSRF-TOKEN=';
    const cookie = document.cookie.split(';')
      .map(value => value.trim())
      .find(value => value.startsWith(name));
    return cookie ? decodeURIComponent(cookie.slice(name.length)) : undefined;
  }

  private async initializeCsrf(): Promise<void> {
    const response = await this.request('/v1/ui/auth/me', { cache: 'no-store' });
    // Anonymous sessions still receive the CSRF cookie from the middleware.
    if (!response.ok && response.status !== 401) {
      throw new Error('Unable to initialize CSRF protection. Please try again.');
    }
  }
}
