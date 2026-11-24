import type { LoginCredentials } from '../login/LoginForm';
import type CookieService from '../service/cookie.service';

export type CurrentUser = {
  username: string;
  authorities: string[];
};

export default class AuthService {
  private readonly cookieService: Pick<CookieService, 'getCookie'>;

  constructor(cookieService: Pick<CookieService, 'getCookie'>) {
    this.cookieService = cookieService;
  }

  async getCurrentUser(): Promise<CurrentUser | null> {
    const response = await fetch('/v1/ui/auth/me', {
      cache: 'no-store',
      credentials: 'same-origin',
      redirect: 'error',
    });
    if (response.status === 401) return null;
    if (!response.ok) {
      throw new Error('Unable to load the current user. Please try again.');
    }
    return response.json();
  }

  async authenticate(credentials: LoginCredentials): Promise<void> {
    const csrfToken = this.cookieService.getCookie('XSRF-TOKEN');
    if (!csrfToken) {
      throw new Error('CSRF token is missing. Please reload the page and try again.');
    }
    const response = await fetch('/v1/ui/auth/login', {
      method: 'POST',
      credentials: 'same-origin',
      redirect: 'error',
      headers: { 'x-xsrf-token': csrfToken },
      // fetch supplies application/x-www-form-urlencoded for URLSearchParams.
      body: new URLSearchParams({
        username: credentials.username,
        password: credentials.password,
        remember_me: String(credentials.rememberme),
      }),
    });

    if (!response.ok) {
      throw new Error('Login failed. Please check your credentials and try again.');
    }
  }

  async logout(): Promise<void> {
    const csrfToken = this.cookieService.getCookie('XSRF-TOKEN');
    if (!csrfToken) throw new Error('CSRF token is missing. Please reload the page and try again.');
    const response = await fetch('/v1/ui/auth/logout', {
      method: 'POST',
      credentials: 'same-origin',
      redirect: 'error',
      headers: { 'x-xsrf-token': csrfToken },
    });
    // An expired session is already logged out.
    if (!response.ok && response.status !== 401) {
      throw new Error('Unable to log out. Please try again.');
    }
  }
}
