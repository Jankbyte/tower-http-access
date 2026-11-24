import type AuthService from './AuthService';
import type { CurrentUser } from './AuthService';
import type { LoginCredentials } from '../login/LoginForm';

export type AuthState =
  | { status: 'loading' }
  | { status: 'authenticated'; user: CurrentUser }
  | { status: 'unauthenticated' }
  | { status: 'error'; error: Error };

type AuthenticationService = Pick<AuthService, 'getCurrentUser' | 'authenticate' | 'logout'>;

export default class AuthStore {
  private readonly service: AuthenticationService;
  private state: AuthState = { status: 'loading' };
  private readonly listeners = new Set<() => void>();
  private initialized = false;
  private initialization: Promise<void> | null = null;
  private version = 0;
  private busy = false;

  constructor(service: AuthenticationService) {
    this.service = service;
  }

  getSnapshot = (): AuthState => this.state;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };

  private publish(state: AuthState) {
    this.state = state;
    this.listeners.forEach(listener => listener());
  }

  initialize(): Promise<void> {
    if (this.initialization) return this.initialization;
    if (this.initialized) return Promise.resolve();
    return this.refresh();
  }

  /** Refresh explicitly after an initialization error or an external session change. */
  refresh(): Promise<void> {
    if (this.initialization) return this.initialization;
    if (this.busy) return Promise.resolve();
    const version = ++this.version;
    const pending = Promise.resolve()
      .then(() => this.service.getCurrentUser())
      .then(user => {
        if (version !== this.version) return;
        this.initialized = true;
        this.publish(user ? { status: 'authenticated', user } : { status: 'unauthenticated' });
      }, error => {
        if (version !== this.version) return;
        this.initialized = true;
        this.publish({ status: 'error', error: asError(error) });
      })
      .finally(() => {
        if (this.initialization === pending) this.initialization = null;
      });
    this.initialization = pending;
    // Keep authenticated routes mounted while refreshing their server data.
    if (this.state.status !== 'authenticated') this.publish({ status: 'loading' });
    return pending;
  }

  /** Fetch profile data without replacing the global session with a page loading/error state. */
  async getCurrentUser(): Promise<CurrentUser | null> {
    const version = this.version;
    const user = await this.service.getCurrentUser();
    if (version !== this.version) return null;
    if (!user) this.invalidate();
    return user;
  }

  async authenticate(credentials: LoginCredentials): Promise<void> {
    await this.initialize();
    if (this.state.status === 'error') throw this.state.error;
    if (this.busy) throw new Error('An authentication operation is already in progress.');
    this.busy = true;
    const version = ++this.version;
    let loggedIn = false;
    try {
      await this.service.authenticate(credentials);
      loggedIn = true;
      if (version !== this.version) return;
      const user = await this.service.getCurrentUser();
      if (version !== this.version) return;
      this.initialized = true;
      if (!user) {
        this.invalidate();
        throw new Error('No authenticated session was found after login.');
      }
      this.publish({ status: 'authenticated', user });
    } catch (error) {
      // Invalid credentials stay a form error. Failure to read a newly created
      // session is a distinct, retryable authentication-state error.
      if (loggedIn && version === this.version) {
        this.initialized = true;
        this.publish({ status: 'error', error: asError(error) });
      }
      throw error;
    } finally {
      this.busy = false;
    }
  }

  async logout(): Promise<void> {
    if (this.busy) throw new Error('An authentication operation is already in progress.');
    this.busy = true;
    const version = ++this.version;
    this.initialization = null;
    try {
      await this.service.logout();
      if (version === this.version) this.invalidate();
    } catch (error) {
      if (version === this.version && this.state.status === 'loading') {
        this.initialized = true;
        this.publish({ status: 'error', error: asError(error) });
      }
      throw error;
    } finally {
      this.busy = false;
    }
  }

  /** Call when a protected API operation returns 401, not for invalid login credentials. */
  invalidate(): void {
    ++this.version;
    this.initialized = true;
    this.initialization = null;
    this.publish({ status: 'unauthenticated' });
  }
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}
