import type ApiClient from '../api/ApiClient';
import type { LoginCredentials } from '../login/LoginForm';

export type CurrentUser = {
  username: string;
  authorities: string[];
};

export default class AuthService {
  private readonly apiClient: ApiClient;

  constructor(apiClient: ApiClient) {
    this.apiClient = apiClient;
  }

  async getCurrentUser(): Promise<CurrentUser | null> {
    const response = await this.apiClient.request('/v1/ui/auth/me', { cache: 'no-store' });
    if (response.status === 401) return null;
    if (!response.ok) {
      throw new Error('Unable to load the current user. Please try again.');
    }
    return response.json();
  }

  async authenticate(credentials: LoginCredentials): Promise<void> {
    const response = await this.apiClient.post('/v1/ui/auth/login', new URLSearchParams({
      username: credentials.username,
      password: credentials.password,
      remember_me: String(credentials.rememberme),
    }));

    if (!response.ok) {
      throw new Error('Login failed. Please check your credentials and try again.');
    }
  }
}
