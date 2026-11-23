import ApiClient from './api/ApiClient';
import AuthService from './auth/AuthService';

export const BASE_PATH = import.meta.env.BASE_URL;

export class AppServices {
  static readonly apiClient = new ApiClient();
  static readonly authService = new AuthService(AppServices.apiClient);
}
