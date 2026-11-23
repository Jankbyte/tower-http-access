import {
  createBrowserRouter,
} from "react-router";
import Root from './Root';
import LoginPage from './login/LoginPage';
import NotesPage from './notes/NotesPage';
import type AuthService from './auth/AuthService';
import { BASE_PATH } from './context';

export function createRouter(authService: AuthService) {
  return createBrowserRouter([
    {
      path: `${BASE_PATH}`,
      Component: Root,
      children: [
        {
          path: 'login',
          element: <LoginPage authService={authService} />
        },
        {
          path: 'notes',
          Component: NotesPage
        }
      ]
    },
  ]);
}
