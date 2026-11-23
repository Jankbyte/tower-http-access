import {
  createBrowserRouter,
} from "react-router";
import App from './App';
import LoginPage from './login/LoginPage';
import {authMiddleware} from './login/auth';
import NotesPage from './notes/NotesPage';
import {AppServices, BASE_PATH} from './context';
import { createElement } from 'react';

const router = createBrowserRouter([
  {
    path: `${BASE_PATH}`,
    Component: App,
    children: [
      {
        path: 'login',
        element: createElement(LoginPage, { authService: AppServices.authService }),
      },
      {
        path: 'notes',
        middleware: [authMiddleware],
        Component: NotesPage
      }
    ]
  },
]);

export default router;
