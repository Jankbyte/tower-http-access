import {
  createBrowserRouter,
  Navigate,
  redirect,
  type MiddlewareFunction,
} from "react-router";
import Root from './Root';
import LoginPage from './login/LoginPage';
import NotesPage from './notes/NotesPage';
import NotePage from './notes/NotePage';
import type NoteClient from './notes/NoteClient';
import type AuthStore from './auth/AuthStore';
import RequireAuth from './auth/RequireAuth';
import AuthRouteError from './auth/AuthRouteError';
import { loginPath } from './auth/navigation';
import ProfilePage from './profile/ProfilePage';
import { BASE_PATH } from './context';

export function createRouter(authStore: AuthStore, noteClient: NoteClient) {
  const requireAuth: MiddlewareFunction = async ({ request }, next) => {
    await authStore.initialize();
    const auth = authStore.getSnapshot();
    if (auth.status === 'error') throw auth.error;
    if (auth.status !== 'authenticated') {
      const url = new URL(request.url);
      throw redirect(loginPath(url.pathname + url.search + url.hash));
    }
    return next();
  };

  return createBrowserRouter([
    {
      path: `${BASE_PATH}`,
      element: <Root authStore={authStore} />,
      children: [
        {
          path: 'login',
          element: <LoginPage authStore={authStore} />
        },
        {
          middleware: [requireAuth],
          element: <RequireAuth authStore={authStore} />,
          errorElement: <AuthRouteError authStore={authStore} />,
          children: [
            {
              index: true,
              element: <Navigate to="notes" replace />
            },
            {
              path: 'notes',
              element: <NotesPage noteClient={noteClient} />
            },
            {
              path: 'notes/:id',
              element: <NotePage noteClient={noteClient} />,
            },
            {
              path: 'profile',
              element: <ProfilePage authStore={authStore} />
            },
          ],
        }
      ]
    },
  ]);
}
