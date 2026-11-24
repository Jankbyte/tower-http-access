import { Navigate, Outlet, useLocation } from 'react-router';
import type AuthStore from './AuthStore';
import AuthStatus from './AuthStatus';
import { loginPath } from './navigation';
import useAuth from './useAuth';

/** Middleware guards navigation; this subscription also handles expiry while a page is open. */
export default function RequireAuth({ authStore }: { authStore: AuthStore }) {
  const auth = useAuth(authStore);
  const location = useLocation();
  if (auth.status === 'loading' || auth.status === 'error') return <AuthStatus authStore={authStore} />;
  if (auth.status === 'unauthenticated') {
    return <Navigate to={loginPath(location.pathname + location.search + location.hash)} replace />;
  }
  return <Outlet />;
}
