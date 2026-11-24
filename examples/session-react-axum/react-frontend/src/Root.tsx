import './Root.css'
import { Outlet } from "react-router";
import Navbar from './navbar/Navbar'
import type AuthStore from './auth/AuthStore';
import useAuth from './auth/useAuth';
import AuthStatus from './auth/AuthStatus';

function Root({ authStore }: { authStore: AuthStore }) {
  const auth = useAuth(authStore);
  if (auth.status === 'loading' || auth.status === 'error') {
    return <AuthStatus authStore={authStore} />;
  }
  return (
    <div className="app-layout">
      <Navbar user={auth.status === 'authenticated' ? auth.user : null} />
      <Outlet />
    </div>
  )
}

export default Root
