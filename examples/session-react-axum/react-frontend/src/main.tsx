import { RouterProvider } from "react-router";
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import AuthService from './auth/AuthService'
import AuthStore from './auth/AuthStore'
import CookieService from './service/cookie.service'
import { createRouter } from './router'
import NoteClient from './notes/NoteClient'

const cookieService = new CookieService();
const authService = new AuthService(cookieService);
const authStore = new AuthStore(authService);
const router = createRouter(authStore, new NoteClient(authStore, cookieService));

const container = document.getElementById('root');
const root = createRoot(container!)

root.render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
