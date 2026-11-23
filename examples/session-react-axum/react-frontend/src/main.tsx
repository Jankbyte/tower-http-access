import { RouterProvider } from "react-router";
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import ApiClient from './api/ApiClient'
import AuthService from './auth/AuthService'
import { createRouter } from './router'

const apiClient = new ApiClient();
const authService = new AuthService(apiClient);
const router = createRouter(authService);

const container = document.getElementById('root');
const root = createRoot(container!)

root.render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
