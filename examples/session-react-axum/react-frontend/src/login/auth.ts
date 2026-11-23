import { redirect, type MiddlewareFunction } from "react-router";

const authMiddleware: MiddlewareFunction = async ({ request }, next) => {
  console.log(`${request}`);
  const isAuthenticated = false;
  if (!isAuthenticated) {
    throw redirect('/ui/login');
  }
  return next();
};

export {
    authMiddleware
}
