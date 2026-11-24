import { BASE_PATH } from '../context';

export function loginPath(returnTo: string): string {
  return `${BASE_PATH}login?${new URLSearchParams({ returnTo })}`;
}

export function returnPath(search: string): string {
  const path = new URLSearchParams(search).get('returnTo');
  // Accept only application paths and avoid redirecting back into the login page.
  if (path?.startsWith(BASE_PATH) && !path.startsWith('//') && !path.includes('\\')
      && path.split(/[?#]/)[0] !== `${BASE_PATH}login`) return path;
  return `${BASE_PATH}notes`;
}
