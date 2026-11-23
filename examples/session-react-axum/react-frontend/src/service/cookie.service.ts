export default class CookieService {
  getAllCookies(): Record<string, string> {
    return document.cookie.split('; ')
      .reduce((cookies, cookie) => {
          const [name, value] = cookie.split('=');
          cookies[name] = decodeURIComponent(value || '');
          return cookies;
        }, {} as Record<string, string>
      );
  }

  getCookie(name: string): string | null {
    const cookies = this.getAllCookies();
    return cookies[name] || null;
  }

  getCookieByName(name: string, shouldDecode: boolean = true): string | null {
    const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
    if (match) {
      return shouldDecode ? decodeURIComponent(match[2]) : match[2];
    }
    return null;
  }

  setCookie(name: string, value: string, days?: number, path: string = '/'): void {
    let cookie = `${name}=${encodeURIComponent(value)}`;
    
    if (days) {
      const expires = new Date();
      expires.setDate(expires.getDate() + days);
      cookie += `; expires=${expires.toUTCString()}`;
    }
    
    cookie += `; path=${path}`;
    document.cookie = cookie;
  }

  deleteCookie(name: string, path: string = '/'): void {
    this.setCookie(name, '', -1, path);
  }

  hasCookie(name: string): boolean {
    return this.getCookie(name) !== null;
  }
}
