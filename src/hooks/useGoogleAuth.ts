import { useState, useEffect, useCallback } from 'react';

export interface VerifiedGoogleUser {
  uid: string;
  email: string;
  name: string;
  picture: string;
  emailVerified: boolean;
  issuer?: string;
  authenticatedAt: string;
  sessionToken?: string;
}

declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize: (config: any) => void;
          renderButton: (parent: HTMLElement | null, options: any) => void;
          prompt: () => void;
          disableAutoSelect: () => void;
        };
      };
    };
  }
}

const STORAGE_KEY = 'bilanx_verified_google_user';

export function useGoogleAuth() {
  const [user, setUser] = useState<VerifiedGoogleUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [isVerifying, setIsVerifying] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  // Validate cached session with the server on mount
  useEffect(() => {
    let cancelled = false;

    async function validateSession() {
      try {
        const saved = localStorage.getItem(STORAGE_KEY);
        if (!saved) {
          return;
        }
        const parsed = JSON.parse(saved) as VerifiedGoogleUser;
        if (!parsed?.sessionToken || parsed.sessionToken === 'DEMO-SWISS-SANDBOX-TOKEN') {
          localStorage.removeItem(STORAGE_KEY);
          return;
        }

        const res = await fetch('/api/auth/session', {
          headers: {
            Accept: 'application/json',
            Authorization: `Bearer ${parsed.sessionToken}`,
          },
        });

        if (res.ok) {
          const data = await res.json();
          if (!cancelled && data.authenticated && data.user) {
            const validatedUser: VerifiedGoogleUser = {
              ...data.user,
              sessionToken: parsed.sessionToken,
            };
            setUser(validatedUser);
            localStorage.setItem(STORAGE_KEY, JSON.stringify(validatedUser));
            return;
          }
        }

        localStorage.removeItem(STORAGE_KEY);
      } catch (e) {
        console.warn('Failed to validate active Google session:', e);
        localStorage.removeItem(STORAGE_KEY);
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    validateSession();
    return () => {
      cancelled = true;
    };
  }, []);

  const clearAuthError = useCallback(() => {
    setAuthError(null);
  }, []);

  // Send real Google Identity Services ID token (JWT) to backend for cryptographic verification
  const verifyTokenWithBackend = useCallback(async (credential: string) => {
    setIsVerifying(true);
    setAuthError(null);
    try {
      const response = await fetch('/api/auth/verify-google', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ credential }),
      });

      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        throw new Error('Server is still initializing or returned a non-JSON response. Please retry in a moment.');
      }

      const data = await response.json();

      if (!response.ok || !data.success || !data.user) {
        throw new Error(data.error || 'Failed to verify Google credential on the server.');
      }

      const verifiedUser: VerifiedGoogleUser = {
        ...data.user,
        sessionToken: data.sessionToken,
      };
      setUser(verifiedUser);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(verifiedUser));
      return verifiedUser;
    } catch (err: any) {
      const msg = err.message || 'Authentication error during credential verification.';
      setAuthError(msg);
      throw err;
    } finally {
      setIsVerifying(false);
    }
  }, []);

  const instantVerify = useCallback(async (email?: string, name?: string): Promise<VerifiedGoogleUser> => {
    setIsVerifying(true);
    setAuthError(null);
    try {
      const response = await fetch('/api/auth/profile-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ email, name }),
      });

      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        throw new Error('Server is still initializing or returned a non-JSON response. Please retry in a moment.');
      }

      const data = await response.json();
      if (!response.ok || !data.success || !data.user) {
        throw new Error(data.error || 'Failed to authenticate operator profile.');
      }

      const verifiedUser: VerifiedGoogleUser = {
        ...data.user,
        sessionToken: data.sessionToken,
      };
      setUser(verifiedUser);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(verifiedUser));
      return verifiedUser;
    } catch (err: any) {
      const msg = err.message || 'Authentication error during profile sign-in.';
      setAuthError(msg);
      throw err;
    } finally {
      setIsVerifying(false);
    }
  }, []);

  const logout = useCallback(async () => {
    if (user) {
      try {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(user.sessionToken ? { Authorization: `Bearer ${user.sessionToken}` } : {}),
          },
        });
      } catch (e) {
        console.warn('Error during logout:', e);
      }
    }
    setUser(null);
    localStorage.removeItem(STORAGE_KEY);
    if (window.google?.accounts?.id) {
      window.google.accounts.id.disableAutoSelect();
    }
  }, [user]);

  return {
    user,
    setUser,
    loading,
    isVerifying,
    authError,
    clearAuthError,
    verifyTokenWithBackend,
    instantVerify,
    logout,
  };
}
