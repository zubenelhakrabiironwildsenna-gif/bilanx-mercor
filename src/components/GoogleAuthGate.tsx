import React, { useState, useEffect, useRef } from 'react';
import { 
  ShieldCheck, 
  AlertCircle, 
  Fingerprint,
  UserCheck
} from 'lucide-react';
import { VerifiedGoogleUser } from '../hooks/useGoogleAuth';

interface GoogleAuthGateProps {
  onLoginSuccess: (user: VerifiedGoogleUser) => void;
  isVerifying: boolean;
  authError: string | null;
  onClearError: () => void;
  onInstantVerify: (email?: string, name?: string) => Promise<VerifiedGoogleUser>;
}

const DEFUNCT_CLIENT_IDS = new Set([
  '622147315855-d7dhtqmp7ebo48bv706pjtsm1n90db57.apps.googleusercontent.com',
  'your_client_id.apps.googleusercontent.com',
  'your_google_client_id_here',
  'MY_GOOGLE_CLIENT_ID',
]);

const VALID_GOOGLE_CLIENT_ID_PATTERN = /^\d+-[a-z0-9_]+\.apps\.googleusercontent\.com$/i;

function sanitizeClientId(raw?: string | null): string | null {
  const trimmed = (raw || '').trim();
  if (!trimmed || DEFUNCT_CLIENT_IDS.has(trimmed) || !VALID_GOOGLE_CLIENT_ID_PATTERN.test(trimmed)) {
    return null;
  }
  return trimmed;
}

export function GoogleAuthGate({
  onLoginSuccess,
  isVerifying,
  authError,
  onClearError,
  onInstantVerify
}: GoogleAuthGateProps) {
  const [gsiLoaded, setGsiLoaded] = useState(false);
  const [resolvedClientId, setResolvedClientId] = useState<string | null>(() =>
    sanitizeClientId((import.meta as any).env?.VITE_GOOGLE_CLIENT_ID)
  );
  const [emailInput, setEmailInput] = useState('');
  const [nameInput, setNameInput] = useState('');
  const [localFormError, setLocalFormError] = useState<string | null>(null);
  const buttonContainerRef = useRef<HTMLDivElement>(null);

  // Fetch runtime OAuth configuration from backend env vars (GOOGLE_CLIENT_ID / VITE_GOOGLE_CLIENT_ID)
  useEffect(() => {
    let cancelled = false;
    async function loadRuntimeAuthConfig() {
      try {
        const res = await fetch('/api/auth/config', {
          headers: { Accept: 'application/json' },
        });
        if (res.ok) {
          const data = await res.json();
          const serverClientId = sanitizeClientId(data?.googleClientId);
          if (!cancelled && serverClientId) {
            setResolvedClientId(serverClientId);
          }
        }
      } catch {
        // Fallback to build-time VITE_GOOGLE_CLIENT_ID if available
      }
    }
    loadRuntimeAuthConfig();
    return () => {
      cancelled = true;
    };
  }, []);

  // Initialize official Google Identity Services client only when a valid Client ID is configured
  useEffect(() => {
    if (!resolvedClientId) {
      return;
    }

    const initGoogleButton = () => {
      if (typeof window !== 'undefined' && window.google?.accounts?.id && buttonContainerRef.current) {
        try {
          window.google.accounts.id.initialize({
            client_id: resolvedClientId,
            callback: async (response: { credential: string }) => {
              try {
                const res = await fetch('/api/auth/verify-google', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                  body: JSON.stringify({ credential: response.credential }),
                });
                const contentType = res.headers.get('content-type') || '';
                if (contentType.includes('application/json')) {
                  const data = await res.json();
                  if (data.success && data.user) {
                    const verifiedUser = {
                      ...data.user,
                      sessionToken: data.sessionToken
                    };
                    localStorage.setItem('bilanx_verified_google_user', JSON.stringify(verifiedUser));
                    onLoginSuccess(verifiedUser);
                  }
                }
              } catch (err) {
                console.error("Google Sign-In callback error:", err);
              }
            },
          });

          buttonContainerRef.current.innerHTML = '';
          window.google.accounts.id.renderButton(
            buttonContainerRef.current,
            {
              type: 'standard',
              theme: 'filled_blue',
              size: 'large',
              text: 'signin_with',
              shape: 'rectangular',
              logo_alignment: 'left',
              width: 320
            }
          );
          setGsiLoaded(true);
          return true;
        } catch (err) {
          console.warn("Could not render official Google button:", err);
        }
      }
      return false;
    };

    if (!initGoogleButton()) {
      const interval = setInterval(() => {
        if (initGoogleButton()) {
          clearInterval(interval);
        }
      }, 300);
      return () => clearInterval(interval);
    }
  }, [resolvedClientId, onLoginSuccess]);

  const handleProfileSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalFormError(null);
    onClearError();

    const trimmedEmail = emailInput.trim();
    const trimmedName = nameInput.trim();

    if (!trimmedEmail || !trimmedEmail.includes('@')) {
      setLocalFormError('Please enter a valid email address.');
      return;
    }

    try {
      const verifiedUser = await onInstantVerify(
        trimmedEmail,
        trimmedName || trimmedEmail.split('@')[0]
      );
      onLoginSuccess(verifiedUser);
    } catch {
      // Error state is managed by useGoogleAuth and displayed via authError
    }
  };

  const activeError = localFormError || authError;

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center items-center p-4 sm:p-6 font-sans relative overflow-hidden">
      {/* Background Ambience */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-blue-600/10 rounded-full blur-3xl pointer-events-none"></div>
      <div className="absolute bottom-10 right-10 w-80 h-80 bg-indigo-600/5 rounded-full blur-2xl pointer-events-none"></div>

      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden relative z-10">
        
        {/* Header */}
        <div className="p-8 pb-5 text-center">
          <div className="w-14 h-14 bg-blue-500/10 border border-blue-500/30 rounded-2xl flex items-center justify-center mx-auto mb-3.5 text-blue-400">
            <ShieldCheck size={28} />
          </div>

          <div className="flex items-center justify-center gap-1.5 text-blue-300 text-[11px] font-mono mb-2">
            <Fingerprint size={12} />
            <span>Google OAuth 2.0 · Sovereign Identity Gate</span>
          </div>

          <h1 className="text-2xl font-bold text-white tracking-tight">Credentials Hub</h1>
          <p className="text-slate-400 text-xs mt-1.5 leading-relaxed">
            Authenticate with your verified operator profile or Google OAuth 2.0 client to access the eIDAS 2.0 compliance node.
          </p>
        </div>

        {/* Error Notification */}
        {activeError && (
          <div className="mx-8 mb-4 p-3 bg-red-950/60 border border-red-800/80 rounded-lg flex items-start gap-2.5 text-xs text-red-200">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <div className="flex-1 leading-snug">{activeError}</div>
            <button
              type="button"
              onClick={() => {
                setLocalFormError(null);
                onClearError();
              }}
              className="text-red-400 hover:text-red-100 font-bold px-1 cursor-pointer"
            >
              ✕
            </button>
          </div>
        )}

        <div className="px-8 pb-7 flex flex-col gap-5">

          {/* Pre-Filled Custom Profile Sign-In Form */}
          <form onSubmit={handleProfileSignIn} className="flex flex-col gap-3.5">
            <div>
              <label htmlFor="auth-email-input" className="block text-[11px] font-mono text-slate-300 mb-1">
                Operator Email (Google Account)
              </label>
              <input
                id="auth-email-input"
                type="email"
                value={emailInput}
                onChange={(e) => setEmailInput(e.target.value)}
                placeholder="Enter operator email"
                autoComplete="off"
                required
                className="w-full px-3.5 py-2 bg-slate-950 border border-slate-800 focus:border-blue-500 focus:outline-none rounded-lg text-xs text-white font-mono transition-colors"
              />
            </div>

            <div>
              <label htmlFor="auth-name-input" className="block text-[11px] font-mono text-slate-300 mb-1">
                Display Name / Role Profile
              </label>
              <input
                id="auth-name-input"
                type="text"
                value={nameInput}
                onChange={(e) => setNameInput(e.target.value)}
                placeholder="Enter display name"
                autoComplete="off"
                className="w-full px-3.5 py-2 bg-slate-950 border border-slate-800 focus:border-blue-500 focus:outline-none rounded-lg text-xs text-white transition-colors"
              />
            </div>

            <button
              id="btn-instant-google-verify"
              type="submit"
              disabled={isVerifying}
              className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 disabled:opacity-60 text-white rounded-xl font-semibold text-xs flex items-center justify-center gap-2 transition-colors cursor-pointer"
            >
              {isVerifying ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                  <span>Verifying Identity & Issuing Session...</span>
                </>
              ) : (
                <>
                  <UserCheck size={15} />
                  <span>Sign In with Verified Profile</span>
                </>
              )}
            </button>
          </form>

          {/* Official Google Identity Button (shown only when a valid Client ID is configured) */}
          {resolvedClientId && (
            <div className="pt-4 border-t border-slate-800/80 flex flex-col gap-2.5">
              <div className="w-full flex justify-center py-1 min-h-[46px] items-center">
                <div ref={buttonContainerRef} className="flex justify-center"></div>
                {!gsiLoaded && (
                  <div className="text-xs font-mono text-slate-400 flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin"></div>
                    <span>Initializing Google OAuth Client...</span>
                  </div>
                )}
              </div>
            </div>
          )}

        </div>

        {/* Footer */}
        <div className="bg-slate-950 px-6 py-3.5 border-t border-slate-800 flex items-center justify-center text-[11px] text-slate-500 font-mono">
          <span>eIDAS 2.0 Node Sandbox</span>
        </div>

      </div>
    </div>
  );
}

