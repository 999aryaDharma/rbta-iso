import { useState, useEffect, type ReactNode } from 'react';
import { isAuthenticated, setApiKey, clearApiKey } from '@/lib/auth';
import { checkAuth } from '@/api/auth';
import { Button } from '@cloudflare/kumo/components/button';
import { InputGroup } from '@cloudflare/kumo/components/input-group';
import { Banner } from '@cloudflare/kumo/components/banner';
import { Shield, Key } from '@phosphor-icons/react';

export function AuthGate({ children }: { children: ReactNode }) {
  const [authed, setAuthed] = useState(isAuthenticated());
  const [input, setInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  useEffect(() => {
    const handleUnauthorized = () => {
      setAuthed(false);
      setError('Sesi berakhir atau tidak diizinkan. Masukkan kembali API key.');
    };
    window.addEventListener('rbta:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('rbta:unauthorized', handleUnauthorized);
  }, []);

  const handleSignIn = async () => {
    const trimmed = input.trim();
    if (!trimmed) {
      setError('API key cannot be empty.');
      return;
    }

    setIsVerifying(true);
    setError(null);

    try {
      setApiKey(trimmed);
      const ok = await checkAuth();
      if (ok) {
        setAuthed(true);
      } else {
        clearApiKey();
        setError('Invalid API key. Please check your credentials.');
      }
    } catch {
      clearApiKey();
      setError('Gagal terhubung ke server.');
    } finally {
      setIsVerifying(false);
    }
  };

  if (authed) return <>{children}</>;

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-kumo-canvas">
      <div className="p-8 rounded-lg border border-kumo-hairline bg-kumo-base w-full max-w-sm">
        <div className="flex items-center gap-2 mb-2">
          <Shield size={20} className="text-kumo-brand" />
          <h1 className="text-sm font-semibold tracking-tight text-kumo-default">
            RBTA Security Analytics (analisis alert keamanan)
          </h1>
        </div>
        <p className="text-xs mb-4 text-kumo-subtle">
          Masukkan API key operasional Anda untuk membuka dashboard.
        </p>

        {error && (
          <div className="mb-4">
            <Banner variant="error" size="sm" description={error} />
          </div>
        )}

        <div className="space-y-3">
          <InputGroup>
            <InputGroup.Addon align="start" className="pl-3"><Key size={14} /></InputGroup.Addon>
            <InputGroup.Input
              type="password"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  handleSignIn();
                }
              }}
              placeholder="Masukkan API key RBTA…"
              className="font-mono text-xs px-3 py-2.5"
              autoFocus
            />
          </InputGroup>

          <Button
            onClick={handleSignIn}
            disabled={isVerifying || !input.trim()}
            className="w-full justify-center"
            variant="primary"
          >
            {isVerifying ? 'Memeriksa API key…' : 'Masuk'}
          </Button>
        </div>

        <p className="mt-4 text-[11px] text-center text-kumo-inactive">
          API key hanya disimpan sementara di memori browser selama sesi ini.
        </p>
      </div>
    </div>
  );
}
