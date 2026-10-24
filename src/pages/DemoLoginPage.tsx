import React, { useState } from 'react';
import { LockKeyhole, ShieldCheck } from 'lucide-react';
import { apiClient } from '../services/apiClient';
import type { User } from '../types';

interface DemoLoginPageProps {
  onLogin: (user: User) => void;
}

const DEMO_ACCOUNTS = [
  { label: 'Analyst 1', email: 'analyst1@sentinelshield.demo', password: 'AnalystDemo2026!' },
  { label: 'Analyst 2', email: 'analyst2@sentinelshield.demo', password: 'Analyst2Demo2026!' },
  { label: 'Admin', email: 'admin@sentinelshield.demo', password: 'AdminDemo2026!' },
];

export const DemoLoginPage: React.FC<DemoLoginPageProps> = ({ onLogin }) => {
  const [email, setEmail] = useState(DEMO_ACCOUNTS[0].email);
  const [password, setPassword] = useState(DEMO_ACCOUNTS[0].password);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError('');
    setBusy(true);
    try {
      const session = await apiClient.login(email, password);
      onLogin(session.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed. Please try again.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-5">
      <div className="w-full max-w-md space-y-6">
        <header className="text-center space-y-2">
          <div className="mx-auto w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-300">
            <ShieldCheck className="w-7 h-7" />
          </div>
          <h1 className="text-2xl font-bold">SentinelShield</h1>
          <p className="text-sm text-slate-400">Digital risk investigation workspace</p>
          <span className="inline-flex rounded-full px-2.5 py-1 text-[11px] font-bold tracking-wide bg-amber-400/10 border border-amber-400/30 text-amber-300">
            DEMO LOGIN — SEEDED DATA
          </span>
        </header>

        <form onSubmit={submit} className="rounded-2xl border border-slate-800 bg-slate-900 p-6 space-y-4 shadow-2xl">
          <label className="block text-xs font-semibold text-slate-300">
            Demo email
            <input
              type="email"
              required
              autoComplete="username"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-white focus:border-cyan-500 focus:outline-none"
            />
          </label>
          <label className="block text-xs font-semibold text-slate-300">
            Password
            <input
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-white focus:border-cyan-500 focus:outline-none"
            />
          </label>
          {error && <p role="alert" className="text-xs text-rose-300">{error}</p>}
          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 text-slate-950 font-bold text-sm py-2.5 flex items-center justify-center gap-2"
          >
            <LockKeyhole className="w-4 h-4" />
            {busy ? 'Signing in…' : 'Sign in to demo'}
          </button>
        </form>

        <section aria-label="Demo credentials" className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <h2 className="text-xs font-bold text-slate-300 mb-3">Seeded demo credentials</h2>
          <div className="space-y-2">
            {DEMO_ACCOUNTS.map((account) => (
              <button
                key={account.email}
                type="button"
                onClick={() => {
                  setEmail(account.email);
                  setPassword(account.password);
                  setError('');
                }}
                className="w-full text-left rounded-lg border border-slate-800 hover:border-cyan-500/40 px-3 py-2 text-[11px] text-slate-400"
              >
                <span className="font-semibold text-slate-200">{account.label}</span>
                <span className="block mt-0.5">{account.email} · {account.password}</span>
              </button>
            ))}
          </div>
        </section>
      </div>
    </main>
  );
};
