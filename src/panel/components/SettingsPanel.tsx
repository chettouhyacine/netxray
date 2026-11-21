import { useState } from 'react';
import { sendMessage } from '../../shared/protocol';
import { usePanelStore } from '../store';
import { inspectedTabId } from '../lib/capture';
import { Modal } from './Modal';

export function SettingsPanel() {
  const open = usePanelStore((state) => state.settingsOpen);
  const setOpen = usePanelStore((state) => state.setSettingsOpen);
  const tls = usePanelStore((state) => state.tls);
  const setTls = usePanelStore((state) => state.setTls);
  const captureBodies = usePanelStore((state) => state.captureBodies);
  const toggleCaptureBodies = usePanelStore((state) => state.toggleCaptureBodies);
  const analysisFocus = usePanelStore((state) => state.analysisFocus);
  const setAnalysisFocus = usePanelStore((state) => state.setAnalysisFocus);
  const theme = usePanelStore((state) => state.theme);
  const setTheme = usePanelStore((state) => state.setTheme);
  const setTourStep = usePanelStore((state) => state.setTourStep);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!open) return null;

  const enableTls = async () => {
    const tabId = inspectedTabId();
    if (tabId === null) {
      setError('Deep TLS inspection requires the DevTools panel context.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      // Must run inside the click gesture: Chrome requires a user gesture.
      const granted = await chrome.permissions.request({ permissions: ['debugger'] });
      if (!granted) {
        setError('Permission denied. Deep TLS inspection stays off; everything else keeps working.');
        return;
      }
      const status = await sendMessage({ type: 'TLS_ENABLE', tabId });
      setTls(status);
      if (status.error) setError(status.error);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not enable deep TLS inspection.');
    } finally {
      setBusy(false);
    }
  };

  const disableTls = async () => {
    const tabId = inspectedTabId();
    if (tabId === null) return;
    setBusy(true);
    try {
      setTls(await sendMessage({ type: 'TLS_DISABLE', tabId }));
    } catch {
      setError('Could not detach the debugger.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="Settings, privacy and permissions" onClose={() => setOpen(false)} wide>
      <div className="space-y-5">
        <section>
          <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Privacy</h3>
          <p className="mt-1 text-[11px] leading-relaxed text-slate-600 dark:text-slate-300">
            All analysis happens on this machine. NetXRay has no telemetry, no remote servers and makes no network
            requests of its own. Captured data lives in DevTools memory and, for crash-recovery, in
            <code className="mx-1 rounded bg-slate-100 px-1 dark:bg-ink-700">chrome.storage.session</code>
            (cleared when the browser closes).
          </p>
          <p className="mt-2 rounded-md border border-amber-300 bg-amber-50 p-2 text-[11px] leading-relaxed text-amber-800 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200">
            Use NetXRay only on applications you own or are authorized to test. Never inspect third-party traffic
            without permission.
          </p>
        </section>

        <section>
          <div className="flex items-start justify-between gap-3">
            <div>
              <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Deep TLS inspection</h3>
              <p className="mt-1 text-[11px] leading-relaxed text-slate-600 dark:text-slate-300">
                Adds protocol version, cipher suite and certificate details from{' '}
                <code className="rounded bg-slate-100 px-1 dark:bg-ink-700">chrome.debugger</code>. This needs the
                powerful <strong>debugger</strong> permission, requests it only now, and shows Chrome’s debugging
                infobar while attached. Without it, TLS rules simply stay quiet.
              </p>
            </div>
            <button
              type="button"
              disabled={busy}
              onClick={() => void (tls.attached ? disableTls() : enableTls())}
              aria-pressed={tls.attached}
              className={`shrink-0 rounded-md px-2.5 py-1 text-[11px] font-semibold disabled:opacity-50 ${
                tls.attached
                  ? 'border border-slate-200 text-slate-600 hover:bg-slate-100 dark:border-ink-700 dark:text-slate-300 dark:hover:bg-ink-800'
                  : 'bg-accent text-ink-950 hover:bg-accent-soft'
              }`}
            >
              {busy ? 'Working…' : tls.attached ? 'Disable' : 'Enable'}
            </button>
          </div>
          {tls.attached ? (
            <p className="mt-1 text-[10px] text-emerald-600 dark:text-emerald-300">
              Attached · {tls.urlCount} URL(s) with TLS details
            </p>
          ) : null}
          {error ? (
            <p className="mt-1 text-[10px] text-rose-600 dark:text-rose-300" role="alert">
              {error}
            </p>
          ) : null}
        </section>

        <section>
          <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Detection</h3>
          <p className="mt-1 text-[11px] leading-relaxed text-slate-600 dark:text-slate-300">
            V1 reports four attack classes (session hijacking, cross-origin data theft, clickjacking and credential
            leakage), and only when the signal is direct enough to be high confidence. Everything else stays available
            as an extended check instead of diluting the signal.
          </p>
          <label className="mt-2 flex cursor-pointer items-start gap-2 text-[11px] text-slate-600 dark:text-slate-300">
            <input
              type="checkbox"
              checked={analysisFocus === 'all'}
              onChange={(event) => setAnalysisFocus(event.target.checked ? 'all' : 'v1')}
              className="mt-0.5 accent-emerald-500"
            />
            <span>
              Show extended checks (all 34 rules). These include missing HSTS, TLS details, cache policy and
              third-party inventory. They are useful review prompts, but are not part of the four v1 attack claims.
            </span>
          </label>
          <p className="mt-2 text-[10px] leading-relaxed text-slate-500 dark:text-slate-400">
            Detection is deterministic and explainable, and every v1 claim is covered by a labelled precision/recall
            test. There is no machine-learning model in v1: with no labelled traffic corpus it would add false
            positives and make findings harder to explain. The rule catalog is the seam where a local model can be
            evaluated in a later version.
          </p>
        </section>

        <section>
          <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Capture</h3>
          <label className="mt-1 flex cursor-pointer items-start gap-2 text-[11px] text-slate-600 dark:text-slate-300">
            <input
              type="checkbox"
              checked={captureBodies}
              onChange={toggleCaptureBodies}
              className="mt-0.5 accent-emerald-500"
            />
            <span>
              Capture response bodies (text/JSON only, capped at 256 KB). Needed for secret-in-response,
              stack-trace, JWT and SRI checks. Stays local; bodies are not written to session storage.
            </span>
          </label>
          <div className="mt-2 flex items-center gap-2 text-[11px] text-slate-600 dark:text-slate-300">
            <span>Theme</span>
            <button
              type="button"
              onClick={() => setTheme('dark')}
              aria-pressed={theme === 'dark'}
              className={`rounded border px-2 py-0.5 ${theme === 'dark' ? 'border-accent text-accent-dim dark:text-accent-soft' : 'border-slate-200 dark:border-ink-700'}`}
            >
              Dark
            </button>
            <button
              type="button"
              onClick={() => setTheme('light')}
              aria-pressed={theme === 'light'}
              className={`rounded border px-2 py-0.5 ${theme === 'light' ? 'border-accent text-accent-dim dark:text-accent-soft' : 'border-slate-200 dark:border-ink-700'}`}
            >
              Light
            </button>
          </div>
        </section>

        <section>
          <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Help</h3>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-slate-600 dark:text-slate-300">
            <button
              type="button"
              onClick={() => {
                setOpen(false);
                setTourStep(0);
              }}
              className="rounded border border-slate-200 px-2 py-0.5 hover:bg-slate-100 dark:border-ink-700 dark:hover:bg-ink-800"
            >
              Replay the tour
            </button>
            <span className="text-[10px] text-slate-400">
              Shortcuts: 1–4 views · j/k move · / filter · t teach me · Esc close
            </span>
          </div>
        </section>
      </div>
    </Modal>
  );
}
