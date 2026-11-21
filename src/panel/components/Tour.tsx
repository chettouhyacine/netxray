import { usePanelStore } from '../store';
import { Modal } from './Modal';

/** Closes the tour and shows the first captured request in the timeline. */
function openFirstRequest(): void {
  const store = usePanelStore.getState();
  const first = store.events[0];
  store.setTourStep(null);
  store.setView('timeline');
  if (first) store.selectEvent(first.id);
}

/** Closes the tour and opens the highest-severity finding. */
function openTopFinding(): void {
  const store = usePanelStore.getState();
  const order = { high: 0, medium: 1, low: 2, info: 3 } as const;
  const top = [...store.findings].sort((a, b) => order[a.severity] - order[b.severity])[0];
  store.setTourStep(null);
  store.setView('security');
  if (top) store.selectFinding(top.id);
}

interface TourStep {
  title: string;
  body: React.ReactNode;
}

const STEPS: TourStep[] = [
  {
    title: 'Welcome to NetXRay',
    body: (
      <>
        <p className="text-xs leading-relaxed text-slate-600 dark:text-slate-300">
          NetXRay shows what your app actually does on the wire and explains the security consequences in plain
          language. Everything (capture, analysis, reports) happens inside this browser. There is no telemetry
          and the extension makes no network requests of its own.
        </p>
        <p className="mt-3 rounded-md border border-amber-300 bg-amber-50 p-2 text-[11px] leading-relaxed text-amber-800 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200">
          Use NetXRay only on systems you own or are explicitly authorized to test. Captured traffic can contain
          personal data and credentials.
        </p>
      </>
    ),
  },
  {
    title: '1 · Read the request lifecycle',
    body: (
      <>
        <p className="text-xs leading-relaxed text-slate-600 dark:text-slate-300">
          Every row in the Timeline is one request. The coloured pipe is time: DNS, TCP connect, TLS handshake,
          the request itself, server thinking time (TTFB) and download.
        </p>
        <ul className="mt-2 space-y-1 text-[11px] text-slate-600 dark:text-slate-300">
          <li>• Click a request to open its detail drawer.</li>
          <li>• Turn on <strong>Teach me</strong> for a one-line explanation per phase.</li>
          <li>• Use <kbd className="rounded border px-1">1</kbd>–<kbd className="rounded border px-1">4</kbd> to switch views, <kbd className="rounded border px-1">j</kbd>/<kbd className="rounded border px-1">k</kbd> to move, <kbd className="rounded border px-1">Esc</kbd> to close.</li>
        </ul>
        <TourAction onClick={openFirstRequest} label="Open the first captured request" available={usePanelStore.getState().events.length > 0} />
      </>
    ),
  },
  {
    title: '2 · Understand one finding',
    body: (
      <>
        <p className="text-xs leading-relaxed text-slate-600 dark:text-slate-300">
          Open the Security view. Each finding answers four questions: <strong>what is it</strong>,{' '}
          <strong>why does it matter</strong>, <strong>how could an attacker use it</strong>, and{' '}
          <strong>how do I fix it</strong>, with copy-ready snippets for Express, Next.js and Nginx. The 0–100
          score drops as distinct rules fire; repeated instances of the same rule count less.
        </p>
        <TourAction onClick={openTopFinding} label="Show me a real finding" available={usePanelStore.getState().findings.length > 0} />
      </>
    ),
  },
  {
    title: '3 · Optional super-powers, your choice',
    body: (
      <>
        <p className="text-xs leading-relaxed text-slate-600 dark:text-slate-300">
          Deep TLS inspection uses the <code className="rounded bg-slate-100 px-1 dark:bg-ink-700">debugger</code>{' '}
          permission to expose certificate and cipher details. It is requested only when you enable it, and
          Chrome shows a visible “started debugging” bar while it is on. Page storage is likewise read only when
          you press the button.
        </p>
        <p className="mt-2 text-xs leading-relaxed text-slate-600 dark:text-slate-300">
          When you are done, export a self-contained HTML report or a HAR. Both are generated locally.
        </p>
      </>
    ),
  },
];

function TourAction({ onClick, label, available }: { onClick: () => void; label: string; available: boolean }) {
  if (!available) {
    return (
      <p className="mt-2 text-[10px] italic text-slate-400">
        Capture a page first, then replay the tour from Settings to try this with real data.
      </p>
    );
  }
  return (
    <button
      type="button"
      onClick={onClick}
      className="mt-2 rounded-md border border-accent/60 bg-accent/10 px-2.5 py-1 text-[11px] font-semibold text-accent-dim hover:bg-accent/20 dark:text-accent-soft"
    >
      {label} →
    </button>
  );
}

export function Tour() {
  const step = usePanelStore((state) => state.tourStep);
  const setStep = usePanelStore((state) => state.setTourStep);
  if (step === null) return null;
  const current = STEPS[Math.min(step, STEPS.length - 1)];
  if (!current) return null;
  const isLast = step >= STEPS.length - 1;

  return (
    <Modal
      title={`Guided tour · ${step + 1} of ${STEPS.length}`}
      onClose={() => setStep(null)}
      wide
    >
      <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{current.title}</h3>
      <div className="mt-2">{current.body}</div>
      <div className="mt-4 flex items-center justify-between gap-2">
        <div className="flex gap-1" aria-hidden="true">
          {STEPS.map((_, index) => (
            <span
              key={index}
              className={`h-1.5 w-1.5 rounded-full ${index === step ? 'bg-accent' : 'bg-slate-300 dark:bg-ink-600'}`}
            />
          ))}
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setStep(null)}
            className="rounded-md px-2 py-1 text-[11px] text-slate-500 hover:bg-slate-100 dark:hover:bg-ink-700"
          >
            Skip
          </button>
          {step > 0 ? (
            <button
              type="button"
              onClick={() => setStep(step - 1)}
              className="rounded-md border border-slate-200 px-2 py-1 text-[11px] font-medium text-slate-600 hover:bg-slate-100 dark:border-ink-700 dark:text-slate-300 dark:hover:bg-ink-800"
            >
              Back
            </button>
          ) : null}
          <button
            type="button"
            onClick={() => setStep(isLast ? null : step + 1)}
            className="rounded-md bg-accent px-3 py-1 text-[11px] font-semibold text-ink-950 hover:bg-accent-soft"
          >
            {isLast ? 'Start exploring' : 'Next'}
          </button>
        </div>
      </div>
    </Modal>
  );
}
