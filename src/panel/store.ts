import { create } from 'zustand';
import type { AnalysisResult } from '../core/analyze';
import type { AnalysisFocus, AttackClass } from '../core/attacks';
import type {
  CookieObservation,
  Finding,
  NetworkEvent,
  ScoreResult,
  Severity,
  TlsDetails,
} from '../core/types';
import type { StorageSnapshot, TlsStatus } from '../shared/protocol';

export type View = 'timeline' | 'map' | 'security' | 'storage';

const EMPTY_SCORE: ScoreResult = { score: 100, grade: 'A', counts: { high: 0, medium: 0, low: 0, info: 0 } };
const MAX_EVENTS = 3000;

export interface PanelState {
  view: View;
  events: NetworkEvent[];
  findings: Finding[];
  score: ScoreResult;
  selectedEventId: string | null;
  selectedFindingId: string | null;
  search: string;
  severityFilter: 'all' | Severity;
  analysisFocus: AnalysisFocus;
  attackFilter: 'all' | AttackClass;
  teachMe: boolean;
  theme: 'dark' | 'light';
  captureBodies: boolean;
  settingsOpen: boolean;
  tourStep: number | null;
  tls: TlsStatus;
  cookies: CookieObservation[];
  pageUrl: string;
  storageSnapshot: StorageSnapshot | null;
  storageError: string | null;
  storageLoading: boolean;
  notice: string | null;

  setView(view: View): void;
  addEvents(events: NetworkEvent[]): void;
  mergeEvent(event: NetworkEvent): void;
  applyTls(byUrl: Record<string, TlsDetails>): void;
  setAnalysis(result: AnalysisResult): void;
  selectEvent(id: string | null): void;
  selectFinding(id: string | null): void;
  setSearch(search: string): void;
  setSeverityFilter(filter: 'all' | Severity): void;
  setAnalysisFocus(focus: AnalysisFocus): void;
  setAttackFilter(filter: 'all' | AttackClass): void;
  toggleTeachMe(): void;
  setTheme(theme: 'dark' | 'light'): void;
  toggleCaptureBodies(): void;
  setSettingsOpen(open: boolean): void;
  setTourStep(step: number | null): void;
  setTls(status: TlsStatus): void;
  setCookies(cookies: CookieObservation[]): void;
  setPageUrl(url: string): void;
  setStorage(snapshot: StorageSnapshot | null, error?: string | null): void;
  setStorageLoading(loading: boolean): void;
  setNotice(notice: string | null): void;
  clearSession(): void;
}

function readPreference(key: string, fallback: string): string {
  try {
    return window.localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}

function writePreference(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Preferences are best-effort; the panel keeps working without storage.
  }
}

const initialTheme = readPreference('nx:theme', 'dark') === 'light' ? 'light' : 'dark';
const initialTeach = readPreference('nx:teach', '1') !== '0';
const initialBodies = readPreference('nx:capture-bodies', '1') !== '0';
const initialFocus: AnalysisFocus = readPreference('nx:focus', 'v1') === 'all' ? 'all' : 'v1';
const tourSeen = readPreference('nx:tour-seen', '0') === '1';

export const usePanelStore = create<PanelState>((set, get) => ({
  view: 'timeline',
  events: [],
  findings: [],
  score: EMPTY_SCORE,
  selectedEventId: null,
  selectedFindingId: null,
  search: '',
  severityFilter: 'all',
  analysisFocus: initialFocus,
  attackFilter: 'all',
  teachMe: initialTeach,
  theme: initialTheme,
  captureBodies: initialBodies,
  settingsOpen: false,
  tourStep: tourSeen ? null : 0,
  tls: { supported: false, attached: false, urlCount: 0 },
  cookies: [],
  pageUrl: '',
  storageSnapshot: null,
  storageError: null,
  storageLoading: false,
  notice: null,

  setView: (view) => set({ view }),
  addEvents: (incoming) => {
    if (incoming.length === 0) return;
    const current = get().events;
    const map = new Map(current.map((event) => [event.id, event]));
    let pageUrl = get().pageUrl;
    for (const event of incoming) {
      map.set(event.id, event);
      if (!pageUrl && event.pageUrl) pageUrl = event.pageUrl;
      if (event.resourceType === 'document') pageUrl = event.pageUrl || event.url;
    }
    const events = Array.from(map.values())
      .sort((a, b) => a.startedAt - b.startedAt)
      .slice(-MAX_EVENTS);
    set({ events, pageUrl });
  },
  mergeEvent: (event) => {
    const events = get().events.map((existing) => (existing.id === event.id ? event : existing));
    set({ events });
  },
  applyTls: (byUrl) => {
    const events = get().events.map((event) => {
      const details = byUrl[event.url];
      if (!details || event.tls) return event;
      return { ...event, tls: details, protocol: details.protocol ?? event.protocol };
    });
    set({ events });
  },
  setAnalysis: (result) =>
    set({
      findings: result.findings,
      score: result.score,
    }),
  selectEvent: (id) => set({ selectedEventId: id, selectedFindingId: id ? null : get().selectedFindingId }),
  selectFinding: (id) => set({ selectedFindingId: id, selectedEventId: id ? null : get().selectedEventId }),
  setSearch: (search) => set({ search }),
  setSeverityFilter: (severityFilter) => set({ severityFilter }),
  setAnalysisFocus: (analysisFocus) => {
    writePreference('nx:focus', analysisFocus);
    set({ analysisFocus, attackFilter: analysisFocus === 'all' ? 'all' : get().attackFilter });
  },
  setAttackFilter: (attackFilter) => set({ attackFilter }),
  toggleTeachMe: () => {
    const teachMe = !get().teachMe;
    writePreference('nx:teach', teachMe ? '1' : '0');
    set({ teachMe });
  },
  setTheme: (theme) => {
    writePreference('nx:theme', theme);
    document.documentElement.classList.toggle('dark', theme === 'dark');
    document.documentElement.classList.toggle('light', theme === 'light');
    set({ theme });
  },
  toggleCaptureBodies: () => {
    const captureBodies = !get().captureBodies;
    writePreference('nx:capture-bodies', captureBodies ? '1' : '0');
    set({ captureBodies });
  },
  setSettingsOpen: (settingsOpen) => set({ settingsOpen }),
  setTourStep: (tourStep) => {
    if (tourStep === null) writePreference('nx:tour-seen', '1');
    set({ tourStep });
  },
  setTls: (tls) => set({ tls }),
  setCookies: (cookies) => set({ cookies }),
  setPageUrl: (pageUrl) => set({ pageUrl }),
  setStorage: (storageSnapshot, storageError = null) => set({ storageSnapshot, storageError }),
  setStorageLoading: (storageLoading) => set({ storageLoading }),
  setNotice: (notice) => set({ notice }),
  clearSession: () =>
    set({
      events: [],
      findings: [],
      score: EMPTY_SCORE,
      selectedEventId: null,
      selectedFindingId: null,
      pageUrl: '',
      cookies: [],
      storageSnapshot: null,
      storageError: null,
    }),
}));
