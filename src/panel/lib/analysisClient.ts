import { analyzeEvents, type AnalysisResult } from '../../core/analyze';
import type { AnalysisFocus } from '../../core/attacks';
import type { CookieObservation, NetworkEvent } from '../../core/types';
import type { AnalyzeResponse } from '../worker/analysis.worker';
import AnalysisWorker from '../worker/analysis.worker?worker';

/**
 * Debounced analysis client. Heavy rule evaluation runs in a worker so typing
 * and the packet animation stay smooth with thousands of requests.
 */
export class AnalysisClient {
  private worker: Worker | null = null;
  private requestId = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private pending: { events: NetworkEvent[]; cookies: CookieObservation[]; focus: AnalysisFocus } | null = null;

  constructor(private readonly onResult: (result: AnalysisResult) => void) {
    try {
      this.worker = new AnalysisWorker();
      this.worker.onmessage = (event: MessageEvent<AnalyzeResponse>) => {
        if (event.data?.type !== 'result') return;
        if (event.data.requestId !== this.requestId) return; // stale
        this.onResult(event.data.result);
      };
    } catch {
      this.worker = null;
    }
  }

  schedule(
    events: NetworkEvent[],
    cookies: CookieObservation[],
    focus: AnalysisFocus = 'v1',
    delayMs = 250,
  ): void {
    this.pending = { events, cookies, focus };
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => this.flush(), delayMs);
  }

  /** Runs immediately (used before exports so the report is current). */
  flushNow(): AnalysisResult {
    const pending = this.pending;
    if (!pending) return analyzeEvents({ events: [], cookies: [] });
    const result = analyzeEvents(pending);
    this.onResult(result);
    return result;
  }

  private flush(): void {
    const pending = this.pending;
    if (!pending) return;
    this.requestId += 1;
    const requestId = this.requestId;
    if (!this.worker) {
      this.onResult(analyzeEvents(pending));
      return;
    }
    this.worker.postMessage({
      type: 'analyze',
      requestId,
      events: pending.events,
      cookies: pending.cookies,
      focus: pending.focus,
    });
  }

  dispose(): void {
    if (this.timer) clearTimeout(this.timer);
    this.worker?.terminate();
    this.worker = null;
  }
}
