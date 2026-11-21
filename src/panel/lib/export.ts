import { analyzeEvents } from '../../core/analyze';
import { exportHar } from '../../core/session';
import { buildHtmlReport, buildJsonReport, reportFileName } from '../../report/htmlReport';
import { usePanelStore } from '../store';

function download(content: string, mimeType: string, filename: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/**
 * Exports the current session. The analysis is recomputed synchronously so the
 * report always matches exactly what was captured, even if the worker debounce
 * has not fired yet.
 */
export function exportSession(kind: 'har' | 'json' | 'html'): void {
  const state = usePanelStore.getState();
  if (state.events.length === 0) {
    state.setNotice('Nothing captured yet. Reload the page with the panel open.');
    return;
  }
  const result = analyzeEvents({
    events: state.events,
    cookies: state.cookies,
    focus: state.analysisFocus,
  });
  const at = Date.now();
  const pageUrl = state.pageUrl || state.events[0]?.pageUrl || '';

  if (kind === 'har') {
    download(exportHar(state.events, pageUrl), 'application/json', reportFileName('har', at));
    state.setNotice('HAR exported. It contains raw headers and bodies. Treat it as sensitive.');
    return;
  }
  if (kind === 'json') {
    download(
      buildJsonReport({ pageUrl, generatedAt: at, score: result.score, findings: result.findings, events: state.events }),
      'application/json',
      reportFileName('json', at),
    );
    state.setNotice('JSON report exported. Secret values are masked.');
    return;
  }
  download(
    buildHtmlReport({ pageUrl, generatedAt: at, score: result.score, findings: result.findings, events: state.events }),
    'text/html',
    reportFileName('html', at),
  );
  state.setNotice('Self-contained HTML report exported. It loads nothing from the network.');
}
