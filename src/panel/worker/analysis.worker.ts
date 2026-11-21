/// <reference lib="webworker" />
import { analyzeEvents, type AnalysisResult } from '../../core/analyze';
import type { AnalysisFocus } from '../../core/attacks';
import type { CookieObservation, NetworkEvent } from '../../core/types';

export interface AnalyzeRequest {
  type: 'analyze';
  requestId: number;
  events: NetworkEvent[];
  cookies: CookieObservation[];
  focus: AnalysisFocus;
}

export type AnalyzeMessage = AnalyzeRequest;

export interface AnalyzeResponse {
  type: 'result';
  requestId: number;
  result: AnalysisResult;
}

self.onmessage = (event: MessageEvent<AnalyzeMessage>) => {
  const message = event.data;
  if (!message || message.type !== 'analyze') return;
  try {
    const result = analyzeEvents({ events: message.events, cookies: message.cookies, focus: message.focus });
    const response: AnalyzeResponse = { type: 'result', requestId: message.requestId, result };
    self.postMessage(response);
  } catch (error) {
    const response: AnalyzeResponse = {
      type: 'result',
      requestId: message.requestId,
      result: {
        findings: [],
        score: { score: 0, grade: 'F', counts: { high: 0, medium: 0, low: 0, info: 0 } },
        severityByHost: {},
        evaluatedRules: 0,
      },
    };
    void error;
    self.postMessage(response);
  }
};
