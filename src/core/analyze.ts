import { rules } from '../rules';
import { collectJwts } from '../rules/lib/jwts';
import { toFinding, type Rule, type RuleContext } from '../rules/types';
import type { AnalysisFocus } from './attacks';
import { dedupeFindings, scoreFindings } from './score';
import type {
  CookieObservation,
  Finding,
  NetworkEvent,
  PageContext,
  ScoreResult,
  Severity,
} from './types';
import { hostOf } from './url';

export interface AnalysisInput {
  events: NetworkEvent[];
  /** Cookies chrome.cookies reported for the inspected page. */
  cookies?: CookieObservation[];
  /**
   * `v1` (default) surfaces only high-confidence findings in the four attack
   * classes. `all` keeps every rule, including lower-confidence checks.
   */
  focus?: AnalysisFocus;
}

export interface AnalysisResult {
  findings: Finding[];
  score: ScoreResult;
  /** Highest severity per host, used to color the map view. */
  severityByHost: Record<string, Severity>;
  evaluatedRules: number;
}

export function buildContext(
  event: NetworkEvent,
  cookies: CookieObservation[],
  page?: PageContext,
): RuleContext {
  const resolvedPage: PageContext = page ?? {
    pageUrl: event.pageUrl,
    pageOrigin: event.pageOrigin,
    isHttps: event.pageOrigin.startsWith('https://'),
  };
  return {
    event,
    page: resolvedPage,
    cookies,
    jwts: collectJwts(event),
  };
}

function ruleApplies(rule: Rule, event: NetworkEvent): boolean {
  if (rule.appliesTo === 'document') {
    return event.resourceType === 'document' || /html/i.test(event.mimeType);
  }
  return true;
}

/**
 * Applies every registered rule to every applicable event. Pure and
 * synchronous so it can run in a Web Worker as well as in tests.
 */
export function analyzeEvents(input: AnalysisInput): AnalysisResult {
  const cookies = input.cookies ?? [];
  const focus: AnalysisFocus = input.focus ?? 'v1';
  const findings: Finding[] = [];
  const page: PageContext | undefined = input.events[0]
    ? {
        pageUrl: input.events[0].pageUrl,
        pageOrigin: input.events[0].pageOrigin,
        isHttps: input.events[0].pageOrigin.startsWith('https://'),
      }
    : undefined;

  for (const event of input.events) {
    const ctx = buildContext(event, cookies, page);
    for (const rule of rules) {
      if (!ruleApplies(rule, event)) continue;
      let hits: ReturnType<Rule['evaluate']>;
      try {
        hits = rule.evaluate(ctx);
      } catch {
        // A failing rule must never break the whole analysis session.
        continue;
      }
      for (const hit of hits) {
        const finding = toFinding(rule, hit, ctx);
        // v1 promises only high-confidence evidence for the four attacks it names.
        if (focus === 'v1' && !(finding.attackClass && finding.confidence === 'high')) continue;
        findings.push(finding);
      }
    }
  }

  const deduped = dedupeFindings(findings);
  const severityByHost: Record<string, Severity> = {};
  const order: Record<Severity, number> = { high: 3, medium: 2, low: 1, info: 0 };
  for (const finding of deduped) {
    const host = finding.domain || hostOf(finding.url ?? '');
    if (!host) continue;
    const current = severityByHost[host];
    if (!current || order[finding.severity] > order[current]) severityByHost[host] = finding.severity;
  }

  return {
    findings: deduped,
    score: scoreFindings(deduped),
    severityByHost,
    evaluatedRules: rules.length,
  };
}
