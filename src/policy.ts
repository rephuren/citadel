/** Движок политик: решает, можно ли вызвать инструмент, какие у него метки и укладываются ли аргументы в ограничения. */
import { type Action, type ArgConstraint, type Policy, type ToolRule, globMatch } from "./config.js";
import type { Label } from "./taint.js";

export interface Decision {
  action: Action;
  reasons: string[];
  rule?: string;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function matchingRules(policy: Policy, qualified: string): ToolRule[] {
  return policy.rules.filter((r) => globMatch(r.match, qualified));
}

export function labelsFor(policy: Policy, qualified: string, serverUntrusted: boolean): Set<Label> {
  const labels = new Set<Label>();
  if (serverUntrusted) labels.add("untrusted");
  for (const r of matchingRules(policy, qualified)) for (const l of r.labels ?? []) labels.add(l);
  return labels;
}

function sameJson(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

export function checkArg(name: string, value: unknown, c: ArgConstraint): string[] {
  const problems: string[] = [];
  if (c.enum && !c.enum.some((e) => sameJson(e, value))) problems.push(`«${name}»: значение вне списка разрешённых`);
  const needsString = c.pattern !== undefined || c.maxLength !== undefined || c.forbid !== undefined;
  if (needsString && typeof value !== "string") {
    problems.push(`«${name}»: ожидается строка`);
    return problems;
  }
  if (typeof value !== "string") return problems;
  if (c.maxLength !== undefined && value.length > c.maxLength) problems.push(`«${name}»: длиннее ${c.maxLength} символов`);
  if (c.pattern !== undefined && !new RegExp(c.pattern).test(value.slice(0, 10_000))) problems.push(`«${name}»: не соответствует шаблону`);
  for (const bad of c.forbid ?? []) if (value.toLowerCase().includes(bad.toLowerCase())) problems.push(`«${name}»: содержит запрещённое «${bad}»`);
  return problems;
}

export function evaluate(policy: Policy, qualified: string, args: unknown): Decision {
  const rules = matchingRules(policy, qualified);
  const reasons: string[] = [];
  let action: Action = policy.default;
  let by: string | undefined;
  const decided = rules.find((r) => r.action !== undefined);
  if (decided?.action) {
    action = decided.action;
    by = decided.match;
  }
  if (action === "deny") {
    reasons.push(by ? `запрещено правилом ${by}` : "запрещено политикой по умолчанию");
    return { action, reasons, ...(by ? { rule: by } : {}) };
  }
  const given = isRecord(args) ? args : {};
  for (const r of rules) {
    for (const [arg, c] of Object.entries(r.args ?? {})) {
      if (!(arg in given)) continue;
      const problems = checkArg(arg, given[arg], c);
      if (problems.length) {
        reasons.push(...problems.map((p) => `${p} (правило ${r.match})`));
        return { action: "deny", reasons, rule: r.match };
      }
    }
  }
  if (action === "confirm") reasons.push(by ? `требуется подтверждение по правилу ${by}` : "требуется подтверждение по умолчанию");
  return { action, reasons, ...(by ? { rule: by } : {}) };
}

/** Скользящее окно вызовов за минуту. Часы подменяются в тестах. */
export class RateLimiter {
  private hits = new Map<string, number[]>();
  constructor(private readonly clock: () => number = Date.now) {}

  /** true, если вызов укладывается в лимит (и он засчитан). */
  take(key: string, limit: number): boolean {
    const now = this.clock();
    const recent = (this.hits.get(key) ?? []).filter((t) => now - t < 60_000);
    if (recent.length >= limit) {
      this.hits.set(key, recent);
      return false;
    }
    recent.push(now);
    this.hits.set(key, recent);
    return true;
  }
}
