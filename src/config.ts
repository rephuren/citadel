/** Конфигурация шлюза: какие серверы подключать и какая политика действует. Только JSON, без внешних разборщиков. */
import { readFileSync } from "node:fs";

export type Action = "allow" | "deny" | "confirm";

export interface ServerSpec {
  /** запуск по stdio; для сервера по HTTP не задаётся */
  command?: string;
  args: string[];
  /** адрес MCP-сервера по streamable HTTP: https, либо http только для localhost */
  url?: string;
  /** дополнительные заголовки запросов (например Authorization); в журнал не попадают */
  headers?: Record<string, string>;
  env: Record<string, string>;
  /** передавать ли серверу всё окружение процесса; по умолчанию нет */
  inheritEnv: boolean;
  /** serverTrust: данные от недоверенного сервера считаются заражёнными */
  trust: "trusted" | "untrusted";
  cwd?: string;
}

export interface ArgConstraint {
  pattern?: string;
  enum?: unknown[];
  maxLength?: number;
  /** подстроки, которых не должно быть в значении (например «..») */
  forbid?: string[];
}

export interface ToolRule {
  /** имя вида сервер__инструмент, допускает * */
  match: string;
  action?: Action;
  args?: Record<string, ArgConstraint>;
  /** метки: private (читает приватные данные), untrusted (отдаёт недоверенное), sink (отправляет наружу) */
  labels?: ("private" | "untrusted" | "sink")[];
  callsPerMinute?: number;
}

export interface Policy {
  default: Action;
  rules: ToolRule[];
  taint: { mode: "off" | "log" | "trifecta" | "strict"; onViolation: "deny" | "confirm" };
  limits: { maxResultBytes: number; maxArgsBytes: number; callsPerMinute: number; timeoutMs: number };
  sanitize: { stripInvisible: boolean; blockDefinitionsAt: "off" | "critical" | "high" | "medium"; scanResults: "off" | "log" | "annotate" | "block"; pinFile?: string };
  audit: { file?: string };
  approvals: { file?: string };
}

export interface Config {
  servers: Record<string, ServerSpec>;
  policy: Policy;
}

export const DEFAULT_POLICY: Policy = {
  default: "allow",
  rules: [],
  taint: { mode: "off", onViolation: "deny" },
  limits: { maxResultBytes: 256 * 1024, maxArgsBytes: 64 * 1024, callsPerMinute: 600, timeoutMs: 30_000 },
  sanitize: { stripInvisible: false, blockDefinitionsAt: "off", scanResults: "off" },
  audit: {},
  approvals: {},
};

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Адрес сервера по HTTP: только https (http разрешён для localhost), без логина и пароля в адресе и без фрагмента. */
export function checkServerUrl(raw: unknown, where: string): string {
  if (typeof raw !== "string" || !raw) return fail(`${where}: ожидается строка с адресом`);
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return fail(`${where}: некорректный адрес`);
  }
  if (u.username || u.password) return fail(`${where}: учётные данные в адресе не допускаются, используйте headers`);
  if (u.hash) return fail(`${where}: фрагмент (#) в адресе не допускается`);
  if (u.protocol === "https:") return raw;
  if (u.protocol === "http:" && LOOPBACK.has(u.hostname)) return raw;
  return fail(`${where}: нужен https (http только для localhost)`);
}

const SERVER_NAME = /^[A-Za-z0-9][A-Za-z0-9-]{0,31}$/;

function fail(message: string): never {
  throw new Error(`конфигурация: ${message}`);
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], where: string, fallback: T): T {
  if (value === undefined) return fallback;
  if (typeof value === "string" && (allowed as readonly string[]).includes(value)) return value as T;
  return fail(`${where}: ожидается одно из ${allowed.join(", ")}`);
}

function num(value: unknown, where: string, fallback: number, min = 0): number {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isFinite(value) || value < min) return fail(`${where}: ожидается число не меньше ${min}`);
  return value;
}

function strArray(value: unknown, where: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((x) => typeof x !== "string")) return fail(`${where}: ожидается массив строк`);
  return value as string[];
}

export function parseConfig(raw: unknown): Config {
  if (!isRecord(raw)) return fail("корень должен быть объектом");
  const serversRaw = raw["servers"];
  if (!isRecord(serversRaw) || Object.keys(serversRaw).length === 0) return fail("нужно описать хотя бы один сервер в servers");
  const servers: Record<string, ServerSpec> = {};
  for (const [name, s] of Object.entries(serversRaw)) {
    if (!SERVER_NAME.test(name)) return fail(`servers.${name}: имя только из латиницы, цифр и дефиса, до 32 символов`);
    if (!isRecord(s)) return fail(`servers.${name}: ожидается объект`);
    const hasUrl = s["url"] !== undefined;
    if (hasUrl && s["command"] !== undefined) return fail(`servers.${name}: укажите либо command, либо url, но не оба`);
    if (!hasUrl && (typeof s["command"] !== "string" || !s["command"])) return fail(`servers.${name}.command: обязательная строка (или url для сервера по HTTP)`);
    const env: Record<string, string> = {};
    if (s["env"] !== undefined) {
      if (!isRecord(s["env"])) return fail(`servers.${name}.env: ожидается объект`);
      for (const [k, v] of Object.entries(s["env"])) {
        if (typeof v !== "string") return fail(`servers.${name}.env.${k}: ожидается строка`);
        env[k] = v;
      }
    }
    const spec: ServerSpec = {
      args: strArray(s["args"], `servers.${name}.args`),
      env,
      inheritEnv: s["inheritEnv"] === true,
      trust: oneOf(s["trust"], ["trusted", "untrusted"] as const, `servers.${name}.trust`, "trusted"),
    };
    if (typeof s["command"] === "string") spec.command = s["command"];
    if (typeof s["cwd"] === "string") spec.cwd = s["cwd"];
    if (hasUrl) {
      spec.url = checkServerUrl(s["url"], `servers.${name}.url`);
      if (s["headers"] !== undefined) {
        if (!isRecord(s["headers"])) return fail(`servers.${name}.headers: ожидается объект`);
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(s["headers"])) {
          if (typeof v !== "string" || !/^[A-Za-z0-9-]+$/.test(k) || /[\r\n]/.test(v)) return fail(`servers.${name}.headers.${k}: недопустимое имя или значение`);
          headers[k] = v;
        }
        spec.headers = headers;
      }
    }
    servers[name] = spec;
  }

  const p = isRecord(raw["policy"]) ? raw["policy"] : {};
  const rules: ToolRule[] = [];
  for (const [i, r] of (Array.isArray(p["rules"]) ? p["rules"] : []).entries()) {
    if (!isRecord(r) || typeof r["match"] !== "string" || !r["match"]) return fail(`policy.rules[${i}].match: обязательная строка`);
    const rule: ToolRule = { match: r["match"] };
    if (r["action"] !== undefined) rule.action = oneOf(r["action"], ["allow", "deny", "confirm"] as const, `policy.rules[${i}].action`, "allow");
    if (r["labels"] !== undefined) {
      const labels = strArray(r["labels"], `policy.rules[${i}].labels`);
      for (const l of labels) if (!["private", "untrusted", "sink"].includes(l)) return fail(`policy.rules[${i}].labels: неизвестная метка «${l}»`);
      rule.labels = labels as NonNullable<ToolRule["labels"]>;
    }
    if (r["callsPerMinute"] !== undefined) rule.callsPerMinute = num(r["callsPerMinute"], `policy.rules[${i}].callsPerMinute`, 0, 1);
    if (r["args"] !== undefined) {
      if (!isRecord(r["args"])) return fail(`policy.rules[${i}].args: ожидается объект`);
      rule.args = {};
      for (const [arg, c] of Object.entries(r["args"])) {
        if (!isRecord(c)) return fail(`policy.rules[${i}].args.${arg}: ожидается объект`);
        const constraint: ArgConstraint = {};
        if (c["pattern"] !== undefined) {
          if (typeof c["pattern"] !== "string") return fail(`policy.rules[${i}].args.${arg}.pattern: ожидается строка`);
          try {
            new RegExp(c["pattern"]);
          } catch {
            return fail(`policy.rules[${i}].args.${arg}.pattern: некорректное регулярное выражение`);
          }
          constraint.pattern = c["pattern"];
        }
        if (c["enum"] !== undefined) {
          if (!Array.isArray(c["enum"])) return fail(`policy.rules[${i}].args.${arg}.enum: ожидается массив`);
          constraint.enum = c["enum"];
        }
        if (c["maxLength"] !== undefined) constraint.maxLength = num(c["maxLength"], `policy.rules[${i}].args.${arg}.maxLength`, 0);
        if (c["forbid"] !== undefined) constraint.forbid = strArray(c["forbid"], `policy.rules[${i}].args.${arg}.forbid`);
        rule.args[arg] = constraint;
      }
    }
    rules.push(rule);
  }
  const taint = isRecord(p["taint"]) ? p["taint"] : {};
  const limits = isRecord(p["limits"]) ? p["limits"] : {};
  const sanitize = isRecord(p["sanitize"]) ? p["sanitize"] : {};
  const audit = isRecord(p["audit"]) ? p["audit"] : {};
  const approvals = isRecord(p["approvals"]) ? p["approvals"] : {};
  const d = DEFAULT_POLICY;
  const policy: Policy = {
    default: oneOf(p["default"], ["allow", "deny", "confirm"] as const, "policy.default", d.default),
    rules,
    taint: {
      mode: oneOf(taint["mode"], ["off", "log", "trifecta", "strict"] as const, "policy.taint.mode", d.taint.mode),
      onViolation: oneOf(taint["onViolation"], ["deny", "confirm"] as const, "policy.taint.onViolation", d.taint.onViolation),
    },
    limits: {
      maxResultBytes: num(limits["maxResultBytes"], "policy.limits.maxResultBytes", d.limits.maxResultBytes, 1),
      maxArgsBytes: num(limits["maxArgsBytes"], "policy.limits.maxArgsBytes", d.limits.maxArgsBytes, 1),
      callsPerMinute: num(limits["callsPerMinute"], "policy.limits.callsPerMinute", d.limits.callsPerMinute, 1),
      timeoutMs: num(limits["timeoutMs"], "policy.limits.timeoutMs", d.limits.timeoutMs, 100),
    },
    sanitize: {
      stripInvisible: sanitize["stripInvisible"] === true,
      blockDefinitionsAt: oneOf(sanitize["blockDefinitionsAt"], ["off", "critical", "high", "medium"] as const, "policy.sanitize.blockDefinitionsAt", "off"),
      scanResults: oneOf(sanitize["scanResults"], ["off", "log", "annotate", "block"] as const, "policy.sanitize.scanResults", "off"),
    },
    audit: {},
    approvals: {},
  };
  if (typeof sanitize["pinFile"] === "string") policy.sanitize.pinFile = sanitize["pinFile"];
  if (typeof audit["file"] === "string") policy.audit.file = audit["file"];
  if (typeof approvals["file"] === "string") policy.approvals.file = approvals["file"];
  return { servers, policy };
}

export function loadConfig(path: string): Config {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8").replace(/^﻿/, ""));
  } catch (e) {
    throw new Error(`конфигурация: не удалось прочитать ${path}: ${e instanceof SyntaxError ? "некорректный JSON" : "файл недоступен"}`);
  }
  return parseConfig(raw);
}

/** Сопоставление имени с маской, где * заменяет любую последовательность символов. */
export function globMatch(pattern: string, name: string): boolean {
  if (!pattern.includes("*")) return pattern === name;
  const parts = pattern.split("*");
  let pos = 0;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i] ?? "";
    const idx = name.indexOf(part, pos);
    if (idx === -1 || (i === 0 && idx !== 0)) return false;
    pos = idx + part.length;
  }
  const last = parts[parts.length - 1] ?? "";
  return last === "" || name.endsWith(last);
}
