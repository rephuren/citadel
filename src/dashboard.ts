/** Локальный дашборд по журналу аудита: JSON API и одна страница. Слушает только 127.0.0.1, данные в страницу попадают через textContent. */
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { type Server, createServer } from "node:http";
import { fileURLToPath } from "node:url";
import type { AuditEvent } from "./audit.js";

const MAX_BYTES = 8 * 1024 * 1024;
const PAGE = fileURLToPath(new URL("../../src/dashboard.html", import.meta.url));

export function readEvents(file: string, limit = 5000): AuditEvent[] {
  if (!existsSync(file)) return [];
  let text = readFileSync(file, "utf8");
  if (Buffer.byteLength(text) > MAX_BYTES) text = text.slice(-MAX_BYTES).replace(/^[^\n]*\n/, ""); // читаем только хвост большого журнала
  const events: AuditEvent[] = [];
  for (const line of text.split("\n")) {
    if (!line) continue;
    try {
      const e = JSON.parse(line) as AuditEvent;
      if (typeof e === "object" && e && typeof e.type === "string") events.push(e);
    } catch {
      continue; // оборванная последняя строка при записи
    }
  }
  return events.slice(-limit);
}

function top(counter: Map<string, number>, n = 10): [string, number][] {
  return [...counter.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
}

export function summarize(events: AuditEvent[]) {
  const decisions = new Map<string, number>();
  const tools = new Map<string, number>();
  const reasons = new Map<string, number>();
  const quarantined: { tool: string; why: string }[] = [];
  const seenQuarantine = new Set<string>();
  let leakFlows = 0;
  let last = "";
  for (const e of events) {
    last = String(e["ts"] ?? last);
    if (e.type === "call") {
      const d = String(e["decision"] ?? "?");
      decisions.set(d, (decisions.get(d) ?? 0) + 1);
      const tool = String(e["tool"] ?? "?");
      tools.set(tool, (tools.get(tool) ?? 0) + 1);
      if (d !== "allow") for (const r of (e["reasons"] as unknown[] | undefined) ?? []) reasons.set(String(r).slice(0, 160), (reasons.get(String(r).slice(0, 160)) ?? 0) + 1);
    } else if (e.type === "definition" && e["quarantine"]) {
      const q = { tool: `${String(e["server"])}__${String(e["tool"])}`, why: String(e["quarantine"]) };
      if (!seenQuarantine.has(`${q.tool}|${q.why}`)) {
        seenQuarantine.add(`${q.tool}|${q.why}`);
        quarantined.push(q);
      }
    } else if (e.type === "taint-note") leakFlows++;
  }
  const total = [...decisions.values()].reduce((a, b) => a + b, 0);
  return {
    total,
    allowed: decisions.get("allow") ?? 0,
    denied: (decisions.get("deny") ?? 0) + (decisions.get("confirm-denied") ?? 0) + (decisions.get("result-blocked") ?? 0) + (decisions.get("result-too-large") ?? 0),
    pending: decisions.get("confirm-pending") ?? 0,
    errors: decisions.get("error") ?? 0,
    quarantined,
    leakFlows,
    topTools: top(tools),
    topReasons: top(reasons),
    last,
  };
}

export async function startDashboard(file: string, port: number, log: (l: string) => void): Promise<Server> {
  if (existsSync(file) && !statSync(file).isFile()) throw new Error(`${file}: это не файл журнала`);
  const html = readFileSync(PAGE, "utf8");
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const nonce = randomBytes(12).toString("base64");
    const headers = {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy": `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; connect-src 'self'`,
    };
    if (req.method !== "GET") {
      res.writeHead(405, headers).end();
      return;
    }
    if (url.pathname === "/") {
      res.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end(html.replace("__NONCE__", nonce));
    } else if (url.pathname === "/api/summary") {
      res.writeHead(200, { ...headers, "Content-Type": "application/json" }).end(JSON.stringify(summarize(readEvents(file))));
    } else if (url.pathname === "/api/events") {
      const limit = Math.min(500, Math.max(1, Number(url.searchParams.get("limit")) || 100));
      res.writeHead(200, { ...headers, "Content-Type": "application/json" }).end(JSON.stringify(readEvents(file, limit).reverse()));
    } else {
      res.writeHead(404, headers).end("не найдено");
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  log(`дашборд: http://127.0.0.1:${port}  (журнал ${file})`);
  return server;
}
