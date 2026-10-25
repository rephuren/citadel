// Копия из проекта basilisk (MIT), синхронизируется скриптом scripts/sync-basilisk.mjs. Правки вносите в basilisk.
/** Закрепление определений: хеши инструментов и запуска серверов. Изменение после закрепления выдаёт подмену (rug pull). */
import { createHash } from "node:crypto";
import type { Finding, Inventory, ServerConfig, Tool } from "./types.js";

export interface Lock {
  version: 1;
  tools: Record<string, { hash: string; descriptionLength: number }>;
  servers: Record<string, string>;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    const rec = value as Record<string, unknown>;
    return `{${Object.keys(rec).sort().map((k) => `${JSON.stringify(k)}:${canonical(rec[k])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function sha(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

export function toolHash(t: Tool): string {
  return sha(canonical({ name: t.name, description: t.description ?? null, inputSchema: t.inputSchema ?? null }));
}

export function serverHash(s: ServerConfig): string {
  // значения env не входят в хеш: секреты не должны попадать в lock-файл, а меняются они законно
  return sha(canonical({ command: s.command ?? null, args: s.args, url: s.url ?? null, env: Object.keys(s.env).sort() }));
}

const toolKey = (t: Tool) => `${t.server}/${t.name}`;

export function makeLock(inv: Inventory): Lock {
  const lock: Lock = { version: 1, tools: Object.create(null) as Lock["tools"], servers: Object.create(null) as Lock["servers"] };
  for (const t of inv.tools) lock.tools[toolKey(t)] = { hash: toolHash(t), descriptionLength: (t.description ?? "").length };
  for (const s of inv.servers) lock.servers[s.name] = serverHash(s);
  return lock;
}

export function parseLock(raw: string): Lock {
  const data = JSON.parse(raw) as Partial<Lock>;
  if (data.version !== 1 || typeof data.tools !== "object" || data.tools === null || typeof data.servers !== "object" || data.servers === null) {
    throw new Error("неизвестный формат lock-файла");
  }
  return data as Lock;
}

export function verify(inv: Inventory, lock: Lock): Finding[] {
  const out: Finding[] = [];
  const current = new Set<string>();
  for (const t of inv.tools) {
    const k = toolKey(t);
    current.add(k);
    const pinned = Object.prototype.hasOwnProperty.call(lock.tools, k) ? lock.tools[k] : undefined;
    if (!pinned) {
      out.push({ rule: "BSK021", severity: "medium", where: k, source: t.source, message: "инструмента не было в закреплённом наборе" });
    } else if (pinned.hash !== toolHash(t)) {
      const len = (t.description ?? "").length;
      out.push({ rule: "BSK020", severity: "critical", where: k, source: t.source,
        message: `определение изменилось после закрепления (описание: ${pinned.descriptionLength} → ${len} символов)` });
    }
  }
  for (const k of Object.keys(lock.tools)) {
    if (!current.has(k)) out.push({ rule: "BSK022", severity: "info", where: k, message: "инструмент был закреплён, но сейчас не найден" });
  }
  for (const s of inv.servers) {
    const pinned = Object.prototype.hasOwnProperty.call(lock.servers, s.name) ? lock.servers[s.name] : undefined;
    if (pinned && pinned !== serverHash(s)) {
      out.push({ rule: "BSK023", severity: "high", where: s.name, source: s.source, message: "команда, аргументы или адрес сервера изменились после закрепления" });
    }
  }
  return out;
}
