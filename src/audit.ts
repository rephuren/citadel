/** Журнал аудита: одна JSON-строка на событие. Значения аргументов в журнал не попадают, только их форма и отпечаток. */
import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export interface AuditEvent {
  type: string;
  [key: string]: unknown;
}

export function digestArgs(args: unknown): { keys: string[]; bytes: number; sha: string } {
  const text = JSON.stringify(args ?? {}) ?? "{}";
  const keys = typeof args === "object" && args !== null && !Array.isArray(args) ? Object.keys(args).slice(0, 50) : [];
  return { keys, bytes: Buffer.byteLength(text), sha: createHash("sha256").update(text).digest("hex").slice(0, 16) };
}

export class Audit {
  readonly events: AuditEvent[] = [];
  private failed = false;

  constructor(private readonly file?: string, private readonly keep = 10_000, private readonly clock: () => number = Date.now) {
    if (file) {
      try {
        mkdirSync(dirname(file), { recursive: true });
      } catch {
        this.failed = true;
      }
    }
  }

  log(event: AuditEvent): void {
    const full = { ts: new Date(this.clock()).toISOString(), ...event };
    this.events.push(full);
    if (this.events.length > this.keep) this.events.shift();
    if (this.file && !this.failed) {
      try {
        appendFileSync(this.file, JSON.stringify(full) + "\n");
      } catch {
        this.failed = true; // диск недоступен: шлюз продолжает работать, а не падает из-за журнала
        process.stderr.write("citadel: не удаётся писать журнал аудита, запись отключена\n");
      }
    }
  }
}
