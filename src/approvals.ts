/** Подтверждения вне канала агента: шлюз кладёт запрос в файл, человек одобряет командой `citadel approve`,
 *  после чего та же самая попытка вызова проходит один раз. Агент сам одобрить свой вызов не может. */
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export interface Approval {
  id: string;
  tool: string;
  argsSha: string;
  created: number;
  status: "pending" | "approved" | "denied" | "used";
  reason: string;
}

export const APPROVAL_TTL_MS = 10 * 60 * 1000;

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    const rec = value as Record<string, unknown>;
    return `{${Object.keys(rec).sort().map((k) => `${JSON.stringify(k)}:${canonical(rec[k])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

export function approvalId(tool: string, args: unknown): { id: string; argsSha: string } {
  const argsSha = createHash("sha256").update(canonical(args ?? {})).digest("hex");
  return { id: createHash("sha256").update(`${tool}|${argsSha}`).digest("hex").slice(0, 8), argsSha };
}

export class Approvals {
  constructor(private readonly file: string | undefined, private readonly clock: () => number = Date.now) {}

  private read(): Approval[] {
    if (!this.file || !existsSync(this.file)) return [];
    try {
      const data = JSON.parse(readFileSync(this.file, "utf8")) as unknown;
      return Array.isArray(data) ? (data as Approval[]).filter((a) => this.clock() - a.created < APPROVAL_TTL_MS) : [];
    } catch {
      return [];
    }
  }

  private write(list: Approval[]): void {
    if (!this.file) return;
    mkdirSync(dirname(this.file), { recursive: true });
    const tmp = `${this.file}.${randomBytes(4).toString("hex")}.tmp`;
    writeFileSync(tmp, JSON.stringify(list, null, 2) + "\n", { mode: 0o600 });
    renameSync(tmp, this.file);
  }

  list(): Approval[] {
    return this.read();
  }

  /** Проверка при вызове: "approved" расходует разрешение, "pending" и "new" значит, что нужно ждать человека. */
  check(tool: string, args: unknown, reason: string): { state: "approved" | "pending" | "denied" | "new"; id: string } {
    const { id, argsSha } = approvalId(tool, args);
    if (!this.file) return { state: "denied", id };
    const list = this.read();
    const found = list.find((a) => a.id === id && a.argsSha === argsSha);
    if (found?.status === "approved") {
      found.status = "used";
      this.write(list);
      return { state: "approved", id };
    }
    if (found?.status === "denied") return { state: "denied", id };
    if (found) return { state: "pending", id };
    list.push({ id, tool, argsSha, created: this.clock(), status: "pending", reason });
    this.write(list);
    return { state: "new", id };
  }

  resolve(id: string, status: "approved" | "denied"): boolean {
    const list = this.read();
    const found = list.find((a) => a.id === id && a.status === "pending");
    if (!found) return false;
    found.status = status;
    this.write(list);
    return true;
  }
}
