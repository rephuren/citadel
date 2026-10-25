/** Отслеживание «заражённых» данных в рамках одной сессии агента. Правило «смертельной тройки»:
 *  приватные данные + недоверенный контент + канал наружу в одной сессии нельзя собирать без подтверждения. */
import type { Policy } from "./config.js";

export type Label = "private" | "untrusted" | "sink";

interface Provenance {
  tool: string;
  call: number;
}

const WINDOW = 24;
const STRIDE = 8;
const MAX_FINGERPRINTS = 40_000;
const MAX_TEXT = 100_000;

export interface TaintVerdict {
  violation: boolean;
  reasons: string[];
  /** общая подстрока аргументов с данными из заражённых результатов: прямое свидетельство перетекания */
  flow?: { from: string; kind: "private" | "untrusted" };
}

export class Taint {
  readonly sources: Record<"private" | "untrusted", Provenance[]> = { private: [], untrusted: [] };
  private fingerprints: Record<"private" | "untrusted", Map<string, string>> = { private: new Map(), untrusted: new Map() };
  private calls = 0;

  constructor(private readonly mode: Policy["taint"]["mode"]) {}

  get state(): { private: boolean; untrusted: boolean } {
    return { private: this.sources.private.length > 0, untrusted: this.sources.untrusted.length > 0 };
  }

  /** Запоминает, что результат вызова содержит данные с такими метками. */
  record(tool: string, labels: ReadonlySet<Label>, text: string): void {
    this.calls++;
    if (this.mode === "off") return;
    for (const kind of ["private", "untrusted"] as const) {
      if (!labels.has(kind)) continue;
      this.sources[kind].push({ tool, call: this.calls });
      const map = this.fingerprints[kind];
      const body = text.slice(0, MAX_TEXT);
      for (let i = 0; i + WINDOW <= body.length && map.size < MAX_FINGERPRINTS; i += STRIDE) map.set(body.slice(i, i + WINDOW), tool);
    }
  }

  /** Проверка перед вызовом инструмента с меткой sink (отправка наружу). */
  check(tool: string, labels: ReadonlySet<Label>, argsText: string): TaintVerdict {
    if (this.mode === "off" || !labels.has("sink")) return { violation: false, reasons: [] };
    const reasons: string[] = [];
    const { private: priv, untrusted } = this.state;
    let flow: TaintVerdict["flow"];
    const body = argsText.slice(0, MAX_TEXT);
    for (const kind of ["private", "untrusted"] as const) {
      const map = this.fingerprints[kind];
      if (!map.size) continue;
      for (let i = 0; i + WINDOW <= body.length; i++) {
        const from = map.get(body.slice(i, i + WINDOW));
        if (from) {
          flow = { from, kind };
          break;
        }
      }
      if (flow) break;
    }
    if (flow) reasons.push(`аргументы содержат данные из результата ${flow.from} (${flow.kind === "private" ? "приватные" : "недоверенные"})`);
    let violation = false;
    if (this.mode === "strict" && untrusted) {
      violation = true;
      reasons.push(`в сессии есть недоверенный контент (${this.sources.untrusted.map((s) => s.tool).join(", ")}), а ${tool} отправляет данные наружу`);
    } else if (this.mode === "trifecta" && untrusted && priv) {
      violation = true;
      reasons.push(`смертельная тройка: приватные данные (${this.sources.private.map((s) => s.tool).join(", ")}), недоверенный контент (${this.sources.untrusted.map((s) => s.tool).join(", ")}) и канал наружу (${tool})`);
    }
    return violation ? { violation, reasons, ...(flow ? { flow } : {}) } : { violation: false, reasons: this.mode === "log" ? reasons : [], ...(flow ? { flow } : {}) };
  }
}
