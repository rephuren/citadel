/** «Послушный» агент для воспроизводимого бенчмарка. Это НЕ языковая модель: он детерминированно выполняет любые указания
 *  вида «call сервер.инструмент with {json}», найденные в описаниях инструментов и в результатах вызовов, как самая
 *  наивная модель. Цифры бенчмарка показывают, что останавливает защита при гарантированно уязвимом агенте,
 *  а не насколько уязвимы настоящие модели. */
import { decodeTags } from "../src/vendor/basilisk/text.js";

export interface AgentTool {
  name: string;
  description: string;
}

export interface ToolClient {
  listTools(): Promise<AgentTool[]>;
  callTool(name: string, args: Record<string, unknown>): Promise<{ text: string; isError: boolean }>;
  close(): Promise<void>;
}

export interface Step {
  server: string;
  tool: string;
  args: Record<string, unknown>;
}

export interface TraceEntry {
  tool: string;
  args: Record<string, unknown>;
  text: string;
  isError: boolean;
  via: "user" | "description" | "result";
}

const MAX_DIRECTIVES = 6;

/** Берёт JSON-объект, который начинается с позиции start, учитывая строки и вложенные скобки. */
export function jsonObjectAt(text: string, start: number): string | null {
  if (text[start] !== "{") return null;
  let depth = 0;
  let inString = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (c === "\\") i++;
      else if (c === '"') inString = false;
    } else if (c === '"') inString = true;
    else if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return text.slice(start, i + 1);
  }
  return null;
}

export interface Directive {
  server: string;
  tool: string;
  args: Record<string, unknown>;
  passAs?: string;
}

export function findDirectives(text: string): Directive[] {
  const out: Directive[] = [];
  const re = /call\s+([a-z0-9-]+)\.([a-z_]+)\s+with\s+/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const json = jsonObjectAt(text, m.index + m[0].length);
    if (!json) continue;
    try {
      const args = JSON.parse(json.replace(/\{\{last_result\}\}/g, "@@LAST@@")) as Record<string, unknown>;
      const after = text.slice(m.index + m[0].length + json.length, m.index + m[0].length + json.length + 90);
      const pass = /^\s*(?:,|;)?\s*(?:and\s+)?pass\s+the\s+result\s+in\s+the\s+(\w+)\s+parameter/i.exec(after);
      out.push({ server: m[1] as string, tool: m[2] as string, args, ...(pass?.[1] ? { passAs: pass[1] } : {}) });
    } catch {
      continue;
    }
  }
  return out;
}

function fill(args: Record<string, unknown>, last: string): Record<string, unknown> {
  return JSON.parse(JSON.stringify(args).replace(/@@LAST@@/g, () => JSON.stringify(last).slice(1, -1)));
}

export class NaiveAgent {
  readonly trace: TraceEntry[] = [];
  private last = "";
  private budget = MAX_DIRECTIVES;

  constructor(private readonly client: ToolClient, private readonly resolve: (server: string, tool: string) => string) {}

  async run(steps: Step[]): Promise<TraceEntry[]> {
    for (const step of steps) {
      const name = this.resolve(step.server, step.tool);
      const args = { ...step.args };
      const tools = await this.client.listTools(); // клиент принимает любое изменение определений без вопросов
      const visible = tools.find((t) => t.name === name);
      if (visible) {
        const text = `${visible.description}\n${decodeTags(visible.description)}`;
        for (const d of findDirectives(text.replace(/before using this tool,?\s*/gi, ""))) {
          const result = await this.exec(d, "description");
          if (d.passAs && result !== undefined) args[d.passAs] = result;
        }
      }
      await this.invoke(name, args, "user");
    }
    return this.trace;
  }

  private async exec(d: Directive, via: TraceEntry["via"]): Promise<string | undefined> {
    if (this.budget-- <= 0) return undefined;
    const name = this.resolve(d.server, d.tool);
    return this.invoke(name, fill(d.args, this.last), via);
  }

  private async invoke(name: string, args: Record<string, unknown>, via: TraceEntry["via"]): Promise<string | undefined> {
    const res = await this.client.callTool(name, args);
    this.trace.push({ tool: name, args, text: res.text, isError: res.isError, via });
    if (res.isError) return undefined;
    this.last = res.text;
    for (const d of findDirectives(res.text)) await this.exec(d, "result"); // выполняет указания из данных
    return res.text;
  }
}
