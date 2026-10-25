/** Очистка и проверка того, что видит модель: определения инструментов и результаты вызовов. */
import { checkTool } from "./vendor/basilisk/rules/tools.js";
import { isInvisible } from "./vendor/basilisk/text.js";
import type { Finding, Severity } from "./vendor/basilisk/types.js";
import { severityRank } from "./vendor/basilisk/types.js";
import type { UpstreamTool } from "./upstream.js";

export function stripInvisible(text: string): { text: string; removed: number } {
  let removed = 0;
  let out = "";
  let i = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (isInvisible(cp) && !(cp === 0xfeff && i === 0)) removed++;
    else out += ch;
    i += ch.length;
  }
  return { text: out, removed };
}

const MAX_DEPTH = 40;

/** Рекурсивно чистит все строки схемы. Копирует значение, исходное не меняется. */
export function cleanDeep(value: unknown, depth = 0): { value: unknown; removed: number } {
  if (typeof value === "string") {
    const r = stripInvisible(value);
    return { value: r.text, removed: r.removed };
  }
  if (depth > MAX_DEPTH || typeof value !== "object" || value === null) return { value, removed: 0 };
  let removed = 0;
  if (Array.isArray(value)) {
    const arr = value.map((v) => {
      const r = cleanDeep(v, depth + 1);
      removed += r.removed;
      return r.value;
    });
    return { value: arr, removed };
  }
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    const r = cleanDeep(v, depth + 1);
    removed += r.removed;
    out[k] = r.value;
  }
  return { value: out, removed };
}

export function sanitizeDefinition(tool: UpstreamTool): { tool: UpstreamTool; removed: number } {
  const description = typeof tool.description === "string" ? stripInvisible(tool.description) : undefined;
  const schema = tool.inputSchema === undefined ? undefined : cleanDeep(tool.inputSchema);
  const clean: UpstreamTool = { ...tool };
  if (description) clean.description = description.text;
  if (schema) clean.inputSchema = schema.value;
  return { tool: clean, removed: (description?.removed ?? 0) + (schema?.removed ?? 0) };
}

export function definitionFindings(server: string, tool: UpstreamTool): Finding[] {
  return checkTool({
    server,
    name: tool.name,
    ...(typeof tool.description === "string" ? { description: tool.description } : {}),
    ...(tool.inputSchema !== undefined ? { inputSchema: tool.inputSchema } : {}),
    source: "upstream",
  });
}

/** Находки, из-за которых определение нельзя показывать модели при выбранном пороге. */
export function blocking(findings: Finding[], level: "off" | Severity): Finding[] {
  if (level === "off") return [];
  const floor = severityRank(level);
  return findings.filter((f) => severityRank(f.severity) <= floor && !isAdvisory(f));
}

/** Правила, которые описывают возможности инструмента, а не вредоносный текст: сами по себе не повод скрывать инструмент. */
function isAdvisory(f: Finding): boolean {
  return f.rule === "BSK006" || f.rule === "BSK007" || f.rule === "BSK005";
}

const RESULT_RULES = new Set(["BSK001", "BSK002", "BSK004"]);

export function scanResultText(text: string): Finding[] {
  if (!text) return [];
  return checkTool({ server: "result", name: "result", description: text.slice(0, 50_000), inputSchema: { type: "object", additionalProperties: false, properties: {} }, source: "result" })
    .filter((f) => RESULT_RULES.has(f.rule) || (f.rule === "BSK003" && f.severity === "high"));
}

interface ContentPart {
  type?: unknown;
  text?: unknown;
  resource?: { text?: unknown };
}

/** Текстовые фрагменты результата вызова. Остальные типы (картинки, ссылки) не разбираем. */
export function resultTexts(result: unknown): string[] {
  if (typeof result !== "object" || result === null) return [];
  const content = (result as { content?: unknown }).content;
  const texts: string[] = [];
  if (Array.isArray(content)) {
    for (const part of content as ContentPart[]) {
      if (part && typeof part.text === "string") texts.push(part.text);
      else if (part?.resource && typeof part.resource.text === "string") texts.push(part.resource.text);
    }
  }
  const structured = (result as { structuredContent?: unknown }).structuredContent;
  if (structured !== undefined) {
    const s = JSON.stringify(structured);
    if (s) texts.push(s.slice(0, 200_000));
  }
  return texts;
}

/** Применяет функцию к каждому текстовому фрагменту результата, возвращая новую копию. */
export function mapResultTexts(result: unknown, fn: (text: string) => string): unknown {
  if (typeof result !== "object" || result === null) return result;
  const copy = { ...(result as Record<string, unknown>) };
  if (Array.isArray(copy["content"])) {
    copy["content"] = (copy["content"] as ContentPart[]).map((part) => {
      if (part && typeof part.text === "string") return { ...part, text: fn(part.text) };
      if (part?.resource && typeof part.resource.text === "string") return { ...part, resource: { ...part.resource, text: fn(part.resource.text) } };
      return part;
    });
  }
  return copy;
}
