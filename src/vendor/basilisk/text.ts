// Копия из проекта basilisk (MIT), синхронизируется скриптом scripts/sync-basilisk.mjs. Правки вносите в basilisk.
/** Общие утилиты работы с текстом полей: извлечение, обрезка, маскировка. */
import type { Tool } from "./types.js";

export const MAX_FIELD_CHARS = 50_000; // длиннее не разбираем: защита от медленных регулярных выражений
const MAX_FIELDS = 2_000;
const MAX_DEPTH = 12;

export interface Field {
  where: string;
  text: string;
  kind: "name" | "description" | "schema-text" | "default";
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Все строки инструмента, которые модель увидит в контексте: имя, описание, тексты и значения схемы. */
export function fieldsOf(tool: Tool): Field[] {
  const base = `${tool.server}/${tool.name}`;
  const out: Field[] = [{ where: `${base}.name`, text: tool.name, kind: "name" }];
  if (typeof tool.description === "string") out.push({ where: `${base}.description`, text: tool.description, kind: "description" });
  walk(tool.inputSchema, `${base}.inputSchema`, 0, out);
  return out.slice(0, MAX_FIELDS).map((f) => ({ ...f, text: f.text.length > MAX_FIELD_CHARS ? f.text.slice(0, MAX_FIELD_CHARS) : f.text }));
}

function walk(node: unknown, path: string, depth: number, out: Field[]): void {
  if (depth > MAX_DEPTH || out.length >= MAX_FIELDS) return;
  if (Array.isArray(node)) {
    node.forEach((v, i) => walk(v, `${path}[${i}]`, depth + 1, out));
    return;
  }
  if (!isRecord(node)) return;
  for (const [key, value] of Object.entries(node)) {
    const p = `${path}.${key}`;
    if ((key === "description" || key === "title" || key === "$comment" || key === "examples") && typeof value === "string") {
      out.push({ where: p, text: value, kind: "schema-text" });
    } else if (key === "default" && typeof value === "string") {
      out.push({ where: p, text: value, kind: "default" });
    } else if (key === "enum" && Array.isArray(value)) {
      value.forEach((v, i) => typeof v === "string" && out.push({ where: `${p}[${i}]`, text: v, kind: "default" }));
    } else if (key === "properties" && isRecord(value)) {
      for (const [prop, sub] of Object.entries(value)) {
        out.push({ where: `${p}.${prop}`, text: prop, kind: "name" }); // имя параметра тоже попадает в контекст модели
        walk(sub, `${p}.${prop}`, depth + 1, out);
      }
    } else {
      walk(value, p, depth + 1, out);
    }
  }
}

export function snippet(text: string, index: number, length = 0, radius = 40): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + Math.max(length, 1) + radius);
  const body = text.slice(start, end).replace(/\s+/g, " ").trim();
  return `${start > 0 ? "…" : ""}${body}${end < text.length ? "…" : ""}`;
}

/** Показывает невидимые символы как \u{XXXX}, чтобы в отчёте было видно, что именно найдено. */
export function visible(text: string): string {
  return [...text].map((ch) => {
    const cp = ch.codePointAt(0) ?? 0;
    return cp < 0x20 || (cp >= 0x7f && cp <= 0xa0) || isInvisible(cp) ? `\\u{${cp.toString(16).toUpperCase()}}` : ch;
  }).join("");
}

export function isInvisible(cp: number): boolean {
  return (
    (cp >= 0x200b && cp <= 0x200f) || // нулевой ширины, LRM/RLM
    (cp >= 0x202a && cp <= 0x202e) || // bidi: встраивание и переопределение
    (cp >= 0x2060 && cp <= 0x2064) ||
    (cp >= 0x2066 && cp <= 0x2069) || // bidi: изоляция
    cp === 0xfeff ||
    cp === 0x00ad ||
    cp === 0x180e ||
    (cp >= 0xe0000 && cp <= 0xe007f) // «теги» Unicode: невидимый ASCII
  );
}

/** Декодирует скрытое сообщение из Unicode-тегов U+E0020..U+E007E в обычный ASCII. */
export function decodeTags(text: string): string {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCharCode(cp - 0xe0000);
  }
  return out;
}

export function mask(secret: string): string {
  return secret.length <= 8 ? "***" : `${secret.slice(0, 4)}…${"*".repeat(4)} (${secret.length} симв.)`;
}
