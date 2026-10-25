// Копия из проекта basilisk (MIT), синхронизируется скриптом scripts/sync-basilisk.mjs. Правки вносите в basilisk.
/** Правила по инструментам: что модель читает в описаниях и схемах и какие возможности ей даны. */
import { type Field, decodeTags, fieldsOf, isInvisible, snippet, visible } from "../text.js";
import type { Finding, Severity, Tool } from "../types.js";

interface Pattern {
  re: RegExp;
  label: string;
  severity?: Severity;
}

// Без вложенных квантификаторов и с ограниченными промежутками: быстрые на длинных входах.
const INJECTION: Pattern[] = [
  { re: /ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|messages?|rules?)/i, label: "просит игнорировать прежние указания" },
  { re: /disregard\s+.{0,40}(?:instructions?|rules?|system\s+prompt|guidelines?)/i, label: "просит отбросить правила" },
  { re: /(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|show|disclose)\s+(?:this\s+|it\s+|that\s+)?(?:to\s+)?(?:the\s+)?user/i, label: "требует скрыть от пользователя" },
  { re: /without\s+(?:telling|informing|notifying|alerting)\s+the\s+user/i, label: "действие втайне от пользователя" },
  { re: /<\s*\/?\s*(?:important|system|instructions?|secret|hidden)\s*>/i, label: "псевдо-системная разметка в описании" },
  { re: /(?:^|\n)\s*(?:system|assistant)\s*:/i, label: "имитация системного сообщения" },
  { re: /\[\s*(?:system|inst|\/inst)\s*\]/i, label: "служебные маркеры промпта" },
  { re: /before\s+(?:using|calling|running|invoking)\s+this\s+tool.{0,100}(?:read|send|include|pass|fetch|upload|open)/i, label: "скрытый предварительный шаг перед вызовом" },
  { re: /you\s+(?:must|should|have\s+to|need\s+to)\s+(?:always\s+|first\s+)?(?:call|use|invoke|run|execute)\s+/i, label: "приказывает модели вызывать инструменты", severity: "medium" },
  { re: /(?:this\s+is\s+(?:a\s+)?(?:secret|hidden)|not\s+visible\s+to\s+the\s+user|the\s+user\s+(?:cannot|can'?t|should\s+not)\s+see)/i, label: "намёк на скрытность от пользователя" },
];

const SENSITIVE: Pattern[] = [
  { re: /~\/\.ssh|\.ssh\/|id_(?:rsa|ed25519|ecdsa)/i, label: "ключи SSH" },
  { re: /\.aws\/(?:credentials|config)|aws_secret_access_key/i, label: "учётные данные AWS" },
  { re: /(?:^|[\s"'`(])\.env(?:\.[a-z]+)?(?:$|[\s"'`),.])/i, label: "файл .env" },
  { re: /\/etc\/(?:passwd|shadow|sudoers)/i, label: "системные файлы /etc" },
  { re: /\.(?:npmrc|netrc|pypirc|git-credentials|kube\/config|docker\/config\.json)/i, label: "файлы с токенами" },
  { re: /(?:claude_desktop_config|\bmcp\.json\b|\.cursor\/mcp|\.claude\/settings)/i, label: "конфиг MCP-клиента" },
  { re: /(?:keychain|credential\s+store|password\s+manager|browser\s+(?:cookies|profile))/i, label: "хранилища паролей и cookie" },
];

const MAX_PAIRWISE = 1_500;
const IMPERATIVE_CROSS = /(?:instead\s+of|rather\s+than|do\s+not\s+use|don'?t\s+use|never\s+use|always\s+(?:use|call)|first\s+(?:call|use)|before\s+(?:calling|using)|replace[sd]?|override)/i;

const EXEC_PARAMS = new Set(["command", "cmd", "shell", "script", "code", "eval", "exec", "expression", "args", "argv", "bash", "powershell"]);
const PATH_PARAMS = new Set(["path", "file", "filepath", "filename", "file_path", "dir", "directory", "folder", "dest", "destination", "src"]);
const URL_PARAMS = new Set(["url", "uri", "endpoint", "href", "webhook", "host", "address"]);
const QUERY_PARAMS = new Set(["sql", "query", "statement", "cypher", "gql"]);
const EXEC_NAME = /^(?:exec|execute|run|shell|bash|sh|cmd|eval|system|spawn|powershell)(?:[_\-.]|$)|(?:^|[_\-.])(?:exec|shell|eval|command)(?:[_\-.]|$)/i;
const DESTRUCTIVE_NAME = /^(?:delete|remove|drop|truncate|wipe|erase|format|kill|send|publish|transfer|pay)(?:[_\-.]|$)/i;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function matchAll(field: Field, patterns: Pattern[], rule: string, severity: Severity, say: (label: string) => string, tool: Tool): Finding[] {
  const out: Finding[] = [];
  for (const p of patterns) {
    const m = p.re.exec(field.text);
    if (!m) continue;
    out.push({ rule, severity: p.severity ?? severity, where: field.where, message: say(p.label), evidence: snippet(field.text, m.index, m[0].length), source: tool.source });
  }
  return out;
}

export function checkTool(tool: Tool): Finding[] {
  const out: Finding[] = [];
  const fields = fieldsOf(tool);
  for (const f of fields) {
    out.push(...matchAll(f, INJECTION, "BSK001", "high", (l) => `текст для модели ${l}`, tool));
    out.push(...matchAll(f, SENSITIVE, "BSK004", "high", (l) => `текст упоминает ${l}`, tool));
    out.push(...invisible(f, tool));
    out.push(...urls(f, tool));
    out.push(...obfuscation(f, tool));
  }
  out.push(...capability(tool));
  out.push(...schemaLoose(tool));
  return out;
}

function invisible(f: Field, tool: Tool): Finding[] {
  const found: number[] = [];
  let first = -1;
  let i = 0;
  for (const ch of f.text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (isInvisible(cp) && !(cp === 0xfeff && i === 0)) {
      found.push(cp);
      if (first < 0) first = i;
    }
    i += ch.length;
  }
  if (!found.length) return [];
  const hidden = decodeTags(f.text);
  const tagCount = found.filter((c) => c >= 0xe0000 && c <= 0xe007f).length;
  const bidi = found.some((c) => (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069));
  const parts = [`${found.length} невидимых символов`];
  if (tagCount) parts.push(`из них ${tagCount} Unicode-тегов`);
  if (bidi) parts.push("есть bidi-управление (меняет порядок показа текста)");
  const finding: Finding = {
    rule: "BSK002",
    severity: hidden ? "critical" : "high",
    where: f.where,
    message: parts.join(", "),
    evidence: hidden ? `скрытый текст: «${hidden.slice(0, 120)}»` : visible(snippet(f.text, first, found.length)),
    source: tool.source,
  };
  return [finding];
}

function urls(f: Field, tool: Tool): Finding[] {
  if (f.kind === "name") return [];
  const out: Finding[] = [];
  const img = /!\[[^\]]{0,100}\]\(\s*(?:https?:)?\/\/[^)\s]{1,300}\)/i.exec(f.text);
  if (img) {
    out.push({ rule: "BSK003", severity: "high", where: f.where, message: "markdown-картинка с внешним адресом: клиент может запросить её сам и унести данные в URL",
      evidence: snippet(f.text, img.index, img[0].length), source: tool.source });
  }
  const re = /\b(?:https?|ftp|wss?):\/\/[^\s)"'<>]{1,300}|\bdata:[a-z/+.-]{1,40};base64,/gi;
  let m: RegExpExecArray | null;
  let n = 0;
  while ((m = re.exec(f.text)) && n++ < 5) {
    const url = m[0];
    if (img && img[0].includes(url)) continue;
    const placeholder = /[{<$]|%7B|\bdata=|[?&](?:q|data|d|token|key|secret|payload|content|prompt)=/i.test(url);
    const plain = url.toLowerCase().startsWith("http://") && !/^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])/i.test(url);
    const severity: Severity = placeholder || url.startsWith("data:") ? "high" : plain ? "medium" : "low";
    out.push({ rule: "BSK003", severity, where: f.where, source: tool.source,
      message: placeholder ? "URL с подстановкой данных в адресе" : plain ? "URL без шифрования" : "внешний URL в тексте для модели",
      evidence: snippet(f.text, m.index, url.length) });
  }
  return out;
}

function obfuscation(f: Field, tool: Tool): Finding[] {
  const out: Finding[] = [];
  if (f.kind === "description" && f.text.length > 1500) {
    out.push({ rule: "BSK008", severity: f.text.length > 5000 ? "high" : "medium", where: f.where, source: tool.source,
      message: `описание длиной ${f.text.length} символов: в длинном тексте легко спрятать указания` });
  }
  if (/(?:\r?\n[ \t]*){13,}/.test(f.text) || / {200,}|\t{50,}/.test(f.text)) {
    out.push({ rule: "BSK008", severity: "medium", where: f.where, source: tool.source, message: "много пустых строк или пробелов: текст может прятаться за пределами видимой области" });
  }
  const b64 = /[A-Za-z0-9+/]{80,}={0,2}/.exec(f.text);
  const hex = /(?:[0-9a-fA-F]{2}[\s:]?){40,}/.exec(f.text);
  const blob = b64 ?? hex;
  if (blob) out.push({ rule: "BSK008", severity: "medium", where: f.where, source: tool.source, message: "закодированный блок (base64 или hex) в тексте для модели", evidence: snippet(f.text, blob.index, 20, 10) });
  return out;
}

function propertiesOf(tool: Tool): [string, Record<string, unknown>][] {
  const schema = tool.inputSchema;
  if (!isRecord(schema) || !isRecord(schema["properties"])) return [];
  return Object.entries(schema["properties"]).map(([k, v]) => [k, isRecord(v) ? v : {}]);
}

function constrained(prop: Record<string, unknown>): boolean {
  return Array.isArray(prop["enum"]) || prop["const"] !== undefined || typeof prop["pattern"] === "string" || typeof prop["format"] === "string" && prop["format"] !== "" && prop["format"] !== "string";
}

function capability(tool: Tool): Finding[] {
  const out: Finding[] = [];
  const base = `${tool.server}/${tool.name}`;
  if (EXEC_NAME.test(tool.name)) {
    out.push({ rule: "BSK006", severity: "medium", where: `${base}.name`, source: tool.source, message: "название указывает на выполнение команд или кода" });
  }
  for (const [name, prop] of propertiesOf(tool)) {
    const key = name.toLowerCase();
    const type = prop["type"];
    if (type !== undefined && type !== "string" && !(Array.isArray(type) && type.includes("string"))) continue;
    const bounded = constrained(prop);
    const where = `${base}.inputSchema.properties.${name}`;
    if (EXEC_PARAMS.has(key) && !bounded) out.push({ rule: "BSK006", severity: "high", where, source: tool.source, message: `параметр «${name}» принимает произвольную строку и похож на команду или код` });
    else if (PATH_PARAMS.has(key) && !bounded) out.push({ rule: "BSK006", severity: "medium", where, source: tool.source, message: `параметр «${name}» принимает любой путь: возможен выход за пределы разрешённой папки` });
    else if (URL_PARAMS.has(key) && !bounded) out.push({ rule: "BSK006", severity: "medium", where, source: tool.source, message: `параметр «${name}» принимает любой адрес: возможны запросы во внутреннюю сеть (SSRF)` });
    else if (QUERY_PARAMS.has(key) && !bounded) out.push({ rule: "BSK006", severity: "medium", where, source: tool.source, message: `параметр «${name}» принимает произвольный запрос к базе` });
  }
  if (DESTRUCTIVE_NAME.test(tool.name)) {
    out.push({ rule: "BSK006", severity: "info", where: `${base}.name`, source: tool.source, message: "необратимое действие: убедитесь, что клиент спрашивает подтверждение пользователя" });
  }
  return out;
}

function schemaLoose(tool: Tool): Finding[] {
  const base = `${tool.server}/${tool.name}.inputSchema`;
  const schema = tool.inputSchema;
  if (schema === undefined) return [{ rule: "BSK007", severity: "low", where: base, source: tool.source, message: "схема входа не задана: модель сама решает, что передать" }];
  if (isRecord(schema) && schema["type"] === "object" && schema["additionalProperties"] !== false && !isRecord(schema["properties"])) {
    return [{ rule: "BSK007", severity: "low", where: base, source: tool.source, message: "объект без описанных свойств: принимает любые поля" }];
  }
  return [];
}

function levenshtein(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 1) return 2;
  const dp: number[] = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0] ?? 0;
    dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cur = dp[j] ?? 0;
      dp[j] = Math.min(cur + 1, (dp[j - 1] ?? 0) + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = cur;
    }
  }
  return dp[b.length] ?? 2;
}

/** Правила, которым нужен весь набор инструментов: совпадения и ссылки между ними. */
export function checkAcross(tools: Tool[]): Finding[] {
  const out: Finding[] = [];
  const byName = new Map<string, Tool[]>();
  for (const t of tools) byName.set(t.name, [...(byName.get(t.name) ?? []), t]);
  for (const [name, list] of byName) {
    const servers = new Set(list.map((t) => t.server));
    if (servers.size > 1) {
      out.push({ rule: "BSK005", severity: "high", where: `${[...servers].join(" и ")}/${name}`, source: list[0]?.source,
        message: `инструмент «${name}» объявлен на нескольких серверах: один может затенять другой` });
    }
  }
  for (const t of tools) {
    if (/[^\x20-\x7e]/.test(t.name) && !isInvisible(t.name.codePointAt(0) ?? 0)) {
      out.push({ rule: "BSK005", severity: "medium", where: `${t.server}/${t.name}.name`, source: t.source, message: "в названии не-ASCII символы: возможна подмена похожими буквами (гомоглифы)", evidence: visible(t.name) });
    }
  }
  const names = [...byName.keys()];
  const limit = names.length <= MAX_PAIRWISE ? names.length : 0; // O(n²): на огромных наборах похожие названия не сравниваем
  for (let i = 0; i < limit; i++) {
    for (let j = i + 1; j < limit; j++) {
      const a = names[i] ?? "";
      const b = names[j] ?? "";
      if (a.length < 5 || b.length < 5 || a.toLowerCase() === b.toLowerCase() && a === b) continue;
      const ta = byName.get(a)?.[0];
      const tb = byName.get(b)?.[0];
      if (ta && tb && ta.server !== tb.server && levenshtein(a.toLowerCase(), b.toLowerCase()) <= 1) {
        out.push({ rule: "BSK005", severity: "medium", where: `${ta.server}/${a} ≈ ${tb.server}/${b}`, source: ta.source, message: "почти одинаковые названия на разных серверах: легко перепутать или подменить" });
      }
    }
  }
  const known = new Set(names);
  for (const t of tools) {
    const text = (t.description ?? "").slice(0, 50_000);
    if (!IMPERATIVE_CROSS.test(text)) continue;
    for (const raw of text.match(/[A-Za-z0-9_.-]{5,}/g) ?? []) {
      const other = raw.replace(/[.-]+$/, "");
      if (other !== t.name && known.has(other)) {
        out.push({ rule: "BSK005", severity: "high", where: `${t.server}/${t.name}.description`, source: t.source,
          message: `описание управляет другим инструментом «${other}»`, evidence: snippet(text, text.indexOf(other), other.length) });
        break;
      }
    }
  }
  return out;
}
