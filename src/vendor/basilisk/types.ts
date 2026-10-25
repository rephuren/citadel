// Копия из проекта basilisk (MIT), синхронизируется скриптом scripts/sync-basilisk.mjs. Правки вносите в basilisk.
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Tool {
  server: string;
  name: string;
  description?: string;
  inputSchema?: unknown;
  /** файл, из которого прочитано определение */
  source: string;
}

export interface ServerConfig {
  name: string;
  command?: string;
  args: string[];
  url?: string;
  env: Record<string, string>;
  source: string;
}

export interface Finding {
  rule: string;
  severity: Severity;
  message: string;
  /** где найдено: сервер/инструмент и поле */
  where: string;
  /** фрагмент, из-за которого сработало правило (обрезан, секреты замаскированы) */
  evidence?: string;
  source?: string;
}

export interface RuleInfo {
  id: string;
  title: string;
  severity: Severity;
  owasp: string;
  fix: string;
}

export interface Inventory {
  tools: Tool[];
  servers: ServerConfig[];
  /** файлы, которые распознаны как конфиг или описание инструментов */
  files: string[];
  /** файлы, пропущенные из-за размера, формата или ошибки разбора */
  skipped: { file: string; reason: string }[];
}

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}
