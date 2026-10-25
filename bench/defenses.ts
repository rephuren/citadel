import type { Config, Policy, ToolRule } from "../src/config.js";
import { DEFAULT_POLICY } from "../src/config.js";

export interface Defense {
  id: string;
  title: string;
  /** null: прямое подключение без шлюза */
  policy: Policy | null;
  pin: boolean;
}

const LABELS: ToolRule[] = [
  { match: "notes__*", labels: ["private"] },
  { match: "mail__send_email", labels: ["sink"] },
];
const CONSTRAINTS: ToolRule[] = [
  { match: "files__read_file", args: { path: { pattern: "^[A-Za-z0-9_./-]+$", forbid: [".."], maxLength: 120 } } },
  { match: "web__fetch_page", args: { url: { pattern: "^https://example\\.test/", forbid: ["169.254", "localhost", "127.0.0.1"] } } },
  { match: "tasks__delete_*", action: "confirm" },
];

const base = (over: Partial<Policy>): Policy => ({ ...DEFAULT_POLICY, ...over });

export const DEFENSES: Defense[] = [
  { id: "D0", title: "прямое подключение, без шлюза", policy: null, pin: false },
  { id: "D1", title: "шлюз с настройками по умолчанию (пространства имён, лимиты, аудит)", policy: base({}), pin: false },
  { id: "D2", title: "+ очистка определений, скрытие опасных, закрепление", policy: base({ sanitize: { stripInvisible: true, blockDefinitionsAt: "high", scanResults: "off" } }), pin: true },
  { id: "D3", title: "+ политики аргументов и подтверждение разрушительных вызовов", policy: base({ rules: [...CONSTRAINTS, ...LABELS], sanitize: { stripInvisible: true, blockDefinitionsAt: "high", scanResults: "off" } }), pin: true },
  { id: "D4", title: "+ отслеживание заражённых данных («смертельная тройка»)", policy: base({ rules: [...CONSTRAINTS, ...LABELS], taint: { mode: "trifecta", onViolation: "confirm" }, sanitize: { stripInvisible: true, blockDefinitionsAt: "high", scanResults: "off" } }), pin: true },
  { id: "D5", title: "+ проверка результатов на инъекции", policy: base({ rules: [...CONSTRAINTS, ...LABELS], taint: { mode: "trifecta", onViolation: "confirm" }, sanitize: { stripInvisible: true, blockDefinitionsAt: "high", scanResults: "block" } }), pin: true },
];

export function toConfig(defense: Defense, servers: Config["servers"], dir: string, pinFile: string): Config {
  const policy = defense.policy as Policy;
  return {
    servers,
    policy: {
      ...policy,
      audit: { file: `${dir}/audit.jsonl` },
      approvals: { file: `${dir}/approvals.json` },
      sanitize: { ...policy.sanitize, ...(defense.pin ? { pinFile } : {}) },
    },
  };
}
