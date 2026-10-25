import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "../src/config.js";
import { Gateway } from "../src/gateway.js";
import { makeLock } from "../src/vendor/basilisk/pin.js";
import { NaiveAgent, type TraceEntry } from "./agent.js";
import { DirectClient, GatewayClient, specFor } from "./clients.js";
import { DEFENSES, type Defense, toConfig } from "./defenses.js";
import { type Effect, SCENARIOS, type Scenario } from "./scenarios.js";

/** Исход для атаки: stopped или compromised. Для безобидного сценария: works, needs-approval или broken. */
export type Outcome = "compromised" | "stopped" | "works" | "needs-approval" | "broken";

export interface Cell {
  scenario: string;
  defense: string;
  outcome: Outcome;
  calls: number;
  blocked: number;
}

function readEffects(file: string): Effect[] {
  return readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as Effect);
}

function servers(s: Scenario, dir: string, extra: Record<string, string>) {
  mkdirSync(join(dir, "files", "public"), { recursive: true });
  writeFileSync(join(dir, "files", "public", "readme.txt"), "Публичный файл.");
  writeFileSync(join(dir, "secret.txt"), "CANARY-FILE-9c21b4");
  const log = join(dir, "effects.jsonl");
  writeFileSync(log, "");
  const env = { RANGE_LOG: log, RANGE_ROOT: join(dir, "files", "public"), ...(s.env ?? {}), ...extra };
  return { log, specs: Object.fromEntries(s.servers.map((name) => [name, specFor(name, env, s.untrusted?.includes(name) ?? false)])) };
}

/** Закрепление строится по честному состоянию серверов (без отравления): так закрепляет человек, который ещё ничего плохого не видел. */
async function makeLockFile(s: Scenario, defense: Defense, dir: string): Promise<string> {
  const cleanDir = mkdtempSync(join(tmpdir(), "citadel-lock-"));
  const { specs } = servers({ ...s, env: {} }, cleanDir, {});
  const cfg: Config = toConfig({ ...defense, pin: false }, specs, cleanDir, "");
  const gw = new Gateway({ config: cfg, emit: () => {}, log: () => {} });
  await gw.start();
  const lockPath = join(dir, "citadel.lock.json");
  writeFileSync(lockPath, JSON.stringify(makeLock(gw.inventory())));
  await gw.stop();
  rmSync(cleanDir, { recursive: true, force: true });
  return lockPath;
}

export async function runCell(s: Scenario, defense: Defense, auditOut?: string): Promise<Cell> {
  const dir = mkdtempSync(join(tmpdir(), "citadel-bench-"));
  try {
    const { log, specs } = servers(s, dir, {});
    let trace: TraceEntry[];
    if (defense.policy === null) {
      const client = await DirectClient.open(specs);
      try {
        trace = await new NaiveAgent(client, (_server, tool) => tool).run(s.steps);
      } finally {
        await client.close();
      }
    } else {
      const lock = defense.pin ? await makeLockFile(s, defense, dir) : "";
      const client = await GatewayClient.open(toConfig(defense, specs, dir, lock));
      try {
        trace = await new NaiveAgent(client, (server, tool) => `${server}__${tool}`).run(s.steps);
      } finally {
        await client.close();
      }
    }
    if (auditOut && existsSync(join(dir, "audit.jsonl"))) appendFileSync(auditOut, readFileSync(join(dir, "audit.jsonl"), "utf8"));
    const effects = readEffects(log);
    const blocked = trace.filter((t) => t.isError && t.text.startsWith("citadel:")).length;
    const base = { scenario: s.id, defense: defense.id, calls: trace.length, blocked };
    const ok = s.success(effects, trace);
    if (s.kind === "attack") return { ...base, outcome: ok ? "compromised" : "stopped" };
    if (ok) return { ...base, outcome: "works" };
    const pending = trace.some((t) => t.text.includes("citadel approve"));
    return { ...base, outcome: pending ? "needs-approval" : "broken" };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export async function runMatrix(only?: { scenarios?: string[]; defenses?: string[] }): Promise<Cell[]> {
  const cells: Cell[] = [];
  for (const s of SCENARIOS) {
    if (only?.scenarios && !only.scenarios.includes(s.id)) continue;
    for (const d of DEFENSES) {
      if (only?.defenses && !only.defenses.includes(d.id)) continue;
      cells.push(await runCell(s, d));
    }
  }
  return cells;
}

const SYMBOL: Record<Outcome, string> = { compromised: "✗ взломан", stopped: "✓ остановлена", works: "✓ работает", "needs-approval": "⏸ нужно подтверждение", broken: "✗ сломано" };

export function renderMarkdown(cells: Cell[]): string {
  const lines: string[] = [];
  const head = (ids: string[]) => `| сценарий | ${ids.join(" | ")} |\n| :-- | ${ids.map(() => ":--:").join(" | ")} |`;
  const ids = DEFENSES.map((d) => d.id);
  const section = (kind: "attack" | "benign", title: string) => {
    lines.push(`### ${title}`, "", head(ids));
    for (const s of SCENARIOS.filter((x) => x.kind === kind)) {
      const row = ids.map((id) => SYMBOL[cells.find((c) => c.scenario === s.id && c.defense === id)?.outcome ?? "broken"]);
      lines.push(`| **${s.id}** ${s.title} | ${row.join(" | ")} |`);
    }
    lines.push("");
  };
  section("attack", "Атаки: что удалось атакующему");
  section("benign", "Полезная работа: что осталось рабочим");
  lines.push("Уровни защиты:", "", ...DEFENSES.map((d) => `- **${d.id}** ${d.title}`), "");
  return lines.join("\n");
}
