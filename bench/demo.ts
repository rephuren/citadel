/** Собирает демонстрационный журнал аудита: все сценарии полигона под полной защитой. Нужен для дашборда и скриншота. */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { DEFENSES } from "./defenses.js";
import { runCell } from "./runner.js";
import { SCENARIOS } from "./scenarios.js";

const out = process.argv[2] ?? ".citadel/demo-audit.jsonl";
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, "");
const full = DEFENSES[DEFENSES.length - 1];
if (!full) throw new Error("нет уровней защиты");
for (const s of SCENARIOS) await runCell(s, full, out);
process.stdout.write(`журнал: ${out}\n`);
