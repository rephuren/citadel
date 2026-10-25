// Запускает скомпилированные тесты на любой поддерживаемой версии Node: папки и маски в `node --test` ведут себя по-разному.
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { join } from "node:path";

const dir = "dist/tests";
const files = readdirSync(dir).filter((f) => f.endsWith(".test.js")).map((f) => join(dir, f));
if (!files.length) {
  console.error("тесты не найдены: сначала npm run build");
  process.exit(2);
}
process.exit(spawnSync(process.execPath, ["--test", ...files], { stdio: "inherit" }).status ?? 1);
