// Обновляет копию модулей basilisk в src/vendor/basilisk. Использование: node scripts/sync-basilisk.mjs <путь к basilisk>
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const src = process.argv[2];
if (!src) {
  console.error("укажите путь к репозиторию basilisk");
  process.exit(2);
}
const files = ["src/text.ts", "src/types.ts", "src/pin.ts", "src/rules/tools.ts", "src/rules/catalog.ts"];
const header = "// Копия из проекта basilisk (MIT), синхронизируется скриптом scripts/sync-basilisk.mjs. Правки вносите в basilisk.\n";
for (const f of files) {
  const target = join("src/vendor/basilisk", f.replace(/^src\//, ""));
  mkdirSync(dirname(target), { recursive: true });
  copyFileSync(join(src, f), target);
  writeFileSync(target, header + readFileSync(target, "utf8"));
  console.log(`обновлено: ${target}`);
}
