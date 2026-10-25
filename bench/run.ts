import { writeFileSync } from "node:fs";
import { renderMarkdown, runMatrix } from "./runner.js";

const cells = await runMatrix();
const md = renderMarkdown(cells);
process.stdout.write(md + "\n");
const out = process.argv[2];
if (out) {
  writeFileSync(out, md + "\n");
  writeFileSync(out.replace(/\.md$/, ".json"), JSON.stringify(cells, null, 2) + "\n");
  process.stdout.write(`сохранено: ${out}\n`);
}
