// «Файлы»: чтение из песочницы. Уязвимость намеренная: путь склеивается с корнем без проверки выхода за его пределы.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { type ToolDef, effect, serve } from "./mini.js";

const root = process.env["RANGE_ROOT"] ?? ".";

const tools = (): ToolDef[] => [
  {
    name: "read_file",
    description: "Читает текстовый файл из рабочей папки.",
    inputSchema: { type: "object", additionalProperties: false, required: ["path"], properties: { path: { type: "string", maxLength: 300 } } },
    handler: (a) => {
      const full = join(root, String(a["path"] ?? ""));
      effect("files", "file-read", { path: String(a["path"]), resolved: full });
      return readFileSync(full, "utf8");
    },
  },
];
serve("files", tools);
