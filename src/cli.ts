#!/usr/bin/env node
import { realpathSync, writeFileSync } from "node:fs";
import type { Readable, Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { Approvals } from "./approvals.js";
import { type Config, loadConfig } from "./config.js";
import { Gateway, VERSION } from "./gateway.js";
import { LineReader, encode, errorResponse, parseMessage } from "./jsonrpc.js";
import { makeLock } from "./vendor/basilisk/pin.js";
import { severityRank } from "./vendor/basilisk/types.js";

const HELP = `citadel: шлюз безопасности для MCP-агентов

использование:
  citadel serve --config <файл>        запустить шлюз на stdio (его подключают к ИИ-клиенту вместо серверов)
  citadel check --config <файл>        запустить серверы, проверить их определения и показать, что будет скрыто
  citadel pin --config <файл>          закрепить текущие определения (sanitize.pinFile или --out)
  citadel approvals --config <файл>    список ожидающих подтверждений
  citadel approve <id> --config <файл> разрешить один раз вызов с этим номером
  citadel deny <id> --config <файл>    отклонить
  citadel dashboard --audit <файл>     локальный дашборд по журналу аудита (--port, по умолчанию 8120)

общие: --version, --help
коды возврата: 0 успех, 1 найдены проблемы (check) или нечего подтверждать, 2 ошибка использования или конфигурации`;

export async function serve(config: Config, input: Readable, output: Writable, log: (l: string) => void): Promise<void> {
  const gateway = new Gateway({ config, emit: (m) => void output.write(encode(m)), log });
  await gateway.start();
  const reader = new LineReader(undefined, () => log("citadel: строка клиента длиннее лимита отброшена"));
  input.setEncoding("utf8");
  const pending = new Set<Promise<void>>();
  input.on("data", (chunk: string) => {
    for (const line of reader.feed(chunk)) {
      const msg = parseMessage(line);
      if (!msg) {
        output.write(encode(errorResponse(null, -32700, "некорректное сообщение JSON-RPC")));
        continue;
      }
      const p = gateway.handle(msg).finally(() => pending.delete(p));
      pending.add(p);
    }
  });
  await new Promise<void>((resolve) => input.once("end", resolve));
  await Promise.allSettled([...pending]);
  await gateway.stop();
}

async function withGateway<T>(config: Config, fn: (g: Gateway) => T | Promise<T>): Promise<T> {
  const g = new Gateway({ config, emit: () => {}, log: (l) => process.stderr.write(`${l}\n`) });
  try {
    await g.start();
    return await fn(g);
  } finally {
    await g.stop();
  }
}

export async function run(argv: string[], write: (s: string) => void = (s) => void process.stdout.write(s)): Promise<number> {
  try {
    const { values, positionals } = parseArgs({
      args: argv,
      allowPositionals: true,
      options: { config: { type: "string" }, out: { type: "string" }, audit: { type: "string" }, port: { type: "string" }, version: { type: "boolean" }, help: { type: "boolean" } },
    });
    if (values.version) return write(`${VERSION}\n`), 0;
    const [command, arg] = positionals;
    if (values.help || !command) return write(`${HELP}\n`), command || values.help ? 0 : 2;

    if (command === "dashboard") {
      const { startDashboard } = await import("./dashboard.js");
      if (!values.audit) throw new Error("dashboard: укажите --audit <файл журнала>");
      const port = Number(values.port ?? 8120);
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("--port: ожидается число от 1 до 65535");
      await startDashboard(values.audit, port, (l) => write(`${l}\n`));
      return await new Promise<number>(() => {}); // работает до остановки процесса
    }

    if (!values.config) throw new Error(`${command}: укажите --config <файл>`);
    const config = loadConfig(values.config);

    if (command === "serve") {
      await serve(config, process.stdin, process.stdout, (l) => process.stderr.write(`${l}\n`));
      return 0;
    }
    if (command === "check") {
      return await withGateway(config, (g) => {
        let bad = 0;
        for (const e of g.catalog.values()) {
          const worst = e.findings.reduce((w, f) => Math.min(w, severityRank(f.severity)), 9);
          const status = e.quarantine ? `СКРЫТ: ${e.quarantine}` : "виден модели";
          if (e.quarantine) bad++;
          write(`${e.qualified.padEnd(34)} ${status}${e.findings.length ? `  (находок ${e.findings.length}, худшая: ${["critical", "high", "medium", "low", "info"][worst]})` : ""}\n`);
        }
        write(`\nинструментов ${g.catalog.size}, скрыто ${bad}\n`);
        return bad ? 1 : 0;
      });
    }
    if (command === "pin") {
      const file = values.out ?? config.policy.sanitize.pinFile;
      if (!file) throw new Error("pin: укажите --out или sanitize.pinFile в конфигурации");
      return await withGateway({ ...config, policy: { ...config.policy, sanitize: { ...config.policy.sanitize, pinFile: undefined as unknown as string } } }, (g) => {
        const inv = g.inventory();
        writeFileSync(file, JSON.stringify(makeLock(inv), null, 2) + "\n");
        write(`закреплено инструментов: ${inv.tools.length} → ${file}\n`);
        return 0;
      });
    }
    const approvals = new Approvals(config.policy.approvals.file);
    if (command === "approvals") {
      const list = approvals.list().filter((a) => a.status === "pending");
      for (const a of list) write(`${a.id}  ${a.tool}\n    ${a.reason}\n`);
      if (!list.length) write("ожидающих подтверждений нет\n");
      return 0;
    }
    if (command === "approve" || command === "deny") {
      if (!arg) throw new Error(`${command}: укажите номер`);
      const ok = approvals.resolve(arg, command === "approve" ? "approved" : "denied");
      write(ok ? `${command === "approve" ? "разрешено" : "отклонено"}: ${arg}\n` : `номер ${arg} не найден среди ожидающих (срок действия 10 минут)\n`);
      return ok ? 0 : 1;
    }
    throw new Error(`неизвестная команда «${command}»`);
  } catch (e) {
    process.stderr.write(`ошибка: ${e instanceof Error ? e.message : String(e)}\n`);
    return 2;
  }
}

const entry = process.argv[1] ? realpathSync(process.argv[1]) : "";
if (entry === fileURLToPath(import.meta.url)) void run(process.argv.slice(2)).then((code) => process.exit(code));

