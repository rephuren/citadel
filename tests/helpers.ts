import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type Config, DEFAULT_POLICY, type Policy, type ServerSpec } from "../src/config.js";
import { Gateway } from "../src/gateway.js";
import type { Message } from "../src/jsonrpc.js";

export const RANGE = (name: string) => fileURLToPath(new URL(`../range/server_${name}.js`, import.meta.url));
export const tmp = () => mkdtempSync(join(tmpdir(), "citadel-"));

export function spec(name: string, extra: Partial<ServerSpec> = {}, env: Record<string, string> = {}): ServerSpec {
  return { command: process.execPath, args: [RANGE(name)], env, inheritEnv: false, trust: "trusted", ...extra };
}

export interface Rig {
  gw: Gateway;
  dir: string;
  out: Message[];
  effects: () => { server: string; kind: string; [k: string]: unknown }[];
  call: (tool: string, args?: unknown) => Promise<{ text: string; isError: boolean; raw: Record<string, unknown> }>;
  stop: () => Promise<void>;
}

export function policy(over: Partial<Policy> = {}): Policy {
  return { ...DEFAULT_POLICY, ...over, limits: { ...DEFAULT_POLICY.limits, ...(over.limits ?? {}), timeoutMs: 10_000 } };
}

export async function rig(servers: string[], pol: Partial<Policy> = {}, opts: { untrusted?: string[]; clock?: () => number; dir?: string; pin?: string } = {}): Promise<Rig> {
  const dir = opts.dir ?? tmp();
  const root = join(dir, "files");
  mkdirSync(join(root, "public"), { recursive: true });
  writeFileSync(join(root, "public", "readme.txt"), "Публичный файл.");
  writeFileSync(join(dir, "secret.txt"), "CANARY-FILE-9c21b4");
  const log = join(dir, "effects.jsonl");
  writeFileSync(log, "");
  const env = { RANGE_LOG: log, RANGE_ROOT: join(root, "public") };
  const specs: Record<string, ServerSpec> = {};
  for (const s of servers) specs[s] = spec(s, { trust: opts.untrusted?.includes(s) ? "untrusted" : "trusted" }, env);
  const policyFull = policy({ ...pol, audit: { file: join(dir, "audit.jsonl") }, approvals: { file: join(dir, "approvals.json") }, ...(pol.sanitize ? { sanitize: { ...pol.sanitize, ...(opts.pin ? { pinFile: opts.pin } : {}) } } : opts.pin ? { sanitize: { ...DEFAULT_POLICY.sanitize, pinFile: opts.pin } } : {}) });
  const config: Config = { servers: specs, policy: policyFull };
  const out: Message[] = [];
  const gw = new Gateway({ config, emit: (m) => void out.push(m), log: () => {}, ...(opts.clock ? { clock: opts.clock } : {}) });
  await gw.start();
  const effects = () => {
    const text = require_fs(log);
    return text.split("\n").filter(Boolean).map((l) => JSON.parse(l) as { server: string; kind: string });
  };
  const call = async (tool: string, args: unknown = {}) => {
    const raw = (await gw.call(tool, args)) as Record<string, unknown>;
    const content = (raw["content"] as { text?: string }[] | undefined) ?? [];
    return { text: content.map((c) => c.text ?? "").join("\n"), isError: raw["isError"] === true, raw };
  };
  const handle: Rig = { gw, dir, out, effects, call, stop: () => gw.stop() };
  open.push(handle);
  return handle;
}

const open: Rig[] = [];
/** Останавливает все шлюзы, даже если тест упал до stop(): иначе дочерние процессы не дают тестовому раннеру завершиться. */
export async function stopAll(): Promise<void> {
  await Promise.allSettled(open.splice(0).map((r) => r.stop()));
}

import { readFileSync } from "node:fs";
function require_fs(path: string): string {
  return readFileSync(path, "utf8");
}

export async function waitFor(cond: () => boolean, ms = 5000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error("условие не выполнилось вовремя");
    await new Promise((r) => setTimeout(r, 20));
  }
}
