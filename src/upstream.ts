/** Клиент MCP к одному серверу по stdio: запуск процесса, рукопожатие, список инструментов, вызов. */
import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { ERR, LineReader, type Message, type Response, encode, errorResponse, isNotification, isRequest, isResponse, parseMessage } from "./jsonrpc.js";
import type { ServerSpec } from "./config.js";

export const PROTOCOL_VERSION = "2025-06-18";
const MAX_TOOLS = 2_000;
const MAX_PAGES = 50;

export interface UpstreamTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
  [key: string]: unknown;
}

export class UpstreamError extends Error {
  constructor(message: string, readonly code: number = ERR.upstream) {
    super(message);
  }
}

export interface UpstreamOptions {
  timeoutMs: number;
  onStderr?: (line: string) => void;
  onToolsChanged?: () => void;
  /** запросы сервера к клиенту (sampling, roots, elicitation) отклоняются; сюда попадает их название для аудита */
  onRefusedRequest?: (method: string) => void;
}

const SAFE_ENV = ["PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR", "SystemRoot", "USERPROFILE"];

export function childEnv(spec: ServerSpec, base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  if (spec.inheritEnv) return { ...base, ...spec.env };
  const env: NodeJS.ProcessEnv = {};
  for (const k of SAFE_ENV) if (base[k] !== undefined) env[k] = base[k];
  return { ...env, ...spec.env };
}

/** Общее для любого транспорта: постраничный список инструментов и вызов. Транспорт даёт только request/start/close. */
export abstract class BaseUpstream {
  stderrTail = "";

  constructor(readonly name: string) {}

  abstract get alive(): boolean;
  abstract start(): Promise<void>;
  abstract request(method: string, params?: unknown, timeoutMs?: number): Promise<Response>;
  abstract close(): Promise<void>;

  async listTools(): Promise<UpstreamTool[]> {
    const tools: UpstreamTool[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < MAX_PAGES; page++) {
      const res = await this.request("tools/list", cursor ? { cursor } : {});
      if (res.error) throw new UpstreamError(`${this.name}: tools/list: ${res.error.message}`);
      const result = res.result as { tools?: unknown; nextCursor?: unknown } | undefined;
      if (!result || !Array.isArray(result.tools)) throw new UpstreamError(`${this.name}: tools/list вернул неверную форму`);
      for (const t of result.tools) {
        if (typeof t === "object" && t !== null && typeof (t as UpstreamTool).name === "string") tools.push(t as UpstreamTool);
        if (tools.length >= MAX_TOOLS) return tools;
      }
      if (typeof result.nextCursor !== "string" || !result.nextCursor) return tools;
      cursor = result.nextCursor;
    }
    return tools;
  }

  async callTool(name: string, args: unknown, timeoutMs?: number): Promise<unknown> {
    const res = await this.request("tools/call", { name, arguments: args ?? {} }, timeoutMs);
    if (res.error) throw new UpstreamError(`${this.name}: ${res.error.message}`, res.error.code);
    return res.result;
  }
}

export class Upstream extends BaseUpstream {
  private child: ChildProcessWithoutNullStreams | undefined;
  private nextId = 1;
  private pending = new Map<number, { resolve: (r: Response) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
  private exited = false;
  constructor(name: string, private readonly spec: ServerSpec, private readonly opts: UpstreamOptions) {
    super(name);
  }

  get alive(): boolean {
    return !!this.child && !this.exited;
  }

  async start(): Promise<void> {
    const command = this.spec.command;
    if (!command) throw new UpstreamError(`${this.name}: для stdio-сервера нужен command`);
    const child = spawn(command, this.spec.args, {
      cwd: this.spec.cwd,
      env: childEnv(this.spec),
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child = child;
    const reader = new LineReader(undefined, () => this.opts.onStderr?.(`[${this.name}] строка длиннее лимита отброшена`));
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      for (const line of reader.feed(chunk)) this.onLine(line);
    });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      this.stderrTail = (this.stderrTail + chunk).slice(-4096);
      for (const l of chunk.split("\n")) if (l.trim()) this.opts.onStderr?.(`[${this.name}] ${l.slice(0, 500)}`);
    });
    child.stdin.on("error", () => {});
    const failed = new Promise<never>((_, reject) => {
      child.once("error", (e) => {
        this.exited = true; // процесс не стартовал: ждать его завершения незачем
        const why = new UpstreamError(`${this.name}: не удалось запустить «${command}»: ${e.message}`);
        this.failPending(why);
        reject(why);
      });
    });
    child.once("exit", (code, signal) => {
      this.exited = true;
      this.failPending(new UpstreamError(`${this.name}: процесс завершился (${signal ?? `код ${code}`})`));
    });
    await Promise.race([failed, this.handshake()]);
  }

  private failPending(why: Error): void {
    for (const [id, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(why);
      this.pending.delete(id);
    }
  }

  private async handshake(): Promise<void> {
    const res = await this.request("initialize", {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "citadel", version: "0.1.0" },
    });
    if (res.error) throw new UpstreamError(`${this.name}: сервер отклонил initialize: ${res.error.message}`);
    this.send({ jsonrpc: "2.0", method: "notifications/initialized" });
  }

  private onLine(line: string): void {
    const msg = parseMessage(line);
    if (!msg) return;
    if (isResponse(msg)) {
      if (typeof msg.id !== "number") return;
      const p = this.pending.get(msg.id);
      if (!p) return;
      clearTimeout(p.timer);
      this.pending.delete(msg.id);
      p.resolve(msg);
    } else if (isRequest(msg)) {
      // sampling, roots, elicitation: чужой сервер не должен просить нашу модель или данные клиента
      this.opts.onRefusedRequest?.(msg.method);
      this.send(errorResponse(msg.id, msg.method === "ping" ? ERR.internal : ERR.methodNotFound, "citadel: запрос сервера к клиенту отклонён"));
      if (msg.method === "ping") this.send({ jsonrpc: "2.0", id: msg.id, result: {} });
    } else if (isNotification(msg) && msg.method === "notifications/tools/list_changed") {
      this.opts.onToolsChanged?.();
    }
  }

  private send(msg: Message): void {
    if (!this.child || this.exited) return;
    this.child.stdin.write(encode(msg));
  }

  request(method: string, params?: unknown, timeoutMs = this.opts.timeoutMs): Promise<Response> {
    return new Promise((resolve, reject) => {
      if (!this.alive && method !== "initialize") return reject(new UpstreamError(`${this.name}: сервер не запущен`));
      const id = this.nextId++;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new UpstreamError(`${this.name}: нет ответа на ${method} за ${timeoutMs} мс`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.send({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) });
    });
  }

  async close(): Promise<void> {
    const child = this.child;
    if (!child || this.exited) return;
    child.stdin.end();
    await new Promise<void>((resolve) => {
      const t = setTimeout(() => {
        child.kill("SIGKILL");
        resolve();
      }, 1500);
      child.once("exit", () => {
        clearTimeout(t);
        resolve();
      });
    });
  }
}
