/** Клиент MCP к одному серверу по streamable HTTP: каждый запрос это POST, ответ приходит как JSON или как поток SSE. */
import { ERR, MAX_LINE_BYTES, type Message, type Response, errorResponse, isNotification, isRequest, isResponse, parseMessage } from "./jsonrpc.js";
import type { ServerSpec } from "./config.js";
import { BaseUpstream, PROTOCOL_VERSION, UpstreamError, type UpstreamOptions } from "./upstream.js";

const CLOSE_TIMEOUT_MS = 1500;
const MAX_STREAM_RETRIES = 3;

/** Разбор потока SSE: события разделены пустой строкой, поля data склеиваются через перевод строки. */
export class SseParser {
  private buf = "";
  private data: string[] = [];

  feed(chunk: string): string[] {
    this.buf += chunk;
    if (this.buf.length > MAX_LINE_BYTES) throw new UpstreamError("событие SSE длиннее лимита");
    const events: string[] = [];
    let nl: number;
    while ((nl = this.buf.search(/\r\n|\n|\r/)) >= 0) {
      const line = this.buf.slice(0, nl);
      const sep = this.buf.startsWith("\r\n", nl) ? 2 : 1;
      if (sep === 1 && this.buf[nl] === "\r" && nl + 1 === this.buf.length) break; // одинокий «\r» в конце: возможно, «\n» придёт в следующем куске
      this.buf = this.buf.slice(nl + sep);
      if (line === "") {
        if (this.data.length) events.push(this.data.join("\n"));
        this.data = [];
      } else if (line.startsWith("data:")) {
        this.data.push(line.slice(5).replace(/^ /, ""));
      }
    }
    return events;
  }
}

export class HttpUpstream extends BaseUpstream {
  private nextId = 1;
  private sessionId: string | undefined;
  private ready = false;
  private closed = false;
  private readonly inflight = new Set<AbortController>();
  private streamAc: AbortController | undefined;
  private readonly url: string;

  constructor(name: string, private readonly spec: ServerSpec, private readonly opts: UpstreamOptions) {
    super(name);
    if (!spec.url) throw new UpstreamError(`${name}: для сервера по HTTP нужен url`);
    this.url = spec.url;
  }

  get alive(): boolean {
    return this.ready && !this.closed;
  }

  /** Адрес для сообщений об ошибках: без пути и параметров, в них бывают токены. */
  private get where(): string {
    return new URL(this.url).origin;
  }

  private headers(): Record<string, string> {
    return {
      ...(this.spec.headers ?? {}),
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "MCP-Protocol-Version": PROTOCOL_VERSION,
      ...(this.sessionId ? { "Mcp-Session-Id": this.sessionId } : {}),
    };
  }

  async start(): Promise<void> {
    const res = await this.request("initialize", {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "citadel", version: "0.1.0" },
    });
    if (res.error) throw new UpstreamError(`${this.name}: сервер отклонил initialize: ${res.error.message}`);
    await this.notify({ jsonrpc: "2.0", method: "notifications/initialized" });
    this.ready = true;
    void this.listen();
  }

  /**
   * Отдельный поток GET: сервер может присылать уведомления в любой момент, а не только в ответе на запрос.
   * Сервер без такого потока отвечает 405: это нормально, и мы просто остаёмся без него.
   * При обрыве переподключаемся не больше MAX_STREAM_RETRIES раз подряд.
   */
  private async listen(): Promise<void> {
    let failures = 0;
    while (!this.closed && failures <= MAX_STREAM_RETRIES) {
      const ac = new AbortController();
      this.streamAc = ac;
      let gotData = false;
      try {
        const { Accept: _a, "Content-Type": _c, ...rest } = this.headers();
        const res = await fetch(this.url, { method: "GET", headers: { ...rest, Accept: "text/event-stream" }, signal: ac.signal, redirect: "error" });
        const type = (res.headers.get("content-type") ?? "").toLowerCase();
        if (res.status === 405 || res.status === 404 || res.status === 501 || !res.ok || !type.includes("text/event-stream")) {
          await res.body?.cancel();
          if (res.status === 405 || res.status === 501 || res.ok) return; // потока уведомлений у сервера нет
          throw new UpstreamError(`${this.name}: поток уведомлений: HTTP ${res.status}`);
        }
        const parser = new SseParser();
        const reader = res.body?.getReader();
        const decoder = new TextDecoder();
        while (reader) {
          const { done, value } = await reader.read();
          if (done) break;
          for (const ev of parser.feed(decoder.decode(value, { stream: true }))) {
            gotData = true;
            const msg = parseMessage(ev);
            if (!msg) continue;
            if (isRequest(msg)) void this.refuse(msg);
            else if (isNotification(msg) && msg.method === "notifications/tools/list_changed") this.opts.onToolsChanged?.();
          }
        }
      } catch (e) {
        if (this.closed) return;
        this.opts.onStderr?.(`[${this.name}] поток уведомлений прервался: ${e instanceof Error ? e.message : String(e)}`);
      }
      if (this.closed) return;
      failures = gotData ? 1 : failures + 1;
      if (failures > MAX_STREAM_RETRIES) {
        this.opts.onStderr?.(`[${this.name}] поток уведомлений отключён после ${MAX_STREAM_RETRIES} неудачных переподключений`);
        return;
      }
      await new Promise((r) => setTimeout(r, (this.opts.streamRetryMs ?? 1000) * failures));
    }
  }

  private async notify(msg: Message): Promise<void> {
    const ac = new AbortController();
    this.inflight.add(ac);
    const timer = setTimeout(() => ac.abort(), this.opts.timeoutMs);
    try {
      const res = await fetch(this.url, { method: "POST", headers: this.headers(), body: JSON.stringify(msg), signal: ac.signal, redirect: "error" });
      await res.body?.cancel();
    } catch {
      // уведомление без ответа: потеря не критична
    } finally {
      clearTimeout(timer);
      this.inflight.delete(ac);
    }
  }

  private async refuse(req: { id: string | number; method: string }): Promise<void> {
    this.opts.onRefusedRequest?.(req.method);
    await this.notify(errorResponse(req.id, req.method === "ping" ? ERR.internal : ERR.methodNotFound, "citadel: запрос сервера к клиенту отклонён"));
  }

  /** Разбирает одно сообщение из ответа синхронно: ответ на наш запрос возвращается сразу, серверные запросы отклоняются фоном (task). */
  private onMessage(text: string, id: number): { response?: Response; task?: Promise<void> } {
    const msg = parseMessage(text);
    if (!msg) return {};
    if (isResponse(msg)) return msg.id === id ? { response: msg } : {};
    if (isRequest(msg)) return { task: this.refuse(msg) };
    if (isNotification(msg) && msg.method === "notifications/tools/list_changed") this.opts.onToolsChanged?.();
    return {};
  }

  async request(method: string, params?: unknown, timeoutMs = this.opts.timeoutMs): Promise<Response> {
    if (!this.alive && method !== "initialize") throw new UpstreamError(`${this.name}: сервер не подключён`);
    const id = this.nextId++;
    const ac = new AbortController();
    this.inflight.add(ac);
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      ac.abort();
    }, timeoutMs);
    try {
      const body = JSON.stringify({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) });
      const res = await fetch(this.url, { method: "POST", headers: this.headers(), body, signal: ac.signal, redirect: "error" });
      if (method === "initialize") this.sessionId = res.headers.get("mcp-session-id") ?? undefined;
      if (res.status === 404 && this.sessionId) {
        this.ready = false;
        throw new UpstreamError(`${this.name}: сессия на сервере закрыта (HTTP 404), нужно переподключение`);
      }
      if (!res.ok) {
        await res.body?.cancel();
        throw new UpstreamError(`${this.name}: ${this.where} ответил HTTP ${res.status}`);
      }
      const type = (res.headers.get("content-type") ?? "").toLowerCase();
      const found = type.includes("text/event-stream") ? await this.readStream(res, id) : type.includes("application/json") ? await this.readJson(res, id) : undefined;
      if (!found) throw new UpstreamError(`${this.name}: нет ответа на ${method} (тип «${type || "?"}», в потоке нет ответа с нашим id)`);
      return found;
    } catch (e) {
      if (timedOut) throw new UpstreamError(`${this.name}: нет ответа на ${method} за ${timeoutMs} мс`);
      if (e instanceof UpstreamError) throw e;
      const cause = e instanceof Error && e.cause instanceof Error ? e.cause.message : "";
      throw new UpstreamError(`${this.name}: ${this.where}: ${e instanceof Error ? e.message : String(e)}${cause ? ` (${cause})` : ""}`);
    } finally {
      clearTimeout(timer);
      this.inflight.delete(ac);
    }
  }

  private async readJson(res: globalThis.Response, id: number): Promise<Response | undefined> {
    const text = await this.readCapped(res, (chunk) => chunk);
    const { response, task } = this.onMessage(text.join(""), id);
    await task;
    return response;
  }

  private async readStream(res: globalThis.Response, id: number): Promise<Response | undefined> {
    const parser = new SseParser();
    const tasks: Promise<void>[] = [];
    let found: Response | undefined;
    await this.readCapped(
      res,
      (chunk) => {
        for (const ev of parser.feed(chunk)) {
          const { response, task } = this.onMessage(ev, id);
          if (task) tasks.push(task);
          found ??= response;
        }
        return chunk;
      },
      () => found !== undefined, // ответ получен: остальное в потоке нам не нужно, соединение закрываем
    );
    await Promise.all(tasks);
    return found;
  }

  /** Читает тело по кускам с общим лимитом MAX_LINE_BYTES; stop() позволяет закончить чтение раньше. */
  private async readCapped(res: globalThis.Response, each: (chunk: string) => string, stop: () => boolean = () => false): Promise<string[]> {
    if (!res.body) return [];
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    const out: string[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_LINE_BYTES) {
        await reader.cancel();
        throw new UpstreamError(`${this.name}: ответ длиннее лимита ${MAX_LINE_BYTES} байт`);
      }
      out.push(each(decoder.decode(value, { stream: true })));
      if (stop()) {
        await reader.cancel();
        break;
      }
    }
    return out;
  }

  async close(): Promise<void> {
    if (this.closed) return;
    const wasReady = this.ready;
    this.closed = true;
    this.ready = false;
    this.streamAc?.abort();
    if (wasReady && this.sessionId) {
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), CLOSE_TIMEOUT_MS);
      try {
        const headers = { ...(this.spec.headers ?? {}), "Mcp-Session-Id": this.sessionId, "MCP-Protocol-Version": PROTOCOL_VERSION };
        const res = await fetch(this.url, { method: "DELETE", headers, signal: ac.signal, redirect: "error" });
        await res.body?.cancel();
      } catch {
        // сервер мог уже закрыть сессию
      } finally {
        clearTimeout(timer);
      }
    }
    for (const ac of this.inflight) ac.abort();
  }
}
