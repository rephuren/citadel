/** JSON-RPC 2.0 для MCP по stdio: сообщения идут по одному в строке. Здесь только разбор, кодирование и лимиты. */

export type Id = string | number | null;

export interface RpcError {
  code: number;
  message: string;
  data?: unknown;
}
export interface Request {
  jsonrpc: "2.0";
  id: string | number;
  method: string;
  params?: unknown;
}
export interface Notification {
  jsonrpc: "2.0";
  method: string;
  params?: unknown;
}
export interface Response {
  jsonrpc: "2.0";
  id: Id;
  result?: unknown;
  error?: RpcError;
}
export type Message = Request | Notification | Response;

export const ERR = {
  parse: -32700,
  invalidRequest: -32600,
  methodNotFound: -32601,
  invalidParams: -32602,
  internal: -32603,
  /** запрет политикой, подтверждение, лимит: коды приложения */
  denied: -32001,
  needsApproval: -32002,
  upstream: -32003,
} as const;

export const MAX_LINE_BYTES = 8 * 1024 * 1024;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export const isResponse = (m: Message): m is Response => !("method" in m);
export const isRequest = (m: Message): m is Request => "method" in m && "id" in m && (m as Request).id !== undefined;
export const isNotification = (m: Message): m is Notification => "method" in m && !("id" in m);

/** Разбирает одну строку. Возвращает null, если это не корректное сообщение JSON-RPC 2.0. */
export function parseMessage(line: string): Message | null {
  let data: unknown;
  try {
    data = JSON.parse(line);
  } catch {
    return null;
  }
  if (!isRecord(data) || data["jsonrpc"] !== "2.0") return null;
  if (typeof data["method"] === "string") {
    const id = data["id"];
    if (id !== undefined && typeof id !== "string" && typeof id !== "number") return null;
    return data as unknown as Message;
  }
  if ("id" in data && ("result" in data || "error" in data)) return data as unknown as Response;
  return null;
}

export function encode(message: Message): string {
  return JSON.stringify(message) + "\n";
}

export function errorResponse(id: Id, code: number, message: string, data?: unknown): Response {
  return { jsonrpc: "2.0", id, error: data === undefined ? { code, message } : { code, message, data } };
}

export function okResponse(id: Id, result: unknown): Response {
  return { jsonrpc: "2.0", id, result };
}

/** Собирает строки из потока кусков. Слишком длинная строка отбрасывается целиком, без накопления в памяти. */
export class LineReader {
  private buf = "";
  private dropping = false;
  constructor(private readonly maxBytes = MAX_LINE_BYTES, private readonly onOverflow: () => void = () => {}) {}

  feed(chunk: string): string[] {
    const out: string[] = [];
    let rest = chunk;
    while (rest.length) {
      const nl = rest.indexOf("\n");
      const part = nl === -1 ? rest : rest.slice(0, nl);
      if (!this.dropping) {
        this.buf += part;
        if (this.buf.length > this.maxBytes) {
          this.buf = "";
          this.dropping = true;
          this.onOverflow();
        }
      }
      if (nl === -1) break;
      if (!this.dropping && this.buf.trim()) out.push(this.buf);
      this.buf = "";
      this.dropping = false;
      rest = rest.slice(nl + 1);
    }
    return out;
  }
}
