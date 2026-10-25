/** Минимальный MCP-сервер по stdio для полигона. Намеренно простой и намеренно небезопасный: это учебная мишень,
 *  а не образец. Ничего не выполняет и не ходит в сеть, а все «эффекты» пишет в файл RANGE_LOG для проверки результатов. */
import { appendFileSync } from "node:fs";
import { LineReader, type Message, encode, errorResponse, isRequest, okResponse, parseMessage } from "../src/jsonrpc.js";

export interface ToolDef {
  name: string;
  description: string;
  inputSchema: unknown;
  handler: (args: Record<string, unknown>) => string | Promise<string>;
}

export function effect(server: string, kind: string, detail: Record<string, unknown>): void {
  const file = process.env["RANGE_LOG"];
  if (!file) return;
  appendFileSync(file, JSON.stringify({ server, kind, ...detail }) + "\n");
}

export interface ServeOptions {
  /** вызывается при каждом tools/call до обработчика; нужен серверу с «подменой определений» */
  onCall?: (tool: string, notifyListChanged: () => void) => void;
}

export function serve(server: string, tools: () => ToolDef[], options: ServeOptions = {}): void {
  const send = (m: Message) => process.stdout.write(encode(m));
  const reader = new LineReader();
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => {
    for (const line of reader.feed(chunk)) void handle(line);
  });
  process.stdin.on("end", () => process.exit(0));

  async function handle(line: string): Promise<void> {
    const msg = parseMessage(line);
    if (!msg || !isRequest(msg)) return;
    const p = (typeof msg.params === "object" && msg.params !== null ? msg.params : {}) as Record<string, unknown>;
    switch (msg.method) {
      case "initialize":
        send(okResponse(msg.id, { protocolVersion: typeof p["protocolVersion"] === "string" ? p["protocolVersion"] : "2025-06-18", capabilities: { tools: { listChanged: true } }, serverInfo: { name: server, version: "0.0.1" } }));
        return;
      case "ping":
        send(okResponse(msg.id, {}));
        return;
      case "tools/list":
        send(okResponse(msg.id, { tools: tools().map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) }));
        return;
      case "tools/call": {
        const name = String(p["name"]);
        const def = tools().find((t) => t.name === name);
        if (!def) {
          send(errorResponse(msg.id, -32602, `неизвестный инструмент ${name}`));
          return;
        }
        options.onCall?.(name, () => send({ jsonrpc: "2.0", method: "notifications/tools/list_changed" }));
        try {
          const text = await def.handler((typeof p["arguments"] === "object" && p["arguments"] !== null ? p["arguments"] : {}) as Record<string, unknown>);
          send(okResponse(msg.id, { content: [{ type: "text", text }] }));
        } catch (e) {
          send(okResponse(msg.id, { content: [{ type: "text", text: e instanceof Error ? e.message : String(e) }], isError: true }));
        }
        return;
      }
      default:
        send(errorResponse(msg.id, -32601, "метод не поддерживается"));
    }
  }
}
