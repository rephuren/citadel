/** Два способа подключить агента: напрямую к серверам (как делает обычный клиент) или через шлюз. */
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Config, ServerSpec } from "../src/config.js";
import { Gateway } from "../src/gateway.js";
import { Upstream, type UpstreamTool } from "../src/upstream.js";
import type { AgentTool, ToolClient } from "./agent.js";

export const serverScript = (name: string) => fileURLToPath(new URL(`../range/server_${name}.js`, import.meta.url));

export function specFor(name: string, env: Record<string, string>, untrusted: boolean): ServerSpec {
  return { command: process.execPath, args: [serverScript(name)], env, inheritEnv: false, trust: untrusted ? "untrusted" : "trusted" };
}

function textOf(result: unknown): { text: string; isError: boolean } {
  const r = (result ?? {}) as { content?: { text?: string }[]; isError?: boolean };
  return { text: (r.content ?? []).map((c) => c.text ?? "").join("\n"), isError: r.isError === true };
}

/** Клиент без шлюза: собирает инструменты всех серверов в один список по голым именам, при совпадении побеждает последний. */
export class DirectClient implements ToolClient {
  private owners = new Map<string, Upstream>();
  private tools = new Map<string, UpstreamTool>();
  private ups: Upstream[] = [];

  static async open(servers: Record<string, ServerSpec>): Promise<DirectClient> {
    const c = new DirectClient();
    for (const [name, spec] of Object.entries(servers)) {
      const up = new Upstream(name, spec, { timeoutMs: 10_000 });
      await up.start();
      c.ups.push(up);
    }
    return c;
  }

  async listTools(): Promise<AgentTool[]> {
    this.owners.clear();
    this.tools.clear();
    for (const up of this.ups) {
      for (const t of await up.listTools()) {
        this.owners.set(t.name, up);
        this.tools.set(t.name, t);
      }
    }
    return [...this.tools.values()].map((t) => ({ name: t.name, description: String(t.description ?? "") }));
  }

  async callTool(name: string, args: Record<string, unknown>) {
    const up = this.owners.get(name);
    if (!up) return { text: `неизвестный инструмент ${name}`, isError: true };
    try {
      return textOf(await up.callTool(name, args, 10_000));
    } catch (e) {
      return { text: e instanceof Error ? e.message : String(e), isError: true };
    }
  }

  async close(): Promise<void> {
    await Promise.all(this.ups.map((u) => u.close()));
  }
}

export class GatewayClient implements ToolClient {
  constructor(readonly gateway: Gateway) {}

  static async open(config: Config): Promise<GatewayClient> {
    const gw = new Gateway({ config, emit: () => {}, log: () => {} });
    await gw.start();
    return new GatewayClient(gw);
  }

  async listTools(): Promise<AgentTool[]> {
    await this.gateway.idle(); // клиент получает tools/list_changed только после того, как шлюз закончил обновление
    return [...this.gateway.catalog.values()].filter((e) => !e.quarantine).map((e) => ({ name: e.qualified, description: String(e.tool.description ?? "") }));
  }

  async callTool(name: string, args: Record<string, unknown>) {
    return textOf(await this.gateway.call(name, args));
  }

  async close(): Promise<void> {
    await this.gateway.stop();
  }
}

export const sandboxPaths = (dir: string) => ({ root: join(dir, "files", "public"), log: join(dir, "effects.jsonl") });
