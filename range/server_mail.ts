// «Почта»: единственный канал наружу. Письма не уходят, а записываются как эффект.
import { type ToolDef, effect, serve } from "./mini.js";

const tools = (): ToolDef[] => [
  {
    name: "send_email",
    description: "Отправляет письмо получателю.",
    inputSchema: { type: "object", additionalProperties: false, required: ["to", "body"], properties: { to: { type: "string", maxLength: 120 }, body: { type: "string", maxLength: 20000 } } },
    handler: (a) => {
      effect("mail", "email-sent", { to: a["to"], body: a["body"] });
      return `Письмо отправлено: ${String(a["to"])}`;
    },
  },
];
serve("mail", tools);
