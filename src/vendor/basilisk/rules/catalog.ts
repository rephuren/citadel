// Копия из проекта basilisk (MIT), синхронизируется скриптом scripts/sync-basilisk.mjs. Правки вносите в basilisk.
import type { RuleInfo } from "../types.js";

const L = (n: string) => `OWASP LLM Top 10 (2025): ${n}`;

export const RULES: RuleInfo[] = [
  { id: "BSK001", title: "инъекция промпта в описании", severity: "high", owasp: L("LLM01 Prompt Injection"),
    fix: "Описание инструмента должно говорить, что он делает, а не что делать модели. Уберите скрытые указания и ссылки на другие инструменты." },
  { id: "BSK002", title: "невидимые символы", severity: "high", owasp: L("LLM01 Prompt Injection"),
    fix: "Уберите символы нулевой ширины, bidi-управление и Unicode-теги: пользователь их не видит, а модель читает." },
  { id: "BSK003", title: "ссылки и картинки в описании", severity: "medium", owasp: L("LLM02 Sensitive Information Disclosure"),
    fix: "Не размещайте во внешнем описании внешние URL: markdown-картинка с данными в адресе — канал утечки." },
  { id: "BSK004", title: "обращение к секретам и чувствительным файлам", severity: "high", owasp: L("LLM02 Sensitive Information Disclosure"),
    fix: "Описание не должно просить читать ключи, .env, конфиги клиента и системные файлы." },
  { id: "BSK005", title: "подмена и затенение инструментов", severity: "high", owasp: L("LLM03 Supply Chain"),
    fix: "Имена инструментов разных серверов не должны совпадать или быть похожими, а описания не должны управлять чужими инструментами." },
  { id: "BSK006", title: "опасная возможность без ограничений", severity: "high", owasp: L("LLM06 Excessive Agency"),
    fix: "Ограничьте параметры: enum, pattern, maxLength, список разрешённых путей и хостов, подтверждение пользователем." },
  { id: "BSK007", title: "слабая схема входа", severity: "low", owasp: L("LLM06 Excessive Agency"),
    fix: "Опишите inputSchema явно и закройте лишние поля через additionalProperties: false." },
  { id: "BSK008", title: "слишком длинное или обфусцированное описание", severity: "medium", owasp: L("LLM01 Prompt Injection"),
    fix: "Сократите описание. Длинный текст и закодированные блоки (base64, hex) скрывают содержимое от ревью." },
  { id: "BSK009", title: "непривязанный пакет в запуске сервера", severity: "medium", owasp: L("LLM03 Supply Chain"),
    fix: "Закрепите версию пакета (npx pkg@1.2.3) или хеш образа и не используйте автоустановку без проверки." },
  { id: "BSK010", title: "секрет прямо в конфиге", severity: "high", owasp: L("LLM02 Sensitive Information Disclosure"),
    fix: "Уберите ключ из файла, передавайте через переменную окружения или менеджер секретов и перевыпустите скомпрометированный." },
  { id: "BSK011", title: "небезопасный транспорт или удалённый сервер", severity: "medium", owasp: L("LLM03 Supply Chain"),
    fix: "Используйте HTTPS, и закрепляйте определения инструментов удалённого сервера (basilisk pin), потому что они могут измениться без вашего ведома." },
  { id: "BSK012", title: "опасный запуск (shell, контейнер, права)", severity: "high", owasp: L("LLM06 Excessive Agency"),
    fix: "Не запускайте серверы через sh -c с загрузкой из сети и не давайте контейнеру привилегии, docker.sock и корень файловой системы." },
  { id: "BSK020", title: "определение инструмента изменилось с момента закрепления", severity: "critical", owasp: L("LLM03 Supply Chain"),
    fix: "Проверьте изменение вручную. Если сервер не обновлялся осознанно, отключите его: это признак подмены определения (rug pull)." },
  { id: "BSK021", title: "новый инструмент после закрепления", severity: "medium", owasp: L("LLM03 Supply Chain"),
    fix: "Проверьте новый инструмент и закрепите заново (basilisk pin)." },
  { id: "BSK022", title: "инструмент пропал после закрепления", severity: "info", owasp: L("LLM03 Supply Chain"),
    fix: "Убедитесь, что удаление ожидаемо, и обновите закрепление." },
  { id: "BSK023", title: "конфигурация сервера изменилась с момента закрепления", severity: "high", owasp: L("LLM03 Supply Chain"),
    fix: "Сравните команду, аргументы и адрес с закреплёнными и убедитесь, что это ваша правка." },
];

export const RULE_BY_ID = new Map(RULES.map((r) => [r.id, r]));
