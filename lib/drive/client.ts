/**
 * Klient adaptera Helios Drive (Google Apps Script).
 *
 * Buduje podpisaną kopertę HMAC i wysyła ją POST-em na URL Apps Script.
 * Nie zawiera żadnej logiki AI. Nie loguje treści notatek. Nie umieszcza
 * sekretów w rzucanych błędach.
 */

import { signPayload } from "../security/signing";
import type { AdapterOp, AdapterResponse } from "./types";

export class DriveAdapterError extends Error {
  constructor(
    message: string,
    public readonly code?: string,
  ) {
    super(message);
    this.name = "DriveAdapterError";
  }
}

export interface AdapterClientConfig {
  appsScriptUrl: string;
  appsScriptSecret: string;
  /** Wstrzykiwalny fetch (dla testów). Domyślnie globalny fetch. */
  fetchImpl?: typeof fetch;
  /** Limit czasu żądania w ms (domyślnie 20 s). */
  timeoutMs?: number;
}

/**
 * Wywołuje pojedynczą operację adaptera. Payload jest serializowany do
 * dokładnego ciągu JSON, który następnie jest podpisywany bajt w bajt.
 */
export async function callAdapter<T = unknown>(
  config: AdapterClientConfig,
  op: AdapterOp,
  args: Record<string, unknown> = {},
): Promise<T> {
  const fetchImpl = config.fetchImpl ?? fetch;
  const payload = JSON.stringify({ op, ...args });
  const envelope = await signPayload(config.appsScriptSecret, payload);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.timeoutMs ?? 20_000);

  let response: Response;
  try {
    response = await fetchImpl(config.appsScriptUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(envelope),
      signal: controller.signal,
    });
  } catch (err) {
    // Nie ujawniamy szczegółów sieci ani sekretów.
    throw new DriveAdapterError("Nie udało się połączyć z Helios Drive Adapter.", "network");
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    throw new DriveAdapterError(
      `Adapter zwrócił status HTTP ${response.status}.`,
      `http_${response.status}`,
    );
  }

  let body: AdapterResponse<T>;
  try {
    body = (await response.json()) as AdapterResponse<T>;
  } catch {
    throw new DriveAdapterError("Nieprawidłowa odpowiedź adaptera (nie-JSON).", "bad_json");
  }

  if (!body || typeof body !== "object" || !("ok" in body)) {
    throw new DriveAdapterError("Nieprawidłowy kształt odpowiedzi adaptera.", "bad_shape");
  }

  if (body.ok === false) {
    throw new DriveAdapterError(body.error || "Adapter zgłosił błąd.", body.code);
  }

  return body.result;
}
