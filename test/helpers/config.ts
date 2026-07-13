import type { HeliosConfig } from "../../lib/config.js";

export function testConfig(overrides: Partial<HeliosConfig> = {}): HeliosConfig {
  return {
    allowedEmail: "me@example.com",
    baseUrl: "https://helios.example.com",
    appsScriptUrl: "https://script.google.com/macros/s/AKfycb/exec",
    appsScriptSecret: "s".repeat(32),
    authSecret: "a".repeat(40),
    googleClientId: "client-id.apps.googleusercontent.com",
    googleClientSecret: "google-client-secret-value",
    writeEnabled: false,
    ...overrides,
  };
}
