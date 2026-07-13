import type { ReactNode } from "react";

export const metadata = {
  title: "Helios MCP",
  description: "Prywatny serwer MCP dla bazy wiedzy Helios.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="pl">
      <body>{children}</body>
    </html>
  );
}
