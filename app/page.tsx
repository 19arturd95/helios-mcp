export const dynamic = "force-static";

export default function Home() {
  return (
    <main style={{ fontFamily: "system-ui", maxWidth: "36rem", margin: "4rem auto", padding: "0 1rem" }}>
      <h1>Helios MCP</h1>
      <p>
        Prywatny zdalny serwer MCP dla osobistej bazy wiedzy Helios. Endpoint MCP:{" "}
        <code>/api/mcp</code> (wymaga logowania OAuth przez Google).
      </p>
      <p>Faza 1: tylko odczyt. Notatki pozostają wyłącznie na Google Drive.</p>
    </main>
  );
}
