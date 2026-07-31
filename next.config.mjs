/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Helios MCP nie serwuje UI ani nie przechowuje danych — to wyłącznie warstwa API.
  // Notatki żyją tylko na Google Drive; system plików Vercela nie jest używany jako magazyn.
};

export default nextConfig;
