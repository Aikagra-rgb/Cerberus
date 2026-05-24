import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
const port = Number(process.env.PORT || 5173);

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
};

function resolvePath(urlPath) {
  const cleanPath = normalize(decodeURIComponent(urlPath.split("?")[0])).replace(/^(\.\.[/\\])+/, "");
  const requested = join(root, cleanPath === "/" ? "index.html" : cleanPath);
  if (!requested.startsWith(root)) {
    return join(root, "index.html");
  }
  if (!existsSync(requested) || statSync(requested).isDirectory()) {
    return join(root, "index.html");
  }
  return requested;
}

createServer((request, response) => {
  const filePath = resolvePath(request.url || "/");
  response.writeHead(200, {
    "Content-Type": contentTypes[extname(filePath)] || "application/octet-stream",
    "Cache-Control": "no-store",
  });
  createReadStream(filePath).pipe(response);
}).listen(port, "127.0.0.1", () => {
  console.log(`LogSentry frontend listening on https://127.0.0.1:${port}`);
});
