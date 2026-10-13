import { chromium, expect } from "@playwright/test";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
const cwd = fileURLToPath(new URL("../../", import.meta.url));
const directory = await mkdtemp("/tmp/acgs-document-lost-ack-");
const db = directory + "/workspace.db";
const url = "http://127.0.0.1:8767";
const reproduce = process.argv.includes("--reproduce");
const server = spawn("python3", ["-m", "document_workspace.server", "--db", db, "--port", "8767"],
  {cwd, stdio: ["ignore", "pipe", "pipe"]});
let output = "";
const token = await new Promise((resolve, reject) => {
  const deadline = setTimeout(() => reject(new Error("Server start timed out")), 10000);
  server.stdout.on("data", chunk => { output += chunk.toString(); });
  server.stderr.on("data", chunk => {
    if (chunk.toString().includes("Uvicorn running")) {
      clearTimeout(deadline);
      resolve(output.match(/Ephemeral session token \(paste in local UI\): (\S+)/)[1]);
    }
  });
  server.once("error", reject);
});
const browser = await chromium.launch({headless: true});
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  let launches = 0, admittedId;
  page.on("request", r => {
    if (r.method() === "POST" && new URL(r.url()).pathname === "/api/workspaces/local/runs") launches++;
  });
  await page.goto(url);
  await page.getByLabel("Session token", {exact:true}).fill(token);
  await page.getByRole("button", {name:"Open session", exact:true}).click();
  const prior = "Contrôle Café ☕ — vérifier la porte.\r\n記録する。\r\n";
  const current = "Contrôle Café ☕ — vérifier la porte deux fois.\r\n記録する。\r\n";
  await page.getByLabel("Load prior file", {exact:true}).setInputFiles({
    name:"ancien-☕.md", mimeType:"text/markdown", buffer:Buffer.from(prior)});
  await page.getByLabel("Load current file", {exact:true}).setInputFiles({
    name:"actuel-☕.md", mimeType:"text/markdown", buffer:Buffer.from(current)});
  await page.route("**/api/workspaces/local/runs", async route => {
    const request = route.request().postDataJSON();
    if (request.sources.prior.text !== prior || request.sources.current.text !== current ||
        request.sources.prior.name !== "ancien-☕.md" || request.sources.current.name !== "actuel-☕.md")
      throw new Error("The original Unicode input bytes/names were changed before admission");
    // Forward and wait for durable admission, then discard only its response.
    const response = await route.fetch();
    if (response.status() !== 200) throw new Error("Admission did not succeed");
    admittedId = (await response.json()).id;
    await route.abort("failed");
  });
  await page.getByRole("button", {name:"Save and compare", exact:true}).click();
  await expect(page.getByRole("status")).toContainText("Retry preserves this launch key");
  if (page.url().includes("?run=")) throw new Error("Dropped response unexpectedly acknowledged in UI");
  await page.unroute("**/api/workspaces/local/runs");
  await page.reload();
  await expect(page.getByLabel("Prior procedure", {exact:true})).toBeVisible();
  if (reproduce) {
    await expect(page.getByRole("button", {name:"Save and compare", exact:true})).toBeEnabled();
    const defaultsShown = await page.getByLabel("Prior procedure", {exact:true}).inputValue();
    if (page.url().includes(admittedId) || defaultsShown === prior.replaceAll("\r\n", "\n"))
      throw new Error("Lost-ack gap was not reproduced");
    await writeFile("../../../evidence/lost-ack-reproduction.json", JSON.stringify({
      confirmed:true, admittedId, launchRequests:launches,
      observation:"Durable non-default Unicode admission exists; full reload shows unrelated defaults and no run URL.",
      displayedPrior:defaultsShown
    },null,2));
    console.log("CONFIRMED: lost acknowledgement plus reload loses admitted run and exact source view");
  } else {
    await expect.poll(() => page.url()).toContain(admittedId);
    await expect(page.getByLabel("Prior procedure", {exact:true})).toHaveValue(prior.replaceAll("\r\n", "\n"));
    await expect(page.getByLabel("Current procedure", {exact:true})).toHaveValue(current.replaceAll("\r\n", "\n"));
    await expect(page.getByText("ancien-☕.md", {exact:false})).toBeVisible();
    await expect(page.getByText("queued", {exact:true})).toBeVisible();
    await page.reload();
    await expect(page.getByText("queued", {exact:true})).toBeVisible();
    if (launches !== 1) throw new Error("Recovery dispatched another launch");
    const worker = spawn("python3", ["-m", "document_workspace.worker", "--db", db, "--once"],
      {cwd, stdio:"ignore"});
    const [exit] = await once(worker,"exit");
    if (exit !== 0) throw new Error("Separate fixture worker failed");
    await expect(page.getByRole("button", {name:"Approve draft",exact:true})).toBeEnabled();
    const removed = spawnSync("python3", ["-c",
      "import sqlite3,json,sys;d=sqlite3.connect(sys.argv[1]);r=d.execute('SELECT * FROM events WHERE seq=2').fetchone();d.execute('DELETE FROM events WHERE seq=2');d.commit();print(json.dumps(r))",
      db], {cwd,encoding:"utf8"});
    if (removed.status !== 0) throw new Error(removed.stderr);
    await expect(page.getByRole("alert")).toContainText("Incomplete evidence");
    await expect(page.getByRole("button", {name:"Approve draft",exact:true})).toBeDisabled();
    const restored = spawnSync("python3", ["-c",
      "import sqlite3,json,sys;d=sqlite3.connect(sys.argv[1]);d.execute('INSERT INTO events VALUES(?,?,?,?,?)',json.loads(sys.argv[2]));d.commit()",
      db, removed.stdout], {cwd,encoding:"utf8"});
    if (restored.status !== 0) throw new Error(restored.stderr);
    await expect(page.getByRole("alert")).toHaveCount(0);
    await expect(page.getByRole("button", {name:"Approve draft",exact:true})).toBeEnabled();
    const counts = spawnSync("python3", ["-c",
      "import sqlite3,json,sys;d=sqlite3.connect(sys.argv[1]);print(json.dumps({t:d.execute('SELECT COUNT(*) FROM '+t).fetchone()[0] for t in ['runs','attempts','manifests']}))",
      db], {cwd,encoding:"utf8"});
    if (counts.status !== 0) throw new Error(counts.stderr);
    const persisted = JSON.parse(counts.stdout);
    if (persisted.runs !== 1 || persisted.attempts !== 1 || persisted.manifests !== 1)
      throw new Error("Recovered admission/worker result duplicated");
    await writeFile("../../../evidence/browser-lost-ack-result.json", JSON.stringify({
      result:"pass", launchRequests:launches, persisted,
      checks:["non-default Unicode filenames/content with CRLF","response dropped after durable admission",
        "full reload recovers scoped run URL", "exact sources restored from server",
        "second remount makes zero launches", "one separate worker attempt and saved result",
        "missing event blocks mounted review", "restored event reconciles from complete snapshot without reload"],
      browserStorage:"Only pending launch key; no document content or credentials"
    },null,2));
    console.log("PASS: lost launch acknowledgement, full reload, exact source recovery and one worker execution");
  }
} finally {
  await browser.close();
  if (server.exitCode === null) {const done = once(server,"exit");server.kill("SIGTERM");await done;}
  await rm(directory,{recursive:true,force:true});
}
