import { chromium, expect } from "@playwright/test";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
const cwd = fileURLToPath(new URL("../../", import.meta.url));
const directory = await mkdtemp("/tmp/acgs-document-recovery-");
const db = directory + "/recovery.db";
const url = "http://127.0.0.1:8766";
let server, worker;
function savedReview() {
  const result = spawnSync("python3", ["-c",
    "import sqlite3,json,sys;d=sqlite3.connect(sys.argv[1]);d.row_factory=sqlite3.Row;print(json.dumps(dict(d.execute('SELECT * FROM reviews ORDER BY rowid LIMIT 1').fetchone())))",
    db], {cwd,encoding:"utf8"});
  if (result.status !== 0) throw new Error(result.stderr);
  return JSON.parse(result.stdout);
}
async function focusWithKeyboard(page, locator) {
  for (let count=0; count<80; count++) {
    if (await locator.evaluate(node => node === document.activeElement)) return;
    await page.keyboard.press("Tab");
  }
  throw new Error("Keyboard focus did not reach the named control");
}
async function startServer() {
  server = spawn("python3", ["-m","document_workspace.server","--db",db,"--port","8766"], {cwd,stdio:["ignore","pipe","pipe"]});
  let output = "";
  return new Promise((resolve,reject) => {
    const deadline = setTimeout(() => reject(new Error("Server start timed out")), 10000);
    server.stdout.on("data", chunk => {output += chunk.toString();});
    server.stderr.on("data", chunk => {
      if (chunk.toString().includes("Uvicorn running")) {
        const match = output.match(/Ephemeral session token \(paste in local UI\): (\S+)/);
        clearTimeout(deadline);
        match ? resolve(match[1]) : reject(new Error("No local bootstrap token"));
      }
    });
    server.once("error",reject);
  });
}
async function stop(child) {
  if (child && child.exitCode === null) {
    const done = once(child,"exit"); child.kill("SIGTERM"); await done;
  }
}
const browser = await chromium.launch({headless:true});
try {
  let token = await startServer();
  const context = await browser.newContext();
  let page = await context.newPage();
  const launched = [];
  const watch = p => p.on("request", r => {
    if (r.method()==="POST" && new URL(r.url()).pathname==="/api/workspaces/local/runs") launched.push(r.url());
  });
  watch(page);
  await page.goto(url);
  await page.getByLabel("Session token",{exact:true}).fill(token);
  await page.getByRole("button",{name:"Open session",exact:true}).click();
  const prior = "Inspect the airlock.\nRecord Café intake.\n";
  const current = "Inspect the airlock twice.\nRecord Café intake.\n";
  await page.getByLabel("Prior procedure",{exact:true}).fill(prior);
  await page.getByLabel("Current procedure",{exact:true}).fill(current);
  await page.getByRole("button",{name:"Save and compare",exact:true}).click();
  await expect(page.getByText("queued",{exact:true})).toBeVisible();
  const taskUrl = page.url();
  await page.close(); // no worker yet: closed browser cannot cancel the admission
  worker = spawn("python3",["-m","document_workspace.worker","--db",db,"--once"],{cwd,stdio:"ignore"});
  const [exit] = await once(worker,"exit");
  if (exit !== 0) throw new Error("Separate worker failed");
  page = await context.newPage(); watch(page);
  await page.goto(taskUrl);
  await expect(page.getByRole("button",{name:"Approve draft",exact:true})).toBeEnabled();
  await expect(page.getByLabel("Prior procedure",{exact:true})).toHaveValue(prior);
  await expect(page.getByLabel("Current procedure",{exact:true})).toHaveValue(current);
  await stop(server); token = await startServer();
  await expect(page.getByLabel("Session token",{exact:true})).toBeVisible({timeout:5000});
  if (page.url() !== taskUrl) throw new Error("Reauthentication lost the task URL");
  await page.getByLabel("Session token",{exact:true}).fill(token);
  await page.getByRole("button",{name:"Open session",exact:true}).click();
  await expect(page.getByRole("button",{name:"Approve draft",exact:true})).toBeEnabled();
  await page.getByLabel("Review feedback",{exact:true}).fill("Please clarify the airlock instruction.");
  await page.getByRole("button",{name:"Request changes",exact:true}).click();
  await expect(page.getByText("request changes",{exact:true})).toBeVisible();
  const savedDigest = await page.locator("p.hash code").first().innerText();
  const exactReviewBeforeRestart = savedReview();
  const savedFeedback = "Please clarify the airlock instruction.";
  await stop(server); token = await startServer();
  worker = spawn("python3",["-m","document_workspace.worker","--db",db,"--once"],{cwd,stdio:"ignore"});
  await once(worker,"exit");
  await expect(page.getByLabel("Session token",{exact:true})).toBeVisible();
  await page.getByLabel("Session token",{exact:true}).fill(token);
  await page.getByRole("button",{name:"Open session",exact:true}).click();
  await expect(page.getByText("request changes",{exact:true})).toBeVisible();
  await expect(page.locator("p.hash code").first()).toHaveText(savedDigest);
  await expect(page.getByText("Saved review:",{exact:false})).toContainText(savedFeedback);
  if (JSON.stringify(savedReview()) !== JSON.stringify(exactReviewBeforeRestart))
    throw new Error("Persisted review identity/content changed across API and worker restart");
  await page.getByRole("button",{name:"Create a new comparison",exact:true}).click();
  await page.getByRole("button",{name:"Save and compare",exact:true}).click();
  await expect(page.getByText("queued",{exact:true})).toBeVisible();
  await page.getByRole("button",{name:"Request cancellation",exact:true}).click();
  await expect(page.getByText("requested",{exact:true})).toBeVisible();
  worker = spawn("python3",["-m","document_workspace.worker","--db",db,"--once"],{cwd,stdio:"ignore"});
  await once(worker,"exit");
  await expect(page.getByText("acknowledged",{exact:true})).toBeVisible();
  await expect(page.getByText("cancelled",{exact:true})).toBeVisible();
  if (launched.length !== 2) throw new Error("Remount/reconnect launched unexpected work");
  await page.goto(url);
  await focusWithKeyboard(page, page.getByLabel("Prior procedure",{exact:true}));
  await page.keyboard.press("Control+A"); await page.keyboard.insertText("New procedure A.");
  await focusWithKeyboard(page, page.getByLabel("Current procedure",{exact:true}));
  await page.keyboard.press("Control+A"); await page.keyboard.insertText("New procedure B.");
  await focusWithKeyboard(page, page.getByRole("button",{name:"Save and compare",exact:true}));
  await page.keyboard.press("Enter");
  await expect(page.getByText("queued",{exact:true})).toBeVisible();
  if (launched.length !== 3) throw new Error("Homepage failed to admit explicit new comparison");
  worker = spawn("python3",["-m","document_workspace.worker","--db",db,"--once"],{cwd,stdio:"ignore"});
  await once(worker,"exit");
  await expect(page.getByRole("button",{name:"Approve draft",exact:true})).toBeEnabled();
  await focusWithKeyboard(page, page.getByRole("link",{name:"Open exact source span",exact:true}).first());
  const sourcePage = context.waitForEvent("page");
  await page.keyboard.press("Enter"); const opened = await sourcePage;
  await expect(opened.locator("body")).toHaveText("New procedure A.");
  await opened.close();
  await focusWithKeyboard(page, page.getByLabel("Review feedback",{exact:true}));
  await page.keyboard.insertText("Keyboard-only fixture review of exact source evidence.");
  await focusWithKeyboard(page, page.getByRole("button",{name:"Approve draft",exact:true}));
  await page.keyboard.press("Enter");
  await expect(page.getByText("approve",{exact:true})).toBeVisible();
  await writeFile("../../../evidence/browser-recovery-result.json",JSON.stringify({
    result:"pass",checks:["browser closed before worker execution","separate worker saves draft",
      "saved non-default sources restored","mounted API restart exposes reauthentication",
      "reauthentication keeps run identity","request-changes feedback saved",
      "explicit replacement admission","cancellation requested then acknowledged",
      "homepage navigation allows a new acknowledged launch identity"],
    strengthenedChecks:["saved review and identical digest survive API and worker restart",
      "keyboard-only source entry, admission, source-span inspection, feedback and approval"],
    explicitLaunches:3,unexpectedLaunches:0
  },null,2));
  console.log("PASS: browser closure, worker execution, mounted API restart, feedback and cancellation recovery");
} finally {await browser.close(); await stop(server); await stop(worker); await rm(directory,{recursive:true,force:true});}
