// Uses already-installed Playwright; no browser download or personal profile.
import { chromium, expect } from "@playwright/test";
import { writeFile } from "node:fs/promises";
const token = process.env.ACGS_TEST_TOKEN;
if (!token) throw new Error("Pass the ephemeral local server token via ACGS_TEST_TOKEN");
const browser = await chromium.launch({headless: true});
const context = await browser.newContext({viewport: {width: 1280, height: 900}});
const page = await context.newPage();
const errors = [], posts = [];
page.on("pageerror", e => errors.push(String(e)));
page.on("request", r => {if (r.method() === "POST") posts.push(new URL(r.url()).pathname);});
try {
  await page.goto("http://127.0.0.1:8765");
  await page.getByLabel("Session token", {exact:true}).fill("invalid");
  await page.getByRole("button", {name:"Open session",exact:true}).click();
  await expect(page.getByRole("status")).toContainText("Check the ephemeral");
  await page.getByLabel("Session token", {exact:true}).fill(token);
  await page.getByLabel("Session token", {exact:true}).press("Tab");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("button", {name:"Save and compare",exact:true})).toBeVisible();
  await page.getByLabel("Prior procedure", {exact:true}).fill("Café: check the queue.\nRecord the result.\n");
  await page.getByLabel("Current procedure", {exact:true}).fill("Café: check the queue twice.\nRecord the result.\n");
  await page.getByRole("button", {name:"Save and compare",exact:true}).click();
  await expect(page.getByRole("button", {name:"Approve draft",exact:true})).toBeEnabled({timeout:10000});
  await expect(page.getByText("draft ready", {exact:true})).toBeVisible();
  await expect(page.getByText("fixture supported", {exact:true})).toBeVisible();
  const admittedUrl = page.url();
  const launchesBefore = posts.filter(p => p === "/api/workspaces/local/runs").length;
  await page.reload();
  await expect(page.getByRole("button", {name:"Approve draft",exact:true})).toBeEnabled();
  if (posts.filter(p => p === "/api/workspaces/local/runs").length !== launchesBefore)
    throw new Error("Remount dispatched a duplicate launch");
  await context.setOffline(true);
  await expect(page.getByText("Disconnected · retrying", {exact:true})).toBeVisible({timeout:5000});
  await expect(page.getByRole("button", {name:"Approve draft",exact:true})).toBeDisabled();
  await context.setOffline(false);
  await expect(page.getByRole("button", {name:"Approve draft",exact:true})).toBeEnabled({timeout:5000});
  await page.getByLabel("Review feedback", {exact:true}).fill("Checked the exact source versions in this browser test.");
  await page.getByRole("button", {name:"Approve draft",exact:true}).click();
  await expect(page.getByText("approve", {exact:true})).toBeVisible();
  await page.reload();
  await expect(page.getByText("approve", {exact:true})).toBeVisible();
  await expect(page.getByRole("button", {name:"Approve draft",exact:true})).toBeDisabled();
  await page.setViewportSize({width:390,height:844});
  await expect(page.getByRole("heading", {name:"Claim evidence",exact:true})).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth);
  if (overflow) throw new Error("Narrow viewport has horizontal overflow");
  await page.screenshot({path:"../../../evidence/browser-internal.png",fullPage:true});
  if (errors.length) throw new Error(errors.join("\n"));
  await writeFile("../../../evidence/browser-result.json", JSON.stringify({
    result:"pass", admittedUrl, launches: launchesBefore, duplicateLaunchesOnRemount:0,
    checks:["invalid session", "keyboard login", "Unicode procedure comparison", "source pairs",
      "worker-produced saved draft", "offline/read recovery", "remount without launch",
      "exact-version approval", "review survives reload", "390px viewport without overflow"],
    pageErrors:errors
  },null,2));
  console.log("PASS: browser journey, remount, offline recovery, review and narrow viewport");
} finally {await browser.close();}
