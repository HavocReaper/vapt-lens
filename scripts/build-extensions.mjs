#!/usr/bin/env node
/**
 * Builds loadable extension packages from extension/ source.
 * Chrome and Firefox share all source files but use different manifests.
 */
import { cp, mkdir, readFile, rm, writeFile, access } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(root, "extension");

const targets = [
  { name: "chrome", manifest: "manifest.chrome.json" },
  { name: "firefox", manifest: "manifest.firefox.json" },
];

const required = [
  "background.js",
  "content.js",
  "content.css",
  "panel.html",
  "panel.css",
  "panel.js",
  "src/core/scanner.js",
  "src/core/analyzer.js",
  "src/core/checks.js",
  "src/core/messages.js",
  "icons/icon.svg",
];

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function build() {
  const missing = [];
  for (const file of [...required, ...targets.map((t) => t.manifest)]) {
    if (!(await exists(join(source, file)))) missing.push(file);
  }
  if (missing.length) {
    console.error("Missing source files:\n  " + missing.join("\n  "));
    process.exitCode = 1;
    return;
  }

  for (const target of targets) {
    const dest = join(root, "dist", target.name);
    await rm(dest, { recursive: true, force: true });
    await mkdir(dest, { recursive: true });
    await cp(source, dest, { recursive: true });
    // Tests are not part of the loadable package.
    await rm(join(dest, "test"), { recursive: true, force: true });

    // Remove alternate manifests so only the correct one is shipped.
    for (const other of targets) {
      if (other.name !== target.name) {
        await rm(join(dest, other.manifest), { force: true });
      }
    }

    const manifestText = await readFile(join(dest, target.manifest), "utf8");
    await writeFile(join(dest, "manifest.json"), manifestText);
    await rm(join(dest, target.manifest));

    console.log(`Built dist/${target.name}/`);
  }
}

await build();
