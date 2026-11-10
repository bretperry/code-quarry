#!/usr/bin/env node
// Runs the prebuilt binary from the platform package npm installed alongside this one.
"use strict";
const { spawnSync } = require("node:child_process");
const path = require("node:path");

// npm blocked the name code-scry-win32-x64 as spam, so Windows uses "windows".
const os = process.platform === "win32" ? "windows" : process.platform;
const pkg = `code-quarry-${os}-${process.arch}`;
const exe = process.platform === "win32" ? "quarry.exe" : "quarry";

let bin;
try {
  bin = path.join(path.dirname(require.resolve(`${pkg}/package.json`)), "bin", exe);
} catch {
  console.error(
    `quarry: no prebuilt binary for ${process.platform}-${process.arch} (package ${pkg} is missing).\n` +
      "If your platform is supported, reinstall without --omit=optional / --no-optional.\n" +
      "Otherwise build from source: https://github.com/bretperry/code-scry"
  );
  process.exit(1);
}

const r = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (r.error) {
  console.error(`quarry: failed to run ${bin}: ${r.error.message}`);
  process.exit(1);
}
if (r.signal) process.kill(process.pid, r.signal);
process.exit(r.status ?? 1);
