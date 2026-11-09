// Builds publishable package dirs under npm/dist from compiled binaries.
// Usage: node npm/stage.mjs <version> <binaries-dir>
// <binaries-dir>/<rust-target>/code-scry[.exe] for each platform in platforms.json.
// Platforms whose binary is missing are skipped and left out of optionalDependencies.
import { cpSync, chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const [version, binDir] = process.argv.slice(2);
if (!version || !binDir) {
  console.error("usage: node npm/stage.mjs <version> <binaries-dir>");
  process.exit(2);
}

const platforms = JSON.parse(readFileSync(join(here, "platforms.json"), "utf8"));
const main = JSON.parse(readFileSync(join(here, "code-scry/package.json"), "utf8"));
const dist = join(here, "dist");
rmSync(dist, { recursive: true, force: true });

main.version = version;
main.optionalDependencies = {};
for (const p of platforms) {
  const exe = p.os === "win32" ? "code-scry.exe" : "code-scry";
  const src = join(binDir, p.target, exe);
  if (!existsSync(src)) {
    console.warn(`skip ${p.pkg}: ${src} not found`);
    continue;
  }
  const out = join(dist, p.pkg);
  mkdirSync(join(out, "bin"), { recursive: true });
  cpSync(src, join(out, "bin", exe));
  chmodSync(join(out, "bin", exe), 0o755);
  cpSync(join(root, "LICENSE"), join(out, "LICENSE"));
  cpSync(join(root, "rust/model/LICENSE"), join(out, "MODEL-LICENSE"));
  writeFileSync(
    join(out, "package.json"),
    JSON.stringify(
      {
        name: p.pkg,
        version,
        description: `code-scry binary for ${p.os}-${p.cpu}`,
        license: "MIT",
        repository: main.repository,
        os: [p.os],
        cpu: [p.cpu],
        files: ["bin", "LICENSE", "MODEL-LICENSE"],
      },
      null,
      2
    ) + "\n"
  );
  main.optionalDependencies[p.pkg] = version;
  console.log(`staged ${p.pkg}`);
}

const mainOut = join(dist, "code-scry");
cpSync(join(here, "code-scry"), mainOut, { recursive: true });
cpSync(join(root, "README.md"), join(mainOut, "README.md"));
cpSync(join(root, "LICENSE"), join(mainOut, "LICENSE"));
writeFileSync(join(mainOut, "package.json"), JSON.stringify(main, null, 2) + "\n");
console.log(`staged code-scry ${version} with ${Object.keys(main.optionalDependencies).length} platforms`);
