#!/usr/bin/env node

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const serverRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const appRoot = resolve(process.argv[2] ?? "../RN-App");
const sourceDir = resolve(appRoot, "i18n/seed");
const targetDir = resolve(serverRoot, "internal/store/i18n-seed");
const expectedLocales = ["zh-CN", "en-US"];
let expectedKeys;

mkdirSync(targetDir, { recursive: true });
for (const locale of expectedLocales) {
  const source = resolve(sourceDir, `${locale}.json`);
  const decoded = JSON.parse(readFileSync(source, "utf8"));
  if (decoded.languageCode !== locale || typeof decoded.messages !== "object")
    throw new Error(`invalid RN-App i18n seed: ${source}`);
  const keys = Object.keys(decoded.messages).sort();
  if (expectedKeys && JSON.stringify(keys) !== JSON.stringify(expectedKeys))
    throw new Error("RN-App locale seed key sets differ");
  expectedKeys = keys;
  writeFileSync(
    resolve(targetDir, `${locale}.json`),
    `${JSON.stringify(decoded, null, 2)}\n`,
  );
}

console.log(
  `synced RN-App i18n seed: ${expectedKeys?.length ?? 0} keys × ${expectedLocales.length} locales`,
);
