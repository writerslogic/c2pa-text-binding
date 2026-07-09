// SPDX-License-Identifier: MIT OR Apache-2.0
// Node round-trip test for the wasm package: fingerprints, watermark, and
// COSE sign/verify — all client-side, no server.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import init, * as wl from "../pkg/c2pa_text_binding.js";

const here = dirname(fileURLToPath(import.meta.url));
await init({ module_or_path: readFileSync(join(here, "../pkg/c2pa_text_binding_bg.wasm")) });

let failures = 0;
function check(name, cond) {
  if (cond) {
    console.log(`  ok   ${name}`);
  } else {
    console.error(`  FAIL ${name}`);
    failures++;
  }
}

const KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const POINTER = "0102030405060708090a0b0c0d0e0f10";
const SECRET = "07070707070707070707070707070707070707070707070707070707070707"; // 31 bytes -> pad below
const secret32 = SECRET.padEnd(64, "0");

const TEXT =
  "Provenance for text must survive the ordinary journey of a copied passage across " +
  "editors and pipelines that reflow and re encode everything they touch without asking, " +
  "so a routing pointer is woven invisibly into the spaces between the words themselves " +
  "and recovered later by any reader who holds the shared protocol key and recomputes the " +
  "very same placement from the normalized content of the document itself today.";

// 1. Fingerprints are deterministic and hex-shaped.
const fp1 = wl.text_fingerprint(TEXT);
const fp2 = wl.text_fingerprint(TEXT);
check("text_fingerprint deterministic", fp1 === fp2 && fp1.length === 64);
check("text_structure hex", wl.text_structure(TEXT).length === 64);

// 2. Reformatting + zero-width injection leave the fingerprint unchanged.
const reflowed = ("  " + TEXT.toUpperCase().replaceAll(" ", "​ ") + "  ");
check("fingerprint survives reformat+zero-width", wl.hamming_hex(fp1, wl.text_fingerprint(reflowed)) === 0);

// 3. Watermark embed -> extract round-trip and content binding.
const marked = wl.embed_watermark(TEXT, POINTER, KEY);
check("watermark is invisible", marked.replaceAll(/[​‌‍⁠﻿]/g, "") === TEXT);
const rec = JSON.parse(wl.extract_watermark(marked, KEY));
check("watermark pointer recovers", rec.pointer === POINTER);
check("watermark tag verifies", rec.verified === true);

// 4. The killer property: strip the invisibles, fingerprint still recovers.
const stripped = marked.replaceAll(/[​‌‍⁠﻿]/g, "");
check("provenance survives full strip via fingerprint", wl.hamming_hex(fp1, wl.text_fingerprint(stripped)) <= 32);

// 5. COSE sign/verify round-trip.
const pub = wl.public_key(secret32);
const assertion = JSON.stringify({ alg: "com.writerslogic.text-fingerprint.1", value: fp1 });
const cose = wl.sign(assertion, secret32);
const payload = wl.verify(cose, pub);
check("COSE sign/verify round-trip", payload === assertion);

// 6. Verify fails on a wrong key.
let rejected = false;
try {
  const otherPub = wl.public_key("09".repeat(32));
  wl.verify(cose, otherPub);
} catch {
  rejected = true;
}
check("COSE verify rejects wrong key", rejected);

// 7. Cross-check tag binds content + repo.
const ch = wl.content_hash(TEXT);
const t1 = wl.cross_check(KEY, "repo-a", ch);
const t2 = wl.cross_check(KEY, "repo-b", ch);
check("cross-check binds repo id", t1 !== t2 && t1.length === 64);

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall wasm round-trip checks passed");
