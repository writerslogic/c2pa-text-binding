#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Live cross-implementation interop check against Encypher's c2pa-text library.

Encodes with the installed reference library, checks it matches a spec-faithful
A.8 encoder byte for byte and round-trips through its own extractor, then prints
the golden hex constants that tests/interop.rs pins (regenerate those if the
reference library changes).

Run: harness/.venv/bin/python harness/interop.py
"""

import c2pa_text as c

PAYLOAD = b"c2pa-manifest-01"


def byte_to_vs(b):
    return chr(0xFE00 + b) if b <= 15 else chr(0xE0100 + (b - 16))


def spec_encode_wrapper(payload):
    body = c.MAGIC + bytes([c.VERSION]) + len(payload).to_bytes(4, "big") + payload
    return c.ZWNBSP + "".join(byte_to_vs(x) for x in body)


def main():
    enc = c.encode_wrapper(PAYLOAD)
    assert enc == spec_encode_wrapper(PAYLOAD), (
        "Encypher output diverges from the A.8 spec formula"
    )
    got, _ = c.extract_manifest(c.embed_manifest("Doc.", PAYLOAD))
    assert got == PAYLOAD, "Encypher does not round-trip its own output"
    print("Encypher c2pa-text interop OK: matches the A.8 spec formula and round-trips")
    print("PAYLOAD_HEX =", PAYLOAD.hex())
    print("ENCYPHER_WRAPPER_HEX =", enc.encode("utf-8").hex())


if __name__ == "__main__":
    main()
