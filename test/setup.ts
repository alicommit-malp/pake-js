import { webcrypto } from "node:crypto";

if (typeof (globalThis as { crypto?: unknown }).crypto === "undefined") {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true,
    writable: false,
  });
}
