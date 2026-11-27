// Behavioral tests for app/media-crypto.ts: file validation before encryption,
// the AES-GCM round trip, and the attachment descriptor guard.
import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  base64ToBytes,
  bytesToBase64,
  createMediaKey,
  decryptMediaBlob,
  encryptMediaBlob,
  isAttachmentDescriptor,
  mediaKindFor,
  validateMediaFile,
} from "../app/media-crypto.ts";

const MB = 1024 * 1024;
// crypto.getRandomValues is limited to 64 KiB per call.
const randomBytes = (length) => {
  const bytes = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 65_536) crypto.getRandomValues(bytes.subarray(offset, offset + 65_536));
  return bytes;
};
const fileOf = (bytes, type, name = "upload") => new File([new Uint8Array(bytes)], name, { type });
const ascii = (text) => [...text].map((character) => character.charCodeAt(0));
const padded = (header, size = 32) => [...header, ...new Array(Math.max(0, size - header.length)).fill(0)];

// A file whose reported size is large without allocating the bytes up front.
const sizedFile = (header, type, size) => new File([new Uint8Array(header), new Uint8Array(size - header.length)], "big", { type });

describe("mediaKindFor", () => {
  const cases = [
    ["image/gif", "gif"],
    ["IMAGE/PNG", "image"],
    ["image/webp", "image"],
    ["video/quicktime", "video"],
    ["audio/x-m4a", "audio"],
    ["application/pdf", "file"],
    ["text/csv", "file"],
    ["image/svg+xml", null],
    ["text/html", null],
    ["application/x-msdownload", null],
    ["", null],
  ];
  for (const [mime, kind] of cases) {
    test(`${mime || "(empty)"} → ${kind}`, () => assert.equal(mediaKindFor(fileOf([0], mime)), kind));
  }
});

describe("validateMediaFile", () => {
  const validHeaders = [
    ["image/jpeg", [0xff, 0xd8, 0xff, 0xe0], "image"],
    ["image/png", [0x89, ...ascii("PNG"), 0x0d, 0x0a, 0x1a, 0x0a], "image"],
    ["image/gif", ascii("GIF89a"), "gif"],
    ["image/webp", [...ascii("RIFF"), 0, 0, 0, 0, ...ascii("WEBP")], "image"],
    ["video/mp4", [0, 0, 0, 0x18, ...ascii("ftyp")], "video"],
    ["video/webm", [0x1a, 0x45, 0xdf, 0xa3], "video"],
    ["audio/ogg", ascii("OggS"), "audio"],
    ["audio/wav", [...ascii("RIFF"), 0, 0, 0, 0, ...ascii("WAVE")], "audio"],
    ["audio/mpeg", ascii("ID3"), "audio"],
    ["audio/mpeg", [0xff, 0xfb], "audio"],
    ["application/pdf", ascii("%PDF-1.7"), "file"],
    ["application/zip", [0x50, 0x4b, 3, 4], "file"],
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document", [0x50, 0x4b, 3, 4], "file"],
    ["application/msword", [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], "file"],
    ["text/plain", ascii("hello"), "file"],
  ];
  for (const [mime, header, kind] of validHeaders) {
    test(`accepts a genuine ${mime} header`, async () => {
      assert.equal(await validateMediaFile(fileOf(padded(header), mime)), kind);
    });
  }

  test("rejects files whose contents do not match the declared type", async () => {
    const pdfBytes = padded(ascii("%PDF-1.7"));
    await assert.rejects(validateMediaFile(fileOf(pdfBytes, "image/png")), /do not match/);
    await assert.rejects(validateMediaFile(fileOf(padded(ascii("<html>")), "image/jpeg")), /do not match/);
    await assert.rejects(validateMediaFile(fileOf(padded(ascii("RIFF....AVI ")), "image/webp")), /do not match/);
    await assert.rejects(validateMediaFile(fileOf(padded([0x4d, 0x5a]), "application/zip")), /do not match/);
  });

  test("rejects unsupported types and empty files", async () => {
    await assert.rejects(validateMediaFile(fileOf(padded(ascii("<svg")), "image/svg+xml")), /not supported/);
    await assert.rejects(validateMediaFile(fileOf([], "image/png")), /Empty files/);
  });

  test("enforces per-kind size limits", async () => {
    const jpeg = [0xff, 0xd8, 0xff, 0xe0];
    assert.equal(await validateMediaFile(sizedFile(jpeg, "image/jpeg", 15 * MB)), "image");
    await assert.rejects(validateMediaFile(sizedFile(jpeg, "image/jpeg", 15 * MB + 1)), /up to 15 MB/);
    await assert.rejects(validateMediaFile(sizedFile(ascii("OggS"), "audio/ogg", 25 * MB + 1)), /up to 25 MB/);
    await assert.rejects(validateMediaFile(sizedFile(ascii("%PDF-"), "application/pdf", 50 * MB + 1)), /up to 50 MB/);
  });
});

describe("AES-GCM media encryption", () => {
  test("round-trips arbitrary binary content with a fresh IV each time", async () => {
    const plaintext = randomBytes(70_000);
    const keyBytes = createMediaKey();
    assert.equal(keyBytes.length, 32);

    const first = await encryptMediaBlob(new Blob([plaintext]), keyBytes);
    const second = await encryptMediaBlob(new Blob([plaintext]), keyBytes);
    assert.equal(first.iv.length, 12);
    assert.notDeepEqual(first.iv, second.iv);
    assert.equal(first.ciphertext.size, plaintext.length + 16, "ciphertext carries the 16-byte GCM tag");
    assert.equal(first.ciphertext.type, "application/octet-stream");

    const decrypted = await decryptMediaBlob(await first.ciphertext.arrayBuffer(), bytesToBase64(keyBytes), bytesToBase64(first.iv), "image/png");
    assert.equal(decrypted.type, "image/png");
    assert.deepEqual(new Uint8Array(await decrypted.arrayBuffer()), plaintext);
  });

  test("decryption fails with the wrong key, wrong IV, or tampered ciphertext", async () => {
    const keyBytes = createMediaKey();
    const { ciphertext, iv } = await encryptMediaBlob(new Blob(["secret media"]), keyBytes);
    const bytes = new Uint8Array(await ciphertext.arrayBuffer());
    const key = bytesToBase64(keyBytes);
    const ivText = bytesToBase64(iv);

    await assert.rejects(decryptMediaBlob(bytes.buffer, bytesToBase64(createMediaKey()), ivText, "text/plain"));
    await assert.rejects(decryptMediaBlob(bytes.buffer, key, bytesToBase64(new Uint8Array(12)), "text/plain"));
    const tampered = bytes.slice();
    tampered[0] ^= 1;
    await assert.rejects(decryptMediaBlob(tampered.buffer, key, ivText, "text/plain"));
  });

  test("base64 helpers round-trip buffers larger than one encoding chunk", () => {
    const bytes = randomBytes(0x8000 * 2 + 7);
    assert.deepEqual(base64ToBytes(bytesToBase64(bytes)), bytes);
  });
});

describe("isAttachmentDescriptor", () => {
  const descriptor = {
    version: 1, id: "a", kind: "image", name: "photo.png", mime: "image/png", size: 10,
    key: "k", iv: "i", retention: "7d", expiresAt: null,
  };

  test("accepts a complete descriptor", () => {
    assert.equal(isAttachmentDescriptor(descriptor), true);
    assert.equal(isAttachmentDescriptor({ ...descriptor, expiresAt: "2026-01-01T00:00:00.000Z" }), true);
  });

  test("rejects missing fields, wrong versions, and unknown kinds", () => {
    assert.equal(isAttachmentDescriptor(null), false);
    assert.equal(isAttachmentDescriptor("descriptor"), false);
    assert.equal(isAttachmentDescriptor({ ...descriptor, version: 2 }), false);
    assert.equal(isAttachmentDescriptor({ ...descriptor, kind: "script" }), false);
    assert.equal(isAttachmentDescriptor({ ...descriptor, size: "10" }), false);
    assert.equal(isAttachmentDescriptor({ ...descriptor, expiresAt: undefined }), false);
    const withoutKey = { ...descriptor };
    delete withoutKey.key;
    assert.equal(isAttachmentDescriptor(withoutKey), false);
  });
});
