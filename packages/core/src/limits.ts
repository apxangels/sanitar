/** Maximum input size: 1 MiB of UTF-8. The server and the web UI check it too. */
export const MAX_INPUT_BYTES = 1024 * 1024;

/** Secrets shorter than this are previewed as just "…". */
export const PREVIEW_MIN_LENGTH = 12;
export const PREVIEW_PREFIX_LENGTH = 4;

export class InputTooLargeError extends Error {
  override name = "InputTooLargeError";
  constructor(readonly bytes: number) {
    super(`input is ${bytes} bytes, limit is ${MAX_INPUT_BYTES}`);
  }
}

/** UTF-8 byte length without TextEncoder/Buffer, so it works everywhere. */
export function utf8ByteLength(text: string): number {
  let bytes = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x80) bytes += 1;
    else if (c < 0x800) bytes += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
      const n = text.charCodeAt(i + 1);
      if (n >= 0xdc00 && n <= 0xdfff) {
        bytes += 4;
        i++;
      } else bytes += 3;
    } else bytes += 3;
  }
  return bytes;
}

export function assertInputSize(text: string): void {
  // fast path: even all-4-byte text of this length fits
  if (text.length * 3 <= MAX_INPUT_BYTES) return;
  const bytes = utf8ByteLength(text);
  if (bytes > MAX_INPUT_BYTES) throw new InputTooLargeError(bytes);
}
