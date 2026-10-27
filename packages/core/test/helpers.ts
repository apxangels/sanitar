/**
 * Test secrets are generated at runtime so that nothing in the repository looks
 * like a real credential (GitHub push protection / secret scanners).
 * Prefixes are split with "+" for the same reason.
 */
export const LOWER = "abcdefghijklmnopqrstuvwxyz";
export const UPPER = LOWER.toUpperCase();
export const DIGITS = "0123456789";
export const ALNUM = LOWER + UPPER + DIGITS;
export const B64 = ALNUM + "+/";

export function rand(alphabet: string, n: number): string {
  let s = "";
  const buf = new Uint32Array(n);
  for (let off = 0; off < n; off += 16384) {
    crypto.getRandomValues(buf.subarray(off, Math.min(n, off + 16384)));
  }
  for (let i = 0; i < n; i++) s += alphabet[buf[i]! % alphabet.length];
  return s;
}

export const fake = {
  githubPat: () => "gh" + "p_" + rand(ALNUM, 36),
  awsKeyId: () => "AK" + "IA" + rand("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16),
  slackBot: () => "xo" + "xb-" + rand(DIGITS, 12) + "-" + rand(DIGITS, 12) + "-" + rand(ALNUM, 24),
  jwt: () => "ey" + "J" + rand(ALNUM, 30) + ".ey" + "J" + rand(ALNUM, 60) + "." + rand(ALNUM + "-_", 43),
  password: () => rand(LOWER, 4) + rand(DIGITS, 3) + rand(UPPER, 3),
  privateKey: (kind = "RSA") => {
    const lines = Array.from({ length: 12 }, () => rand(B64, 64));
    return [`-----BEGIN ${kind} PRIVATE` + " KEY-----", ...lines, `-----END ${kind} PRIVATE` + " KEY-----"].join("\n");
  },
};
