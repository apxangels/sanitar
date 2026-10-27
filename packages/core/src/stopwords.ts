/**
 * Fast "does the text contain any of these words" check. gitleaks' generic rule
 * has ~1500 stopwords; calling includes() for each one on every finding is the
 * slowest part of a scan with many findings. Instead, words are indexed by
 * their first two chars and the text is walked once.
 */
export type StopwordMatcher = (lowerText: string) => boolean;

const cache = new WeakMap<readonly string[], StopwordMatcher>();

export function stopwordMatcher(words: readonly string[]): StopwordMatcher {
  let m = cache.get(words);
  if (m) return m;

  const short = new Set<string>(); // 1-char words
  const byPrefix = new Map<string, string[]>();
  for (const w of words) {
    if (w.length === 0) continue;
    if (w.length === 1) {
      short.add(w);
      continue;
    }
    const key = w.slice(0, 2);
    const list = byPrefix.get(key);
    if (list) list.push(w);
    else byPrefix.set(key, [w]);
  }

  m = (text) => {
    for (let i = 0; i < text.length; i++) {
      if (short.size > 0 && short.has(text[i]!)) return true;
      const list = byPrefix.get(text.slice(i, i + 2));
      if (list) for (const w of list) if (text.startsWith(w, i)) return true;
    }
    return false;
  };
  cache.set(words, m);
  return m;
}
