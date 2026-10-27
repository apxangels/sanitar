import type { Mode } from "@sanitar/core";

/**
 * UI settings persisted in localStorage. The text itself is never stored —
 * don't add it here.
 */
export interface Settings {
  mode: Mode;
  placeholder: string;
  placeholderWithType: boolean;
  exclusions: string;
  /** also find personal data (emails, phones, cards, names) */
  pii: boolean;
}

const KEY = "sanitar.settings.v1";

export const defaults: Settings = {
  mode: "placeholder",
  placeholder: "<secret>",
  placeholderWithType: false,
  exclusions: "",
  pii: true,
};

export function loadSettings(): Settings {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...defaults };
    const v = JSON.parse(raw) as Partial<Settings>;
    return {
      mode: v.mode === "erase" || v.mode === "random" || v.mode === "placeholder" ? v.mode : defaults.mode,
      placeholder: typeof v.placeholder === "string" ? v.placeholder : defaults.placeholder,
      placeholderWithType: typeof v.placeholderWithType === "boolean" ? v.placeholderWithType : defaults.placeholderWithType,
      exclusions: typeof v.exclusions === "string" ? v.exclusions : defaults.exclusions,
      pii: typeof v.pii === "boolean" ? v.pii : defaults.pii,
    };
  } catch {
    return { ...defaults };
  }
}

export function saveSettings(s: Settings): void {
  // explicit field list so nothing else (like the text) can slip in
  const { mode, placeholder, placeholderWithType, exclusions, pii } = s;
  try {
    localStorage.setItem(KEY, JSON.stringify({ mode, placeholder, placeholderWithType, exclusions, pii }));
  } catch {
    // storage disabled/full: settings just won't persist
  }
}
