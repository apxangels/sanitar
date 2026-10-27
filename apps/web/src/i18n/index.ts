import { en, type Strings } from "./en.js";

export type { Strings };

/** Current UI language. English only for now. */
export const t: Strings = en;

/** Fills elements marked with data-i18n / data-i18n-placeholder. */
export function applyStaticStrings(root: ParentNode = document): void {
  for (const el of root.querySelectorAll<HTMLElement>("[data-i18n]")) {
    const v = t[el.dataset.i18n as keyof Strings];
    if (typeof v === "string") el.textContent = v;
  }
  for (const el of root.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("[data-i18n-placeholder]")) {
    const v = t[el.dataset.i18nPlaceholder as keyof Strings];
    if (typeof v === "string") el.placeholder = v;
  }
}
