import "./style.css";
import {
  compileExclusions,
  compileUserRules,
  GITLEAKS_VERSION,
  MAX_INPUT_BYTES,
  sanitize,
  utf8ByteLength,
  type Finding,
  type Mode,
  type SanitizeResult,
} from "@sanitar/core";
import { applyStaticStrings, t } from "./i18n/index.js";
import { loadSettings, saveSettings, type Settings } from "./settings.js";

// All processing happens here, in the page. This file must never call fetch/XHR.

function $<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`#${id} missing`);
  return el as T;
}

const source = $<HTMLTextAreaElement>("source");
const sourcePane = $<HTMLDivElement>("source-pane");
const sourceSize = $<HTMLSpanElement>("source-size");
const result = $<HTMLTextAreaElement>("result");
const copyBtn = $<HTMLButtonElement>("copy");
const stale = $<HTMLParagraphElement>("stale");
const modeHint = $<HTMLParagraphElement>("mode-hint");
const placeholderOpts = $<HTMLFieldSetElement>("placeholder-opts");
const placeholderInput = $<HTMLInputElement>("placeholder");
const withType = $<HTMLInputElement>("with-type");
const piiToggle = $<HTMLInputElement>("pii");
const exclusions = $<HTMLTextAreaElement>("exclusions");
const exclusionErrors = $<HTMLUListElement>("exclusion-errors");
const extraRules = $<HTMLTextAreaElement>("extra-rules");
const extraRuleErrors = $<HTMLUListElement>("extra-rule-errors");
const runBtn = $<HTMLButtonElement>("run");
const counter = $<HTMLParagraphElement>("counter");
const runError = $<HTMLParagraphElement>("run-error");
const findingsSection = $<HTMLElement>("findings-section");
const findingsList = $<HTMLOListElement>("findings");
const excludedBlock = $<HTMLDivElement>("excluded-block");
const excludedList = $<HTMLOListElement>("excluded");
const modeRadios = [...document.querySelectorAll<HTMLInputElement>('input[name="mode"]')];

applyStaticStrings();
$("shortcut").textContent = /Mac|iPhone|iPad/.test(navigator.platform) ? "⌘↵" : "Ctrl+↵";
$("version").textContent = t.version(GITLEAKS_VERSION);

// ---------------------------------------------------------------- settings

let settings: Settings = loadSettings();

function readSettings(): Settings {
  const checked = modeRadios.find((r) => r.checked);
  return {
    mode: (checked?.value as Mode | undefined) ?? "placeholder",
    placeholder: placeholderInput.value,
    placeholderWithType: withType.checked,
    exclusions: exclusions.value,
    extraRules: extraRules.value,
    pii: piiToggle.checked,
  };
}

function renderSettings(): void {
  for (const r of modeRadios) r.checked = r.value === settings.mode;
  placeholderInput.value = settings.placeholder;
  withType.checked = settings.placeholderWithType;
  exclusions.value = settings.exclusions;
  extraRules.value = settings.extraRules;
  piiToggle.checked = settings.pii;
  updateModeUi();
  validateExclusions();
  validateExtraRules();
}

function updateModeUi(): void {
  const mode = readSettings().mode;
  placeholderOpts.disabled = mode !== "placeholder";
  placeholderOpts.classList.toggle("dim", mode !== "placeholder");
  modeHint.textContent =
    mode === "erase" ? t.modeHintErase : mode === "random" ? t.modeHintRandom : t.modeHintPlaceholder;
}

function onSettingsChange(): void {
  settings = readSettings();
  saveSettings(settings);
  updateModeUi();
  if (lastResult) markStale();
}

for (const r of modeRadios) r.addEventListener("change", onSettingsChange);
placeholderInput.addEventListener("input", onSettingsChange);
withType.addEventListener("change", onSettingsChange);
piiToggle.addEventListener("change", onSettingsChange);
exclusions.addEventListener("input", () => {
  onSettingsChange();
  validateExclusions();
});
extraRules.addEventListener("input", () => {
  onSettingsChange();
  validateExtraRules();
});

function exclusionLines(): string[] {
  return exclusions.value.split("\n");
}

function extraRuleLines(): string[] {
  return extraRules.value.split("\n");
}

function showPatternErrors(
  field: HTMLTextAreaElement,
  list: HTMLUListElement,
  errors: readonly { line: number; message: string }[],
): void {
  list.replaceChildren(
    ...errors.map((e) => {
      const li = document.createElement("li");
      li.textContent = t.exclusionError(e.line, e.message);
      return li;
    }),
  );
  field.classList.toggle("invalid", errors.length > 0);
  field.setAttribute("aria-invalid", String(errors.length > 0));
}

/** Shows invalid exclusion regexes as you type. */
function validateExclusions(): void {
  showPatternErrors(exclusions, exclusionErrors, compileExclusions(exclusionLines()).errors);
}

/** Same for user rules, compiled by core exactly as sanitize() will. */
function validateExtraRules(): void {
  showPatternErrors(extraRules, extraRuleErrors, compileUserRules(extraRuleLines()).errors);
}

// ---------------------------------------------------------------- processing

let lastResult: SanitizeResult | null = null;
let lastSource = "";

function formatSize(bytes: number): string {
  const [b, kb, mb] = t.sizeUnits;
  if (bytes < 1024) return `${bytes} ${b}`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} ${kb}`;
  return `${(bytes / 1024 / 1024).toFixed(2)} ${mb}`;
}

function showError(msg: string | null): void {
  runError.hidden = msg === null;
  runError.textContent = msg ?? "";
}

function updateSourceSize(): void {
  const bytes = utf8ByteLength(source.value);
  sourceSize.textContent = bytes ? formatSize(bytes) : "";
  sourceSize.classList.toggle("over", bytes > MAX_INPUT_BYTES);
}

function markStale(): void {
  stale.hidden = source.value === lastSource && lastResult !== null && !settingsChangedSinceRun();
}

let settingsAtRun = "";
function settingsChangedSinceRun(): boolean {
  return JSON.stringify(readSettings()) !== settingsAtRun;
}

function run(): void {
  const text = source.value;
  const bytes = utf8ByteLength(text);
  if (bytes > MAX_INPUT_BYTES) {
    showError(t.tooLarge(formatSize(bytes), formatSize(MAX_INPUT_BYTES)));
    return;
  }
  showError(null);
  const s = readSettings();
  let res: SanitizeResult;
  try {
    res = sanitize(text, {
      mode: s.mode,
      placeholder: s.placeholder,
      placeholderWithType: s.placeholderWithType,
      exclusions: exclusionLines(),
      extraRules: extraRuleLines(),
      pii: s.pii,
    });
  } catch {
    // deliberately no details: an error message must never echo the text
    showError(t.failed);
    return;
  }
  lastResult = res;
  lastSource = text;
  settingsAtRun = JSON.stringify(s);
  result.value = res.text;
  copyBtn.disabled = false;
  copyBtn.textContent = t.copy;
  stale.hidden = true;
  renderFindings(res);
}

function renderFindings(res: SanitizeResult): void {
  const found = res.findings.length + res.excluded.length;
  counter.textContent = found === 0 ? t.nothingFound : t.counter(found, res.findings.length, res.excluded.length);
  findingsSection.hidden = found === 0;
  findingsList.replaceChildren(...res.findings.map(findingItem));
  excludedList.replaceChildren(...res.excluded.map(findingItem));
  excludedBlock.hidden = res.excluded.length === 0;
}

function findingItem(f: Finding): HTMLLIElement {
  const li = document.createElement("li");
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "finding";
  btn.title = `${f.description}\n${t.showInSource}`;

  const rule = document.createElement("span");
  rule.className = "rule";
  rule.textContent = f.ruleId;
  const line = document.createElement("span");
  line.className = "line";
  line.textContent = t.line(f.line);
  const preview = document.createElement("code");
  preview.className = "preview";
  preview.textContent = f.preview;

  btn.append(rule, line, preview);
  btn.addEventListener("click", () => revealInSource(f));
  li.append(btn);
  return li;
}

/** Selects the finding in the source textarea and scrolls it into view. */
function revealInSource(f: Finding): void {
  // offsets refer to the text that was processed; warn if it has changed since
  markStale();
  source.focus({ preventScroll: true });
  source.setSelectionRange(f.start, f.end);

  // wrap="off": line N is at (N-1) * lineHeight; columns are monospace
  const cs = getComputedStyle(source);
  const lineHeight = parseFloat(cs.lineHeight) || parseFloat(cs.fontSize) * 1.4;
  source.scrollTop = Math.max(0, (f.line - 1) * lineHeight - source.clientHeight / 3);
  const lineStart = source.value.lastIndexOf("\n", f.start - 1) + 1;
  const col = f.start - lineStart;
  source.scrollLeft = Math.max(0, col * charWidth() - source.clientWidth / 3);
}

let cachedCharWidth = 0;
function charWidth(): number {
  if (cachedCharWidth) return cachedCharWidth;
  const probe = document.createElement("span");
  probe.className = "char-probe";
  probe.textContent = "0".repeat(100);
  document.body.append(probe);
  cachedCharWidth = probe.getBoundingClientRect().width / 100 || 8;
  probe.remove();
  return cachedCharWidth;
}

runBtn.addEventListener("click", run);
document.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    run();
  }
});

source.addEventListener("input", () => {
  updateSourceSize();
  if (lastResult) markStale();
});

// ---------------------------------------------------------------- copy

copyBtn.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(result.value);
    copyBtn.textContent = t.copied;
  } catch {
    result.focus();
    result.select();
    copyBtn.textContent = t.copyFailed;
  }
  setTimeout(() => (copyBtn.textContent = t.copy), 2000);
});

// ---------------------------------------------------------------- drag & drop

let dragDepth = 0;
sourcePane.addEventListener("dragenter", (e) => {
  if (!e.dataTransfer?.types.includes("Files")) return;
  e.preventDefault();
  dragDepth++;
  sourcePane.classList.add("dragging");
});
sourcePane.addEventListener("dragover", (e) => {
  if (e.dataTransfer?.types.includes("Files")) e.preventDefault();
});
sourcePane.addEventListener("dragleave", () => {
  dragDepth = Math.max(0, dragDepth - 1);
  if (dragDepth === 0) sourcePane.classList.remove("dragging");
});
sourcePane.addEventListener("drop", async (e) => {
  const file = e.dataTransfer?.files[0];
  dragDepth = 0;
  sourcePane.classList.remove("dragging");
  if (!file) return;
  e.preventDefault();
  if (file.size > MAX_INPUT_BYTES) {
    showError(t.tooLarge(formatSize(file.size), formatSize(MAX_INPUT_BYTES)));
    return;
  }
  const text = await file.text();
  if (text.includes("\u0000")) {
    showError(t.notText);
    return;
  }
  showError(null);
  source.value = text;
  updateSourceSize();
  if (lastResult) markStale();
});

renderSettings();
updateSourceSize();
