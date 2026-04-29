import init, { analyze } from "./pkg/macchk.js";
import "./style.css";

const wasmUrl = new URL("./pkg/macchk_bg.wasm", import.meta.url);

type Confidence = "definitive" | "high" | "medium";
type Polarity = "positive" | "negative" | "info";

interface Evidence {
  strategy: string;
  description: string;
  confidence: Confidence;
  address?: number;
  function_name?: string;
}

interface CoverageStats {
  functions_with_feature: number;
  functions_scanned: number;
  sites_found: number;
}

interface CheckResult {
  id: string;
  name: string;
  category: string;
  polarity: Polarity;
  detected: boolean;
  evidence: Evidence[];
  stats?: CoverageStats;
}

interface SliceResult {
  arch: string;
  file_type: string;
  checks: CheckResult[];
}

interface AnalysisResult {
  path: string;
  slices: SliceResult[];
}

const $ = <T extends HTMLElement>(selector: string): T => {
  const element = document.querySelector<T>(selector);
  if (!element) {
    throw new Error(`Missing element: ${selector}`);
  }
  return element;
};

const dropzone = $("#dropzone");
const fileInput = $("#file-input") as HTMLInputElement;
const chooseButton = $("#choose-button") as HTMLButtonElement;
const levelSelect = $("#level") as HTMLSelectElement;
const archSelect = $("#arch") as HTMLSelectElement;
const fileName = $("#file-name");
const statusText = $("#status");
const sliceCount = $("#slice-count");
const detectedCount = $("#detected-count");
const warningCount = $("#warning-count");
const results = $("#results");

let wasmReady: Promise<void> | null = null;
let activeFile: File | null = null;
let activeSliceIndex = 0;
let latestResult: AnalysisResult | null = null;

function ensureWasm(): Promise<void> {
  wasmReady ??= init({ module_or_path: wasmUrl }).then(() => undefined);
  return wasmReady;
}

function setStatus(text: string, busy = false) {
  statusText.textContent = text;
  document.body.classList.toggle("busy", busy);
}

function formatCategory(category: string): string {
  const labels: Record<string, string> = {
    header: "Mach-O Header",
    load_commands: "Load Commands",
    symbols: "Symbol Table",
    codesign: "Code Signing",
    sections: "Sections & Segments",
    entitlements: "Entitlements",
    instructions: "Instruction Analysis",
  };
  if (labels[category]) {
    return labels[category];
  }

  return category
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function categoryClass(category: string): string {
  return `category-${category.replace(/_/g, "-")}`;
}

function statusLabel(check: CheckResult): string {
  if (check.detected) {
    return check.polarity === "negative" ? "Flagged" : "Detected";
  }
  return check.polarity === "info" ? "Not present" : "Missing";
}

function confidenceLabel(confidence: Confidence): string {
  if (confidence === "definitive") {
    return "Definitive";
  }
  return confidence.charAt(0).toUpperCase() + confidence.slice(1);
}

function textElement<K extends keyof HTMLElementTagNameMap>(
  tagName: K,
  text: string,
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tagName);
  element.textContent = text;
  return element;
}

function chip(text: string, className: string): HTMLSpanElement {
  const element = textElement("span", text);
  element.className = className;
  return element;
}

function statTile(label: string, value: number): HTMLDivElement {
  const tile = document.createElement("div");
  tile.className = "stat-tile";
  tile.append(textElement("strong", String(value)), textElement("span", label));
  return tile;
}

function renderEvidence(item: Evidence): HTMLDivElement {
  const row = document.createElement("div");
  row.className = "evidence-item";

  const body = document.createElement("div");
  body.className = "evidence-body";
  body.append(textElement("p", item.description));

  const meta = document.createElement("div");
  meta.className = "evidence-meta";
  meta.append(chip(item.strategy, "strategy-chip"));
  if (item.address !== undefined) {
    meta.append(chip(`0x${item.address.toString(16)}`, "address-chip"));
  }
  if (item.function_name) {
    meta.append(chip(item.function_name, "function-chip"));
  }
  body.append(meta);

  row.append(chip(confidenceLabel(item.confidence), `confidence-chip ${item.confidence}`), body);
  return row;
}

function renderCheck(check: CheckResult): HTMLElement {
  const card = document.createElement("article");
  card.className = `check-card ${check.detected ? "detected" : "missing"} ${check.polarity}`;

  const head = document.createElement("div");
  head.className = "check-card-head";
  head.append(textElement("h3", check.name), chip(statusLabel(check), "status-pill"));

  const id = textElement("code", check.id);
  id.className = "check-id";
  card.append(head, id);

  if (check.stats) {
    const stats = document.createElement("div");
    stats.className = "stat-strip";
    stats.append(
      statTile("with feature", check.stats.functions_with_feature),
      statTile("scanned", check.stats.functions_scanned),
      statTile("sites", check.stats.sites_found),
    );
    card.append(stats);
  }

  const evidence = check.evidence.slice(0, 4);
  if (evidence.length > 0) {
    const evidenceList = document.createElement("div");
    evidenceList.className = "evidence-list";
    evidenceList.replaceChildren(...evidence.map(renderEvidence));
    card.append(evidenceList);
  }

  return card;
}

function renderCategory(category: string, checks: CheckResult[]): HTMLElement {
  const section = document.createElement("details");
  section.className = `check-section ${categoryClass(category)}`;
  section.open = category === "header" || category === "load_commands";

  const detected = checks.filter((check) => check.detected).length;
  const warnings = checks.filter((check) => check.detected && check.polarity === "negative").length;
  const summary = document.createElement("summary");
  summary.className = "section-summary";

  const title = document.createElement("div");
  title.className = "section-title";
  title.append(textElement("strong", formatCategory(category)), textElement("span", `${checks.length} checks`));

  const badges = document.createElement("div");
  badges.className = "section-badges";
  badges.append(chip(`${detected} detected`, "count-chip detected-count"));
  if (warnings > 0) {
    badges.append(chip(`${warnings} warnings`, "count-chip warning-count"));
  }

  summary.append(title, badges);

  const body = document.createElement("div");
  body.className = "check-stack";
  body.replaceChildren(...checks.map(renderCheck));

  section.append(summary, body);
  return section;
}

function renderSliceTabs(result: AnalysisResult): HTMLElement {
  const tabs = document.createElement("div");
  tabs.className = "slice-tabs";
  tabs.setAttribute("role", "tablist");
  tabs.setAttribute("aria-label", "Architecture slices");

  tabs.replaceChildren(
    ...result.slices.map((slice, index) => {
      const button = document.createElement("button");
      const detected = slice.checks.filter((check) => check.detected).length;
      button.type = "button";
      button.className = `slice-tab ${index === activeSliceIndex ? "active" : ""}`;
      button.setAttribute("role", "tab");
      button.setAttribute("aria-selected", String(index === activeSliceIndex));
      button.append(
        textElement("strong", slice.arch),
        textElement("span", slice.file_type),
        chip(`${detected}/${slice.checks.length}`, "slice-score"),
      );
      button.addEventListener("click", () => {
        activeSliceIndex = index;
        if (latestResult) {
          renderResults(latestResult);
        }
      });
      return button;
    }),
  );

  return tabs;
}

function renderSlicePanel(slice: SliceResult): HTMLElement {
  const panel = document.createElement("section");
  panel.className = "slice-panel";
  panel.setAttribute("role", "tabpanel");

  const detected = slice.checks.filter((check) => check.detected).length;
  const warnings = slice.checks.filter((check) => check.detected && check.polarity === "negative").length;

  const banner = document.createElement("header");
  banner.className = "slice-banner";
  const bannerText = document.createElement("div");
  bannerText.append(textElement("span", slice.file_type), textElement("strong", slice.arch));
  const bannerStats = document.createElement("div");
  bannerStats.className = "slice-banner-stats";
  bannerStats.append(chip(`${detected} detected`, "count-chip detected-count"));
  bannerStats.append(chip(`${warnings} warnings`, "count-chip warning-count"));
  banner.append(bannerText, bannerStats);

  const groups = slice.checks.reduce<Record<string, CheckResult[]>>((acc, check) => {
    acc[check.category] ??= [];
    acc[check.category].push(check);
    return acc;
  }, {});

  const categories = document.createElement("div");
  categories.className = "category-stack";
  categories.replaceChildren(
    ...Object.entries(groups).map(([category, checks]) => renderCategory(category, checks)),
  );

  panel.append(banner, categories);
  return panel;
}

function renderSummary(result: AnalysisResult) {
  const allChecks = result.slices.flatMap((slice) => slice.checks);
  const detected = allChecks.filter((check) => check.detected).length;
  const warnings = allChecks.filter(
    (check) => check.detected && check.polarity === "negative",
  ).length;

  sliceCount.textContent = String(result.slices.length);
  detectedCount.textContent = String(detected);
  warningCount.textContent = String(warnings);
}

function renderEmpty(message: string) {
  activeSliceIndex = 0;
  latestResult = null;
  results.className = "results empty";
  results.textContent = message;
  sliceCount.textContent = "0";
  detectedCount.textContent = "0";
  warningCount.textContent = "0";
}

function renderResults(result: AnalysisResult) {
  latestResult = result;
  if (result.slices.length === 0) {
    renderEmpty("No matching architecture found.");
    return;
  }

  activeSliceIndex = Math.min(activeSliceIndex, result.slices.length - 1);
  results.className = "results";
  results.replaceChildren(renderSliceTabs(result), renderSlicePanel(result.slices[activeSliceIndex]));
}

async function analyzeFile(file: File) {
  activeFile = file;
  fileName.textContent = file.name;
  setStatus("Scanning", true);

  try {
    await ensureWasm();
    const bytes = new Uint8Array(await file.arrayBuffer());
    const parsed = JSON.parse(
      analyze(bytes, levelSelect.value, archSelect.value || undefined),
    ) as AnalysisResult;
    activeSliceIndex = 0;
    renderSummary(parsed);
    renderResults(parsed);
    setStatus("Complete");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    latestResult = null;
    renderEmpty(message);
    setStatus("Failed");
  }
}

chooseButton.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", () => {
  const [file] = Array.from(fileInput.files ?? []);
  if (file) {
    void analyzeFile(file);
  }
});

dropzone.addEventListener("dragover", (event) => {
  event.preventDefault();
  dropzone.classList.add("dragging");
});

dropzone.addEventListener("dragleave", () => {
  dropzone.classList.remove("dragging");
});

dropzone.addEventListener("drop", (event) => {
  event.preventDefault();
  dropzone.classList.remove("dragging");
  const [file] = Array.from(event.dataTransfer?.files ?? []);
  if (file) {
    void analyzeFile(file);
  }
});

dropzone.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    fileInput.click();
  }
});

levelSelect.addEventListener("change", () => {
  if (activeFile) {
    void analyzeFile(activeFile);
  }
});

archSelect.addEventListener("change", () => {
  if (activeFile) {
    void analyzeFile(activeFile);
  }
});

void ensureWasm()
  .then(() => setStatus("Waiting"))
  .catch(() => setStatus("WASM unavailable"));
