"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
const API_URL = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
type NavKey = "dashboard" | "scanner" | "history" | "campaigns" | "safety";
type Signal = {
  name?: string;
  signal?: string;
  value?: number | string | boolean;
  score?: number;
  severity?: string;
  description?: string;
};
type AnalysisResult = {
  analysis_id?: string;
  timestamp?: string;
  prediction?: string;
  binary_prediction?: string;
  risk_score?: number;
  risk_level?: string;
  category?: string;
  confidence?: number;
  scam_probability?: number;
  explanation?: string;
  signals?: Signal[];
  recommendations?: string[];
  campaign_id?: string | null;
  campaign?: {
    campaign_id?: string;
    is_known_campaign?: boolean;
    similarity?: number;
    description?: string;
  };
  [key: string]: unknown;
};
type ScanItem = {
  analysis_id: string;
  timestamp?: string | null;
  category: string;
  risk_score: number;
  risk_level: string;
  prediction: string;
  campaign_id?: string | null;
  input_preview?: string;
  urls?: string[];
};
type ScanDetail = ScanItem & {
  input_text?: string;
  ocr_text?: string;
  result?: AnalysisResult;
};
type HistoryResponse = {
  total: number;
  limit: number;
  offset: number;
  items: ScanItem[];
};
type Stats = {
  total_scans: number;
  high_or_critical_scans: number;
  category_distribution: Record<string, number>;
  risk_distribution: Record<string, number>;
};
type MissedScamReportResponse = {
  report_id: string;
  status: string;
  created_at?: string | null;
  message: string;
};

const samples = {
  kyc: {
    text: "URGENT: Your KYC is pending. Your bank account will be blocked today. Verify your KYC immediately using the link below and submit your PAN and Aadhaar details.",
    url: "https://secure-kyc-verification.example.com/update",
  },
  lottery: {
    text: "Congratulations! You have won a lottery prize of Rs 25,00,000. To receive your prize, pay a small processing fee immediately and send your bank details.",
    url: "",
  },
  delivery: {
    text: "Your parcel could not be delivered because of an incomplete address. Pay Rs 25 delivery rescheduling fee using the link below to receive your package.",
    url: "https://delivery-update.example.com/pay",
  },
  job: {
    text: "Congratulations! You have been selected for a work-from-home job with a salary of Rs 50,000 per month. To confirm your appointment, pay a refundable registration fee of Rs 2,000 today. Send your bank details for verification.",
    url: "",
  },
  benign: {
    text: "Hey, I will reach college around 10 AM. Please send me the notes when you get time.",
    url: "",
  },
};
const navItems: { label: string; icon: string; key: NavKey }[] = [
  { label: "Dashboard", icon: "D", key: "dashboard" },
  { label: "Threat Scanner", icon: "S", key: "scanner" },
  { label: "Scan History", icon: "H", key: "history" },
  { label: "Scam Campaigns", icon: "C", key: "campaigns" },
  { label: "Safety Toolkit", icon: "T", key: "safety" },
];
function riskTone(level = "") {
  const value = level.toUpperCase();
  if (value === "CRITICAL") {
    return { text: "#dc2626", bg: "#fff1f2", border: "#fecdd3", ring: "#ef4444" };
  }
  if (value === "HIGH") {
    return { text: "#ea580c", bg: "#fff7ed", border: "#fed7aa", ring: "#f97316" };
  }
  if (value === "MEDIUM") {
    return { text: "#ca8a04", bg: "#fefce8", border: "#fde68a", ring: "#eab308" };
  }
  return { text: "#059669", bg: "#ecfdf5", border: "#a7f3d0", ring: "#10b981" };
}
function formatCategory(category = "OTHER") {
  return category
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}
function formatDate(value?: string | null) {
  if (!value) return "Date unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString();
}
function getSignalName(signal: Signal) {
  return signal.name || signal.signal || "Security signal";
}
function getSignalValue(signal: Signal) {
  if (signal.value !== undefined) return String(signal.value);
  if (signal.score !== undefined) {
    return typeof signal.score === "number"
      ? `${Math.round(signal.score * 100)}%`
      : String(signal.score);
  }
  return signal.severity || "Detected";
}
function getErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : "An unexpected error occurred.";
}
async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`API request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}
function Panel({
  title,
  subtitle,
  children,
  action,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <section className="rounded-[26px] border border-[#d5e8f2] bg-white/95 p-6 shadow-[0_16px_50px_rgba(19,86,130,.07)] sm:p-8">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-xl font-black text-[#17364b]">{title}</h2>
          {subtitle && <p className="mt-2 text-sm leading-6 text-[#78909f]">{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
function MetricCard({
  label,
  value,
  description,
  icon,
}: {
  label: string;
  value: string | number;
  description: string;
  icon: string;
}) {
  return (
    <div className="rounded-[22px] border border-[#d9eaf3] bg-white p-6 shadow-[0_12px_35px_rgba(19,86,130,.06)]">
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm font-bold text-[#78909f]">{label}</span>
        <span className="grid h-11 w-11 place-items-center rounded-xl bg-[#eaf7ff] text-xl text-[#087fe5]">
          {icon}
        </span>
      </div>
      <div className="mt-5 text-4xl font-black tracking-tight text-[#17364b]">{value}</div>
      <p className="mt-2 text-xs leading-5 text-[#91a4b1]">{description}</p>
    </div>
  );
}
function RiskBadge({ level }: { level: string }) {
  const tone = riskTone(level);
  return (
    <span
      className="inline-flex rounded-full border px-3 py-1.5 text-xs font-black"
      style={{ color: tone.text, background: tone.bg, borderColor: tone.border }}
    >
      {level || "UNKNOWN"}
    </span>
  );
}
function EmptyState({
  title,
  message,
}: {
  title: string;
  message: string;
}) {
  return (
    <div className="rounded-2xl border border-dashed border-[#cbdfea] bg-[#fbfdff] px-6 py-12 text-center">
      <div className="text-3xl font-black text-[#7da9c0]">i</div>
      <h3 className="mt-3 font-black text-[#17364b]">{title}</h3>
      <p className="mx-auto mt-2 max-w-lg text-sm leading-6 text-[#78909f]">{message}</p>
    </div>
  );
}
export default function Home() {
  const [activeNav, setActiveNav] = useState<NavKey>("scanner");
  const [text, setText] = useState("");
  const [url, setUrl] = useState("");
  const [mode, setMode] = useState<"message" | "url">("message");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [notice, setNotice] = useState("");
  const [pageError, setPageError] = useState("");
  const [stats, setStats] = useState<Stats | null>(null);
  const [history, setHistory] = useState<HistoryResponse | null>(null);
  const [historyOffset, setHistoryOffset] = useState(0);
  const [selectedScan, setSelectedScan] = useState<ScanDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [reportType, setReportType] = useState("MISSED_DETECTION");
  const [reportDescription, setReportDescription] = useState("");
  const [suspiciousContent, setSuspiciousContent] = useState("");
  const [submittingReport, setSubmittingReport] = useState(false);
  const [reportNotice, setReportNotice] = useState("");
  const [reportError, setReportError] = useState("");

  const riskScore = Math.max(
    0,
    Math.min(100, Math.round(
      typeof result?.risk_score === "number"
        ? result.risk_score
        : typeof result?.scam_probability === "number"
          ? result.scam_probability
          : 0
    ))
  );
  const riskLevel = result?.risk_level || "LOW";
  const tone = riskTone(riskLevel);
  const circumference = 2 * Math.PI * 88;
  const dashOffset = circumference - (riskScore / 100) * circumference;
  const loadDashboardData = useCallback(async () => {
    setRefreshing(true);
    setPageError("");
    try {
      const [statsData, historyData] = await Promise.all([
        apiGet<Stats>("/stats"),
        apiGet<HistoryResponse>("/history?limit=100&offset=0"),
      ]);
      setStats(statsData);
      setHistory(historyData);
    } catch (error) {
      setPageError(`${getErrorMessage(error)}. Check that the ScamShield API is running on port 8000.`);
    } finally {
      setRefreshing(false);
    }
  }, []);
  const loadHistory = useCallback(async (offset: number) => {
    setRefreshing(true);
    setPageError("");
    try {
      const data = await apiGet<HistoryResponse>(
        `/history?limit=20&offset=${offset}`
      );
      setHistory(data);
      setHistoryOffset(offset);
    } catch (error) {
      setPageError(`${getErrorMessage(error)}. Check that the API is running.`);
    } finally {
      setRefreshing(false);
    }
  }, []);
  useEffect(() => {
    if (activeNav === "dashboard") {
      void loadDashboardData();
    } else if (activeNav === "history") {
      void loadHistory(historyOffset);
    } else if (activeNav === "campaigns") {
      void loadDashboardData();
    }
  }, [activeNav, historyOffset, loadDashboardData, loadHistory]);
  const campaigns = useMemo(() => {
    const groups = new Map<string, { count: number; highestRisk: number; latest?: string; category: string }>();
    for (const scan of history?.items || []) {
      if (!scan.campaign_id) continue;
      const existing = groups.get(scan.campaign_id);
      if (existing) {
        existing.count += 1;
        existing.highestRisk = Math.max(existing.highestRisk, scan.risk_score || 0);
        if (scan.timestamp && (!existing.latest || scan.timestamp > existing.latest)) {
          existing.latest = scan.timestamp;
          existing.category = scan.category;
        }
      } else {
        groups.set(scan.campaign_id, {
          count: 1,
          highestRisk: scan.risk_score || 0,
          latest: scan.timestamp || undefined,
          category: scan.category || "OTHER",
        });
      }
    }
    return Array.from(groups.entries())
      .map(([campaign_id, data]) => ({ campaign_id, ...data }))
      .sort((a, b) => b.highestRisk - a.highestRisk);
  }, [history]);
  async function analyze() {
    const cleanText = text.trim();
    const cleanUrl = url.trim();
    if (!cleanText && !cleanUrl) {
      setNotice("Enter a message or URL to start the security analysis.");
      return;
    }
    setNotice("");
    setLoading(true);
    setResult(null);
    try {
      let data: AnalysisResult;

      if (!cleanText && cleanUrl) {
        const response = await fetch(`${API_URL}/predict`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: cleanUrl }),
        });

        if (!response.ok) {
          const detail = await response.json().catch(() => null);
          throw new Error(
            typeof detail?.detail === "string"
              ? detail.detail
              : typeof detail?.error === "string"
                ? detail.error
                : `URL prediction API returned ${response.status}`
          );
        }

        const prediction = await response.json() as {
          url: string;
          hostname: string;
          prediction: string;
          is_phishing: boolean;
          phishing_score: number;
          threshold: number;
          model_version: string;
          warning?: string;
        };

        const probability = Math.max(
          0,
          Math.min(1, Number(prediction.phishing_score) || 0)
        );
        const isPhishing =
          prediction.is_phishing === true ||
          prediction.prediction?.toUpperCase() === "PHISHING";

        data = {
          prediction: isPhishing ? "SCAM" : "NON_SCAM",
          binary_prediction: isPhishing ? "SCAM" : "NON_SCAM",
          risk_score: Math.round(probability * 100),
          scam_probability: probability * 100,
          confidence: Math.max(probability, 1 - probability),
          risk_level: isPhishing ? "HIGH" : "LOW",
          category: "URL_ANALYSIS",
          explanation: `${prediction.warning || "Prediction is probabilistic."} Model: ${prediction.model_version}. URL: ${prediction.hostname}.`,
          signals: [
            {
              name: "URL phishing model",
              value: `${(probability * 100).toFixed(2)}% phishing probability`,
              description: `Decision threshold: ${(prediction.threshold * 100).toFixed(0)}%`,
              severity: isPhishing ? "HIGH" : "LOW",
            },
          ],
          recommendations: isPhishing
            ? ["Avoid opening this URL or entering personal information."]
            : ["Check the website address carefully before sharing sensitive information."],
        };
      } else {
        const response = await fetch(`${API_URL}/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            text: cleanText,
            urls: cleanUrl ? [cleanUrl] : [],
            ocr_text: "",
          }),
        });

        if (!response.ok) {
          const detail = await response.json().catch(() => null);
          throw new Error(
            typeof detail?.detail === "string"
              ? detail.detail
              : typeof detail?.error === "string"
                ? detail.error
                : `API returned ${response.status}`
          );
        }

        data = await response.json() as AnalysisResult;
      }
      setResult(data);
      setActiveNav("scanner");
      void loadDashboardData();
    } catch (error) {
      setNotice(
        `Analysis failed: ${getErrorMessage(error)}. Confirm that the FastAPI server is running on port 8000.`
      );
    } finally {
      setLoading(false);
    }
  }
  async function submitMissedScamReport() {
    const description = reportDescription.trim();
    const content = suspiciousContent.trim();

    if (!description && !content) {
      setReportError("Add a description or suspicious message/URL before submitting.");
      setReportNotice("");
      return;
    }

    setSubmittingReport(true);
    setReportError("");
    setReportNotice("");

    try {
      const response = await fetch(`${API_URL}/api/v1/reports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          report_type: reportType,
          description,
          suspicious_content: content,
        }),
      });

      const data = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(
          typeof data?.detail === "string"
            ? data.detail
            : `Report submission failed (${response.status})`,
        );
      }

      const report = data as MissedScamReportResponse;
      setReportNotice(
        `Report saved. ID: ${report.report_id} | Status: ${report.status}. ${report.message}`,
      );
      setReportDescription("");
      setSuspiciousContent("");
    } catch (error) {
      setReportError(
        `${getErrorMessage(error)}. Confirm the ScamShield API is reachable.`,
      );
    } finally {
      setSubmittingReport(false);
    }
  }

  function loadSample(type: keyof typeof samples) {
    const sample = samples[type];
    setText(sample.text);
    setUrl(sample.url);
    setMode(sample.url ? "url" : "message");
    setResult(null);
    setNotice("");
    setActiveNav("scanner");
  }
  function clearScanner() {
    setText("");
    setUrl("");
    setResult(null);
    setNotice("");
  }
  async function openScan(analysisId: string) {
    setSelectedScan(null);
    setDetailLoading(true);
    setPageError("");
    try {
      const detail = await apiGet<ScanDetail>(
        `/history/${encodeURIComponent(analysisId)}`
      );
      setSelectedScan(detail);
    } catch (error) {
      setPageError(`Unable to load scan details: ${getErrorMessage(error)}`);
    } finally {
      setDetailLoading(false);
    }
  }
  function openScanInScanner(scan: ScanDetail) {
    setText(scan.input_text || scan.input_preview || "");
    setUrl(scan.urls?.[0] || "");
    setResult(scan.result || {
      analysis_id: scan.analysis_id,
      prediction: scan.prediction,
      category: scan.category,
      risk_score: scan.risk_score,
      risk_level: scan.risk_level,
      campaign_id: scan.campaign_id,
    });
    setActiveNav("scanner");
    setSelectedScan(null);
    setNotice("");
  }
  const recentScans = history?.items || [];
  return (
    <main className="min-h-screen overflow-x-hidden bg-[#f5faff] text-[#102b40]">
      <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
        <div className="absolute -left-40 -top-40 h-[520px] w-[520px] rounded-full bg-[#dff4ff] blur-3xl" />
        <div className="absolute right-[-180px] top-[15%] h-[600px] w-[600px] rounded-full bg-[#e7f1ff] blur-3xl" />
        <div className="absolute bottom-[-220px] left-[30%] h-[500px] w-[500px] rounded-full bg-[#eefaff] blur-3xl" />
        <div className="absolute inset-0 opacity-[0.25] [background-image:linear-gradient(rgba(24,110,160,.07)_1px,transparent_1px),linear-gradient(90deg,rgba(24,110,160,.07)_1px,transparent_1px)] [background-size:42px_42px]" />
      </div>
      <div className="mx-auto grid min-h-screen max-w-[1900px] gap-6 p-5 sm:p-7 lg:grid-cols-[360px_minmax(0,1fr)] lg:p-8">
        <aside className="flex min-h-[600px] flex-col rounded-[34px] border border-[#d1e7f4] bg-white/95 p-7 shadow-[0_24px_90px_rgba(19,86,130,.13)] backdrop-blur-xl lg:sticky lg:top-8 lg:h-[calc(100vh-64px)]">
          <button
            onClick={() => setActiveNav("scanner")}
            className="mb-9 flex items-center gap-4 px-2 text-left"
          >
            <div className="relative grid h-[68px] w-[68px] shrink-0 place-items-center rounded-[22px] bg-gradient-to-br from-[#087fe5] to-[#54c8ff] text-4xl text-white shadow-[0_18px_38px_rgba(8,127,229,.27)]">
              S
              <span className="absolute -right-1 -top-1 h-4 w-4 rounded-full border-[3px] border-white bg-[#19bd8a]" />
            </div>
            <div>
              <div className="text-[27px] font-black tracking-tight text-[#102b40]">ScamShield</div>
              <div className="mt-1 text-[10px] font-black tracking-[.14em] text-[#8095a8]">AI THREAT INTELLIGENCE</div>
            </div>
          </button>
          <div className="mb-4 px-2 text-xs font-black uppercase tracking-[.18em] text-[#8fa5b7]">
            Security Center
          </div>
          <nav className="space-y-2">
            {navItems.map((item) => {
              const active = activeNav === item.key;
              return (
                <button
                  key={item.key}
                  onClick={() => {
                    setActiveNav(item.key);
                    setSelectedScan(null);
                    setPageError("");
                  }}
                  className={`group flex min-h-[64px] w-full items-center gap-4 rounded-[19px] px-4 text-left text-[15px] font-extrabold transition ${
                    active
                      ? "bg-[#e9f6ff] text-[#087fe5] shadow-[inset_4px_0_0_#087fe5]"
                      : "text-[#5f788b] hover:bg-[#f3faff] hover:text-[#087fe5]"
                  }`}
                >
                  <span className={`grid h-11 w-11 shrink-0 place-items-center rounded-[14px] text-2xl ${
                    active ? "bg-white text-[#087fe5] shadow-sm" : "bg-[#f2f8fc] text-[#7c9aaf]"
                  }`}>
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                  {active && <span className="ml-auto h-2.5 w-2.5 rounded-full bg-[#13a9e8]" />}
                </button>
              );
            })}
          </nav>
          <div className="flex-1" />
          <div className="rounded-[23px] border border-[#cceafa] bg-gradient-to-br from-[#effaff] to-[#f7fcff] p-5">
            <div className="flex items-center gap-3">
              <div className="grid h-12 w-12 place-items-center rounded-2xl bg-white text-2xl font-black text-[#087fe5] shadow-sm">OK</div>
              <div>
                <div className="font-black text-[#28749f]">AI Protected</div>
                <div className="mt-1 text-xs font-bold text-[#8196a8]">Threat engine status</div>
              </div>
            </div>
            <div className="mt-4 flex items-center gap-2 text-xs font-black text-[#15966f]">
              <span className="h-2.5 w-2.5 rounded-full bg-[#19bd8a]" />
              API STATUS CHECKED ON REQUEST
            </div>
          </div>
          <div className="mt-5 px-2 text-[11px] font-bold leading-5 text-[#9aabba]">
            ScamShield AI Engine<br />Secure threat analysis platform
          </div>
        </aside>
        <section className="min-w-0 px-1 py-2 lg:px-3">
          <header className="mb-8 flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
            <div>
              <div className="mb-4 inline-flex items-center gap-3 rounded-full border border-[#c8eafa] bg-white/90 px-4 py-2.5 text-[11px] font-black tracking-[.15em] text-[#1787c5] shadow-sm">
                <span className="h-2.5 w-2.5 rounded-full bg-[#16b981]" />
                REAL-TIME AI SECURITY
              </div>
              <h1 className="max-w-4xl text-[42px] font-black leading-[1.04] tracking-[-.04em] text-[#102b40] sm:text-[56px]">
                {activeNav === "scanner" && <>Stop scams<br /><span className="bg-gradient-to-r from-[#087fe5] via-[#149fe8] to-[#51c8f5] bg-clip-text text-transparent">before they spread.</span></>}
                {activeNav === "dashboard" && <>Threat<br /><span className="bg-gradient-to-r from-[#087fe5] to-[#51c8f5] bg-clip-text text-transparent">intelligence.</span></>}
                {activeNav === "history" && <>Your scan<br /><span className="bg-gradient-to-r from-[#087fe5] to-[#51c8f5] bg-clip-text text-transparent">history.</span></>}
                {activeNav === "campaigns" && <>Scam campaign<br /><span className="bg-gradient-to-r from-[#087fe5] to-[#51c8f5] bg-clip-text text-transparent">intelligence.</span></>}
                {activeNav === "safety" && <>Stay alert.<br /><span className="bg-gradient-to-r from-[#087fe5] to-[#51c8f5] bg-clip-text text-transparent">Stay protected.</span></>}
              </h1>
              <p className="mt-4 max-w-3xl text-base leading-7 text-[#698296]">
                {activeNav === "scanner" && "Analyze suspicious messages, links and social-engineering patterns with the ScamShield threat engine."}
                {activeNav === "dashboard" && "A live overview of scan activity and risk patterns recorded by your backend."}
                {activeNav === "history" && "Review previously analyzed content and open the full stored result for any scan."}
                {activeNav === "campaigns" && "Explore campaign identifiers actually recorded by the analysis pipeline."}
                {activeNav === "safety" && "Practical steps to reduce exposure to phishing, payment fraud and impersonation scams."}
              </p>
            </div>
            <div className="rounded-[20px] border border-[#d5eaf5] bg-white/90 px-5 py-4 shadow-sm">
              <div className="text-[10px] font-black uppercase tracking-[.15em] text-[#8da3b4]">Backend</div>
              <div className="mt-2 flex items-center gap-2 text-sm font-black text-[#176b8f]">
                <span className="h-2.5 w-2.5 rounded-full bg-[#17b985]" />
                FastAPI   Port 8000
              </div>
            </div>
          </header>
          {pageError && (
            <div className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-[#fed7aa] bg-[#fff7ed] px-5 py-4 text-sm font-semibold text-[#9a3412]">
              <span>{pageError}</span>
              <button onClick={() => activeNav === "history" ? void loadHistory(historyOffset) : void loadDashboardData()} className="rounded-lg border border-[#fdba74] bg-white px-3 py-2 font-black">Retry</button>
            </div>
          )}
          {activeNav === "scanner" && (
            <>
              <section className="relative overflow-hidden rounded-[30px] border border-[#cfe6f2] bg-white/95 p-6 shadow-[0_25px_90px_rgba(19,86,130,.12)] sm:p-8">
                <div className="mb-6 flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
                  <div className="flex items-center gap-4">
                    <div className="grid h-13 w-13 place-items-center rounded-2xl bg-[#e9f7ff] p-3 text-2xl font-black text-[#087fe5]">TS</div>
                    <div>
                      <h2 className="text-2xl font-black text-[#17364b]">Threat Scanner</h2>
                      <p className="mt-1 text-sm text-[#7b91a2]">Inspect a suspicious message or URL.</p>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {([
                      ["kyc", "KYC Demo"],
                      ["lottery", "Lottery Demo"],
                      ["delivery", "Delivery Demo"],
                      ["job", "Job Scam Demo"],
                      ["benign", "Safe Demo"],
                    ] as const).map(([key, label]) => (
                      <button key={key} onClick={() => loadSample(key)} className="rounded-xl border border-[#d7e9f3] bg-[#f8fcff] px-3 py-2.5 text-xs font-black text-[#5f8094] transition hover:border-[#8ccdf0] hover:text-[#087fe5]">
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="mb-5 grid grid-cols-2 gap-2 rounded-2xl bg-[#f1f7fb] p-2">
                  <button onClick={() => setMode("message")} className={`rounded-xl py-3 text-sm font-black transition ${mode === "message" ? "bg-white text-[#087fe5] shadow-sm" : "text-[#7c94a6]"}`}>Message Analysis</button>
                  <button onClick={() => setMode("url")} className={`rounded-xl py-3 text-sm font-black transition ${mode === "url" ? "bg-white text-[#087fe5] shadow-sm" : "text-[#7c94a6]"}`}>URL Analysis</button>
                </div>
                <label className="mb-3 block text-sm font-black text-[#426175]">Suspicious content</label>
                <textarea
                  value={text}
                  maxLength={20000}
                  onChange={(event) => setText(event.target.value)}
                  placeholder={mode === "message" ? "Paste the suspicious message here..." : "Optional: add message context for URL analysis..."}
                  className="min-h-[220px] w-full resize-y rounded-[20px] border border-[#d5e7f1] bg-[#fbfdff] p-5 text-base leading-7 text-[#17364b] outline-none transition placeholder:text-[#a6b7c3] focus:border-[#58bde9] focus:ring-4 focus:ring-[#dff4ff]"
                />
                <div className="mt-1 text-right text-xs text-[#91a4b1]">{text.length}/20,000</div>
                <label className="mb-3 mt-5 block text-sm font-black text-[#426175]">Suspicious URL <span className="font-medium text-[#9aabba]">(optional)</span></label>
                <input
                  value={url}
                  maxLength={2048}
                  onChange={(event) => setUrl(event.target.value)}
                  placeholder="https://example.com/verify-account"
                  className="h-[58px] w-full rounded-[17px] border border-[#d5e7f1] bg-[#fbfdff] px-5 text-sm text-[#17364b] outline-none transition placeholder:text-[#a6b7c3] focus:border-[#58bde9] focus:ring-4 focus:ring-[#dff4ff]"
                />
                {notice && <div role="alert" className="mt-5 rounded-2xl border border-[#fed7aa] bg-[#fff7ed] px-5 py-4 text-sm font-semibold text-[#c2410c]">{notice}</div>}
                <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2 text-xs font-bold text-[#8ba0af]">
                    <span className="h-2.5 w-2.5 rounded-full bg-[#19bd8a]" />Analysis is processed by the backend API
                  </div>
                  <div className="flex gap-3">
                    <button onClick={clearScanner} className="rounded-xl border border-[#d7e8f0] px-4 py-3 text-sm font-black text-[#7c96a7] hover:bg-[#f6fbfe]">Clear</button>
                    <button onClick={() => void analyze()} disabled={loading} className="min-h-[50px] rounded-[15px] bg-gradient-to-r from-[#087fe5] to-[#22aeea] px-6 text-sm font-black text-white shadow-[0_14px_30px_rgba(8,127,229,.25)] transition hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-60">
                      {loading ? "Analyzing..." : "Analyze Threat"}
                    </button>
                  </div>
                </div>
              </section>
              {result && (
                <section className="mt-6 overflow-hidden rounded-[30px] border border-[#cfe5f1] bg-white shadow-[0_25px_90px_rgba(19,86,130,.10)]">
                  <div className="border-b border-[#e3eef4] bg-gradient-to-r from-[#fbfeff] to-[#f2faff] p-6 sm:p-8">
                    <div className="flex flex-col gap-6 xl:flex-row xl:items-center xl:justify-between">
                      <div className="flex flex-col items-start gap-5 sm:flex-row sm:items-center">
                        <div className="relative h-[190px] w-[190px] shrink-0">
                          <svg className="h-full w-full -rotate-90" viewBox="0 0 200 200">
                            <circle cx="100" cy="100" r="88" fill="none" stroke="#e8f1f5" strokeWidth="13" />
                            <circle cx="100" cy="100" r="88" fill="none" stroke={tone.ring} strokeWidth="13" strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={dashOffset} className="transition-all duration-1000" />
                          </svg>
                          <div className="absolute inset-0 grid place-items-center text-center">
                            <div>
                              <div className="text-6xl font-black leading-none text-[#17364b]">{riskScore}</div>
                              <div className="mt-2 text-[11px] font-black uppercase tracking-[.16em] text-[#8da2b0]">Risk Score</div>
                            </div>
                          </div>
                        </div>
                        <div>
                          <div className="mb-3 text-xs font-black uppercase tracking-[.16em] text-[#8ba0af]">Overall Assessment</div>
                          <RiskBadge level={riskLevel} />
                          <h3 className="mt-3 text-2xl font-black text-[#17364b]">{formatCategory(result.category)}</h3>
                          <p className="mt-3 max-w-xl text-sm leading-7 text-[#708899]">
                            {result.explanation || "Assessment generated from the returned risk score, category and detection signals."}
                          </p>
                          {result.analysis_id && <div className="mt-3 break-all text-xs font-bold text-[#91a4b1]">Scan ID: {result.analysis_id}</div>}
                        </div>
                      </div>
                      <div className="grid min-w-[220px] grid-cols-2 gap-3">
                        <div className="rounded-2xl border border-[#dcecf4] bg-white p-4">
                          <div className="text-[10px] font-black uppercase tracking-wider text-[#91a5b3]">Confidence</div>
                          <div className="mt-3 text-2xl font-black text-[#17364b]">{typeof result.confidence === "number" ? `${Math.round(result.confidence <= 1 ? result.confidence * 100 : result.confidence)}%` : " "}</div>
                          <div className="mt-1 text-[10px] text-[#91a5b3]">Model output score</div>
                        </div>
                        <div className="rounded-2xl border border-[#dcecf4] bg-white p-4">
                          <div className="text-[10px] font-black uppercase tracking-wider text-[#91a5b3]">Prediction</div>
                          <div className="mt-3 break-words text-xl font-black text-[#087fe5]">{result.prediction || result.binary_prediction || "Unavailable"}</div>
                          <div className="mt-1 text-[10px] text-[#91a5b3]">Classifier label</div>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="grid gap-7 p-6 sm:p-8 xl:grid-cols-2">
                    <div>
                      <h4 className="mb-4 text-lg font-black text-[#17364b]">Detection Signals</h4>
                      <div className="space-y-3">
                        {result.signals?.length ? result.signals.map((signal, index) => (
                          <div key={`${getSignalName(signal)}-${index}`} className="flex items-center justify-between gap-4 rounded-2xl border border-[#e0edf3] bg-[#fbfdff] p-4">
                            <div className="flex min-w-0 items-center gap-3">
                              <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-[#edf8fd] text-lg font-black text-[#0788c7]">!</div>
                              <span className="text-sm font-black text-[#426175]">{getSignalName(signal)}</span>
                            </div>
                            <span className="shrink-0 rounded-lg bg-[#f0f7fa] px-3 py-2 text-xs font-black text-[#638294]">{getSignalValue(signal)}</span>
                          </div>
                        )) : <EmptyState title="No signals returned" message="The backend did not return individual detection signals for this scan." />}
                      </div>
                    </div>
                    <div>
                      <h4 className="mb-4 text-lg font-black text-[#17364b]">Recommended Actions</h4>
                      <div className="space-y-3">
                        {result.recommendations?.length ? result.recommendations.map((recommendation, index) => (
                          <div key={`${recommendation}-${index}`} className="flex gap-3 rounded-2xl border border-[#dceee8] bg-[#f9fdfb] p-4">
                            <div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-[#e9faf3] text-sm font-black text-[#12a574]">{index + 1}</div>
                            <p className="pt-1 text-sm font-semibold leading-6 text-[#567184]">{recommendation}</p>
                          </div>
                        )) : <EmptyState title="No recommendations returned" message="The backend did not provide recommended actions for this result." />}
                      </div>
                    </div>
                  </div>
                  <div className="border-t border-[#e4eef3] bg-[#f9fcfe] p-6 sm:p-8">
                    <div className="flex flex-wrap items-center justify-between gap-4">
                      <div>
                        <div className="text-[10px] font-black uppercase tracking-[.15em] text-[#8ca2b1]">Campaign Intelligence</div>
                        <div className="mt-2 text-lg font-black text-[#17364b]">{result.campaign_id || result.campaign?.campaign_id || "No campaign ID returned"}</div>
                        <p className="mt-1 text-xs leading-5 text-[#78909f]">Campaign ID supplied by the backend for this analysis.</p>
                      </div>
                      <button onClick={() => setActiveNav("history")} className="rounded-xl border border-[#d7e8f0] bg-white px-4 py-3 text-sm font-black text-[#087fe5] hover:bg-[#f3faff]">View Scan History</button>
                    </div>
                  </div>
                </section>
              )}
              <section className="mt-6 grid gap-4 md:grid-cols-3">
                <FeatureCard icon="M" title="Multi-Signal Detection" text="Combines message patterns, URLs, categories and behavioral indicators." />
                <FeatureCard icon="R" title="Explainable Risk" text="Inspect the risk score, category, signals and recommended actions." />
                <FeatureCard icon="A" title="Real-Time Analysis" text="Analysis is submitted to the connected FastAPI backend." />
              </section>
            </>
          )}
          {activeNav === "dashboard" && (
            <div className="space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="text-sm text-[#78909f]">Statistics are read from the saved scan database.</p>
                <button onClick={() => void loadDashboardData()} disabled={refreshing} className="rounded-xl border border-[#d7e8f0] bg-white px-4 py-2.5 text-sm font-black text-[#087fe5] disabled:opacity-60">{refreshing ? "Refreshing..." : "? Refresh data"}</button>
              </div>
              <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
                <MetricCard label="Total Scans" value={stats?.total_scans ?? " "} description="All scans stored in the database" icon="T" />
                <MetricCard label="High / Critical" value={stats?.high_or_critical_scans ?? " "} description="Saved scans with elevated risk" icon="!" />
                <MetricCard label="Campaign IDs" value={campaigns.length} description="Distinct campaign IDs in the loaded history" icon="C" />
              </div>
              <div className="grid gap-6 xl:grid-cols-2">
                <Panel title="Risk Distribution" subtitle="Stored scans grouped by assigned risk level.">
                  {stats && Object.keys(stats.risk_distribution || {}).length > 0 ? (
                    <div className="space-y-4">
                      {Object.entries(stats.risk_distribution).sort((a, b) => b[1] - a[1]).map(([level, count]) => {
                        const total = Math.max(stats.total_scans, 1);
                        const risk = riskTone(level);
                        return <div key={level}>
                          <div className="mb-2 flex items-center justify-between gap-3 text-sm">
                            <span className="font-bold text-[#426175]">{level}</span>
                            <span className="font-black text-[#17364b]">{count} <span className="font-medium text-[#91a4b1]">({Math.round(count / total * 100)}%)</span></span>
                          </div>
                          <div className="h-3 overflow-hidden rounded-full bg-[#edf4f8]">
                            <div className="h-full rounded-full" style={{ width: `${Math.min(100, count / total * 100)}%`, background: risk.ring }} />
                          </div>
                        </div>;
                      })}
                    </div>
                  ) : <EmptyState title="No scan data yet" message="Run a scan to populate the risk distribution." />}
                </Panel>
                <Panel title="Category Distribution" subtitle="Categories returned by the backend classifier and rules.">
                  {stats && Object.keys(stats.category_distribution || {}).length > 0 ? (
                    <div className="space-y-3">
                      {Object.entries(stats.category_distribution).sort((a, b) => b[1] - a[1]).map(([category, count]) => (
                        <div key={category} className="flex items-center justify-between gap-4 rounded-xl border border-[#e0edf3] bg-[#fbfdff] p-4">
                          <span className="text-sm font-bold text-[#426175]">{formatCategory(category)}</span>
                          <span className="rounded-lg bg-[#eaf7ff] px-3 py-2 text-sm font-black text-[#087fe5]">{count}</span>
                        </div>
                      ))}
                    </div>
                  ) : <EmptyState title="No categories yet" message="Category counts will appear after scans are saved." />}
                </Panel>
              </div>
              <Panel title="Recent Scans" subtitle="Latest saved analysis records." action={<button onClick={() => setActiveNav("history")} className="text-sm font-black text-[#087fe5]">View all</button>}>
                {recentScans.length ? <ScanTable scans={recentScans.slice(0, 5)} onOpen={(id) => void openScan(id)} /> : <EmptyState title="No saved scans" message="Use Threat Scanner to analyze your first message or URL." />}
              </Panel>
            </div>
          )}
          {activeNav === "history" && (
            <div className="space-y-6">
              <Panel
                title="Scan History"
                subtitle={`Saved scan records   ${history?.total ?? 0} total`}
                action={<button onClick={() => void loadHistory(historyOffset)} disabled={refreshing} className="rounded-xl border border-[#d7e8f0] bg-white px-4 py-2.5 text-sm font-black text-[#087fe5] disabled:opacity-60">{refreshing ? "Loading..." : "? Refresh"}</button>}
              >
                {recentScans.length ? <ScanTable scans={recentScans} onOpen={(id) => void openScan(id)} /> : !pageError ? <EmptyState title="No scans in history" message="Analyzed messages will appear here after the backend saves them." /> : null}
                {history && history.total > 20 && (
                  <div className="mt-6 flex flex-wrap items-center justify-between gap-3 border-t border-[#e5eff4] pt-5">
                    <span className="text-xs font-bold text-[#78909f]">Showing {history.total === 0 ? 0 : historyOffset + 1} {Math.min(historyOffset + 20, history.total)} of {history.total}</span>
                    <div className="flex gap-2">
                      <button disabled={historyOffset <= 0 || refreshing} onClick={() => void loadHistory(Math.max(0, historyOffset - 20))} className="rounded-xl border border-[#d7e8f0] px-4 py-2 text-sm font-black text-[#527387] disabled:opacity-40">Previous</button>
                      <button disabled={historyOffset + 20 >= history.total || refreshing} onClick={() => void loadHistory(historyOffset + 20)} className="rounded-xl border border-[#d7e8f0] px-4 py-2 text-sm font-black text-[#527387] disabled:opacity-40">Next</button>
                    </div>
                  </div>
                )}
              </Panel>
              {detailLoading && <Panel title="Scan Details"><p className="text-sm text-[#78909f]">Loading saved scan details...</p></Panel>}
              {selectedScan && (
                <Panel title="Scan Details" subtitle={`Analysis ID: ${selectedScan.analysis_id}`} action={<button onClick={() => setSelectedScan(null)} className="rounded-lg border border-[#d7e8f0] px-3 py-2 text-xs font-black text-[#527387]">Close</button>}>
                  <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                    <MetricCard label="Risk Score" value={selectedScan.risk_score} description="Out of 100" icon="R" />
                    <div className="rounded-[22px] border border-[#d9eaf3] bg-white p-5"><div className="text-sm font-bold text-[#78909f]">Risk Level</div><div className="mt-4"><RiskBadge level={selectedScan.risk_level} /></div></div>
                    <div className="rounded-[22px] border border-[#d9eaf3] bg-white p-5"><div className="text-sm font-bold text-[#78909f]">Prediction</div><div className="mt-4 break-words text-xl font-black text-[#087fe5]">{selectedScan.prediction}</div></div>
                    <div className="rounded-[22px] border border-[#d9eaf3] bg-white p-5"><div className="text-sm font-bold text-[#78909f]">Category</div><div className="mt-4 text-sm font-black text-[#17364b]">{formatCategory(selectedScan.category)}</div></div>
                  </div>
                  <div className="mt-5 rounded-2xl border border-[#e0edf3] bg-[#fbfdff] p-5">
                    <div className="text-xs font-black uppercase tracking-wider text-[#78909f]">Original Input</div>
                    <p className="mt-3 whitespace-pre-wrap break-words text-sm leading-7 text-[#426175]">{selectedScan.input_text || selectedScan.input_preview || "No text was stored."}</p>
                    {!!selectedScan.urls?.length && <div className="mt-4 break-all text-sm text-[#087fe5]">{selectedScan.urls.join("\n")}</div>}
                    {selectedScan.ocr_text && <p className="mt-4 whitespace-pre-wrap text-sm text-[#426175]">OCR: {selectedScan.ocr_text}</p>}
                    <div className="mt-4 text-xs text-[#91a4b1]">{formatDate(selectedScan.timestamp)}</div>
                  </div>
                  <div className="mt-5 flex flex-wrap gap-3">
                    <button onClick={() => openScanInScanner(selectedScan)} className="rounded-xl bg-[#087fe5] px-5 py-3 text-sm font-black text-white">View in Scanner</button>
                    {selectedScan.campaign_id && <button onClick={() => setActiveNav("campaigns")} className="rounded-xl border border-[#d7e8f0] bg-white px-5 py-3 text-sm font-black text-[#087fe5]">View Campaign</button>}
                  </div>
                  {selectedScan.result?.signals?.length ? <div className="mt-6"><h3 className="mb-3 font-black text-[#17364b]">Stored Detection Signals</h3><div className="space-y-2">{selectedScan.result.signals.map((signal, index) => <div key={index} className="flex items-center justify-between gap-3 rounded-xl border border-[#e0edf3] p-3 text-sm"><span className="font-bold text-[#426175]">{getSignalName(signal)}</span><span className="text-[#78909f]">{getSignalValue(signal)}</span></div>)}</div></div> : null}
                </Panel>
              )}
            </div>
          )}
          {activeNav === "campaigns" && (
            <div className="space-y-6">
              <Panel title="Scam Campaigns" subtitle="Campaign groups derived from campaign IDs stored in scan history." action={<button onClick={() => void loadDashboardData()} disabled={refreshing} className="rounded-xl border border-[#d7e8f0] bg-white px-4 py-2.5 text-sm font-black text-[#087fe5] disabled:opacity-60">{refreshing ? "Loading..." : "? Refresh"}</button>}>
                <div className="mb-5 rounded-xl border border-[#d8eaf4] bg-[#f5fbff] p-4 text-sm leading-6 text-[#638294]">
                  Campaign groups below are based on stored campaign IDs. A shared ID indicates that the backend assigned the same identifier; it is not, by itself, proof of a confirmed real-world criminal campaign.
                </div>
                {campaigns.length ? (
                  <div className="grid gap-4 lg:grid-cols-2">
                    {campaigns.map((campaign) => {
                      const risk = campaign.highestRisk >= 80 ? "CRITICAL" : campaign.highestRisk >= 60 ? "HIGH" : campaign.highestRisk >= 35 ? "MEDIUM" : "LOW";
                      const related = (history?.items || []).filter((scan) => scan.campaign_id === campaign.campaign_id);
                      return (
                        <div key={campaign.campaign_id} className="rounded-[22px] border border-[#d9eaf3] bg-white p-5 shadow-sm">
                          <div className="flex items-start justify-between gap-3">
                            <div className="grid h-12 w-12 place-items-center rounded-2xl bg-[#eaf7ff] text-2xl font-black text-[#087fe5]">C</div>
                            <RiskBadge level={risk} />
                          </div>
                          <div className="mt-4 break-all text-xl font-black text-[#17364b]">{campaign.campaign_id}</div>
                          <div className="mt-2 text-sm text-[#78909f]">{formatCategory(campaign.category)}</div>
                          <div className="mt-5 grid grid-cols-2 gap-3">
                            <div className="rounded-xl bg-[#f6fafc] p-3"><div className="text-xs text-[#91a4b1]">Associated scans</div><div className="mt-1 text-xl font-black text-[#17364b]">{campaign.count}</div></div>
                            <div className="rounded-xl bg-[#f6fafc] p-3"><div className="text-xs text-[#91a4b1]">Highest risk score</div><div className="mt-1 text-xl font-black text-[#17364b]">{campaign.highestRisk}/100</div></div>
                          </div>
                          <div className="mt-4 text-xs text-[#91a4b1]">Latest associated scan: {formatDate(campaign.latest)}</div>
                          <div className="mt-4 space-y-2 border-t border-[#e5eff4] pt-4">
                            {related.slice(0, 3).map((scan) => (
                              <button key={scan.analysis_id} onClick={() => void openScan(scan.analysis_id)} className="flex w-full items-center justify-between gap-3 rounded-xl p-2 text-left hover:bg-[#f4faff]">
                                <span className="min-w-0"><span className="block truncate text-xs font-black text-[#527387]">{scan.analysis_id}</span><span className="mt-1 block truncate text-xs text-[#91a4b1]">{scan.input_preview || formatCategory(scan.category)}</span></span>
                                <span className="shrink-0 text-xs font-black text-[#087fe5]">Open</span>
                              </button>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : <EmptyState title="No campaign IDs recorded" message="Campaigns will appear when saved scans contain a campaign ID. This view does not generate sample campaigns or fabricate matches." />}
              </Panel>
              {selectedScan && (
                <Panel title="Selected Scan" subtitle={selectedScan.analysis_id}>
                  <p className="text-sm leading-7 text-[#527387]">{selectedScan.input_text || selectedScan.input_preview || "No input preview available."}</p>
                  <div className="mt-4 flex flex-wrap items-center gap-3"><RiskBadge level={selectedScan.risk_level} /><span className="text-sm font-black text-[#17364b]">{selectedScan.risk_score}/100</span><button onClick={() => openScanInScanner(selectedScan)} className="rounded-xl bg-[#087fe5] px-4 py-2 text-sm font-black text-white">Open in Scanner</button></div>
                </Panel>
              )}
            </div>
          )}
          {activeNav === "safety" && (
            <div className="space-y-6">
              <Panel title="Safety Toolkit" subtitle="Practical checks to perform before responding to suspicious messages.">
                <div className="grid gap-4 md:grid-cols-2">
                  {[
                    { icon: "L", title: "Inspect links carefully", text: "Check the complete domain, spelling and unexpected subdomains. Avoid opening links from unsolicited messages; visit the official website independently." },
                    { icon: "P", title: "Protect credentials", text: "Never share OTPs, UPI PINs, passwords or recovery codes with callers or through a link sent in an unsolicited message." },
                    { icon: "$", title: "Verify payment requests", text: "Do not approve an unexpected UPI collect request or pay a fee to unlock a supposed prize, job offer or refund without independent verification." },
                    { icon: "V", title: "Verify the sender", text: "Contact the organisation using the number or app listed on its official website, not contact details supplied in the suspicious message." },
                    { icon: "R", title: "Question unexpected rewards", text: "Unexpected lottery wins, guaranteed returns and job offers requiring advance payments are warning signs. Verify independently before acting." },
                    { icon: "E", title: "Preserve evidence", text: "Keep the original message, sender details, timestamps and transaction references. Avoid forwarding suspicious links to other people." },
                  ].map((item) => (
                    <div key={item.title} className="rounded-[22px] border border-[#d9eaf3] bg-[#fbfdff] p-5">
                      <div className="grid h-12 w-12 place-items-center rounded-2xl bg-[#eaf7ff] text-2xl">{item.icon}</div>
                      <h3 className="mt-4 font-black text-[#17364b]">{item.title}</h3>
                      <p className="mt-2 text-sm leading-7 text-[#78909f]">{item.text}</p>
                    </div>
                  ))}
                </div>
              </Panel>
              <Panel title="Report a missed scam" subtitle="If ScamShield missed a scam or you found suspicious content, submit it for internal review. Do not include passwords, OTPs, UPI PINs or other secrets.">
                <div className="grid gap-4">
                  <div>
                    <label htmlFor="report-type" className="mb-2 block text-sm font-black text-[#426175]">Report type</label>
                    <select
                      id="report-type"
                      value={reportType}
                      onChange={(event) => setReportType(event.target.value)}
                      className="h-12 w-full rounded-xl border border-[#d5e7f1] bg-[#fbfdff] px-4 text-sm text-[#17364b] outline-none focus:border-[#58bde9]"
                    >
                      <option value="MISSED_DETECTION">ScamShield missed a scam</option>
                      <option value="SUSPICIOUS_URL">Suspicious URL</option>
                      <option value="SUSPICIOUS_MESSAGE">Suspicious message</option>
                      <option value="MALWARE_CONCERN">Malware concern</option>
                      <option value="OTHER">Other concern</option>
                    </select>
                  </div>
                  <div>
                    <label htmlFor="report-description" className="mb-2 block text-sm font-black text-[#426175]">What happened? (optional if content is supplied)</label>
                    <textarea
                      id="report-description"
                      value={reportDescription}
                      maxLength={3000}
                      onChange={(event) => setReportDescription(event.target.value)}
                      placeholder="Describe why you think this is suspicious..."
                      className="min-h-[100px] w-full rounded-xl border border-[#d5e7f1] bg-[#fbfdff] p-4 text-sm leading-6 text-[#17364b] outline-none focus:border-[#58bde9]"
                    />
                  </div>
                  <div>
                    <label htmlFor="suspicious-content" className="mb-2 block text-sm font-black text-[#426175]">Suspicious message or URL</label>
                    <textarea
                      id="suspicious-content"
                      value={suspiciousContent}
                      maxLength={10000}
                      onChange={(event) => setSuspiciousContent(event.target.value)}
                      placeholder="Paste the suspicious message or URL. Remove any private credentials first."
                      className="min-h-[120px] w-full rounded-xl border border-[#d5e7f1] bg-[#fbfdff] p-4 text-sm leading-6 text-[#17364b] outline-none focus:border-[#58bde9]"
                    />
                  </div>
                  {reportError && <div role="alert" className="rounded-xl border border-[#fecaca] bg-[#fff1f2] p-4 text-sm font-semibold text-[#b91c1c]">{reportError}</div>}
                  {reportNotice && <div role="status" className="break-words rounded-xl border border-[#bbf7d0] bg-[#f0fdf4] p-4 text-sm font-semibold leading-6 text-[#166534]">{reportNotice}</div>}
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <p className="max-w-xl text-xs leading-5 text-[#91a4b1]">This saves a report to ScamShield only; it does not submit an official police or cybercrime complaint.</p>
                    <button
                      type="button"
                      onClick={() => void submitMissedScamReport()}
                      disabled={submittingReport}
                      className="rounded-xl bg-gradient-to-r from-[#087fe5] to-[#22aeea] px-5 py-3 text-sm font-black text-white shadow-sm disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {submittingReport ? "Submitting..." : "Submit report"}
                    </button>
                  </div>
                  <div className="flex flex-wrap gap-3 border-t border-[#e5eff4] pt-4">
                    <a href="https://www.cybercrime.gov.in/Webform/cyber_suspect.aspx" target="_blank" rel="noreferrer" className="text-sm font-black text-[#087fe5] underline underline-offset-4">Report suspect on official portal</a>
                    <span className="text-sm text-[#78909f]">Financial cyber fraud in India: call 1930 immediately.</span>
                  </div>
                </div>
              </Panel>
              <Panel title="If you suspect financial fraud" subtitle="Take prompt action if you have already transferred money or disclosed sensitive information.">
                <ol className="space-y-4">
                  {[
                    "Contact your bank or payment provider immediately through an official channel and ask about securing the account or disputing the transaction.",
                    "In India, report suspected cyber financial fraud promptly through the official cybercrime helpline 1930 or the National Cyber Crime Reporting Portal at cybercrime.gov.in.",
                    "Change compromised passwords from a trusted device, revoke suspicious sessions and enable multi-factor authentication where available.",
                    "Preserve transaction IDs, messages, phone numbers and screenshots for the relevant bank or authorities.",
                  ].map((item, index) => <li key={item} className="flex gap-4"><span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-[#eaf7ff] text-sm font-black text-[#087fe5]">{index + 1}</span><p className="pt-1 text-sm leading-7 text-[#527387]">{item}</p></li>)}
                </ol>
              </Panel>
              <p className="px-2 text-xs leading-6 text-[#91a4b1]">ScamShield provides automated risk indicators, not a guarantee of safety. Verify high-impact decisions independently.</p>
            </div>
          )}
          <footer className="flex flex-col gap-3 px-2 py-8 text-[11px] font-bold text-[#91a4b1] sm:flex-row sm:items-center sm:justify-between">
            <div>ScamShield AI Threat Intelligence Platform</div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-[#19bd8a]" />
              BACKEND-DRIVEN DATA <span className="text-[#c2d0d8]"> </span> FASTAPI
            </div>
          </footer>
        </section>
      </div>
    </main>
  );
}
function ScanTable({
  scans,
  onOpen,
}: {
  scans: ScanItem[];
  onOpen: (id: string) => void;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[680px] border-collapse text-left">
        <thead>
          <tr className="border-b border-[#e3eef4] text-[10px] font-black uppercase tracking-wider text-[#91a4b1]">
            <th className="px-3 py-3">Scan / Input</th>
            <th className="px-3 py-3">Category</th>
            <th className="px-3 py-3">Risk</th>
            <th className="px-3 py-3">Prediction</th>
            <th className="px-3 py-3">Details</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.analysis_id} className="border-b border-[#edf3f7] last:border-0 hover:bg-[#fbfdff]">
              <td className="max-w-[300px] px-3 py-4">
                <div className="truncate text-xs font-black text-[#426175]">{scan.analysis_id}</div>
                <div className="mt-1 max-w-[270px] truncate text-xs text-[#91a4b1]">{scan.input_preview || (scan.urls || []).join(", ") || "No text preview"}</div>
                <div className="mt-1 text-[10px] text-[#a0b0bb]">{formatDate(scan.timestamp)}</div>
              </td>
              <td className="px-3 py-4 text-xs font-bold text-[#527387]">{formatCategory(scan.category)}</td>
              <td className="px-3 py-4">
                <RiskBadge level={scan.risk_level} />
                <div className="mt-1 text-xs font-black text-[#17364b]">{scan.risk_score}/100</div>
              </td>
              <td className="px-3 py-4 text-xs font-black text-[#087fe5]">{scan.prediction || "UNKNOWN"}</td>
              <td className="px-3 py-4">
                <button onClick={() => onOpen(scan.analysis_id)} className="rounded-lg border border-[#d7e8f0] px-3 py-2 text-xs font-black text-[#087fe5] hover:bg-[#eef8ff]">Open</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function FeatureCard({
  icon,
  title,
  text,
}: {
  icon: string;
  title: string;
  text: string;
}) {
  return (
    <div className="group rounded-[24px] border border-[#d4e8f2] bg-white/90 p-6 shadow-[0_18px_55px_rgba(19,86,130,.08)] transition duration-300 hover:-translate-y-1 hover:shadow-[0_25px_70px_rgba(19,86,130,.13)]">
      <div className="mb-5 grid h-12 w-12 place-items-center rounded-2xl bg-[#ebf8ff] text-2xl text-[#087fe5]">{icon}</div>
      <h3 className="text-base font-black text-[#17364b]">{title}</h3>
      <p className="mt-3 text-sm leading-6 text-[#78909f]">{text}</p>
    </div>
  );
}
