import React, { useMemo, useState } from "react";

const PROVIDERS = [
  { name: "Microsoft 365", include: "spf.protection.outlook.com", category: "Productivity" },
  { name: "Google Workspace", include: "_spf.google.com", category: "Productivity" },
  { name: "Proofpoint", include: "spf.protection.proofpoint.com", category: "Security" },
  { name: "Mailchimp", include: "servers.mcsv.net", category: "Marketing" },
  { name: "SendGrid", include: "sendgrid.net", category: "Transactional" },
  { name: "Salesforce", include: "_spf.salesforce.com", category: "CRM" },
  { name: "Zendesk", include: "mail.zendesk.com", category: "Support" },
  { name: "HubSpot", include: "spf.hubspotemail.net", category: "Marketing" },
];

function uniqueClean(values) {
  return [...new Set(values.map(v => String(v).trim()).filter(Boolean))];
}

function cleanTxtRecord(value) {
  return String(value || "")
    .replace(/^"|"$/g, "")
    .replace(/"\s+"/g, "")
    .trim();
}

function parseSPF(spf) {
  const clean = cleanTxtRecord(spf);
  const parts = clean.split(/\s+/).filter(Boolean);

  return {
    raw: clean,
    includes: uniqueClean(parts.filter(p => p.toLowerCase().startsWith("include:")).map(p => p.slice(8))),
    ip4: uniqueClean(parts.filter(p => p.toLowerCase().startsWith("ip4:")).map(p => p.slice(4))),
    ip6: uniqueClean(parts.filter(p => p.toLowerCase().startsWith("ip6:")).map(p => p.slice(4))),
    mx: parts.some(p => p.toLowerCase() === "mx"),
    a: parts.some(p => p.toLowerCase() === "a"),
    policy: parts.find(p => ["~all", "-all", "?all", "+all"].includes(p.toLowerCase())) || "~all",
    advanced: uniqueClean(parts.filter(p => {
      const lower = p.toLowerCase();
      return lower !== "v=spf1" &&
        lower !== "mx" &&
        lower !== "a" &&
        !lower.startsWith("include:") &&
        !lower.startsWith("ip4:") &&
        !lower.startsWith("ip6:") &&
        !["~all", "-all", "?all", "+all"].includes(lower);
    })),
  };
}

function buildSPF({ mx, a, includes, ip4, ip6, advanced, policy }) {
  return [
    "v=spf1",
    ...(mx ? ["mx"] : []),
    ...(a ? ["a"] : []),
    ...uniqueClean(ip4).map(ip => `ip4:${ip}`),
    ...uniqueClean(ip6).map(ip => `ip6:${ip}`),
    ...uniqueClean(includes).map(i => `include:${i}`),
    ...uniqueClean(advanced),
    policy || "~all",
  ].join(" ");
}

export default function App() {
  const [domain, setDomain] = useState("example.com");
  const [existingRecords, setExistingRecords] = useState([]);
  const [lookupStatus, setLookupStatus] = useState("idle");
  const [lookupMessage, setLookupMessage] = useState("");
  const [selectedProviders, setSelectedProviders] = useState(["spf.protection.outlook.com"]);
  const [customInclude, setCustomInclude] = useState("");
  const [customIncludes, setCustomIncludes] = useState([]);
  const [ipInput, setIpInput] = useState("");
  const [manualIp4, setManualIp4] = useState([]);
  const [policy, setPolicy] = useState("~all");
  const [mergeExisting, setMergeExisting] = useState(true);
  const [copied, setCopied] = useState(false);

  const existing = useMemo(() => {
    return existingRecords.length ? parseSPF(existingRecords[0]) : {
      raw: "",
      includes: [],
      ip4: [],
      ip6: [],
      mx: true,
      a: false,
      policy: "~all",
      advanced: [],
    };
  }, [existingRecords]);

  const includes = useMemo(() => {
    return uniqueClean([
      ...(mergeExisting ? existing.includes : []),
      ...selectedProviders,
      ...customIncludes,
    ]);
  }, [mergeExisting, existing.includes, selectedProviders, customIncludes]);

  const ip4 = useMemo(() => uniqueClean([...(mergeExisting ? existing.ip4 : []), ...manualIp4]), [mergeExisting, existing.ip4, manualIp4]);
  const ip6 = useMemo(() => uniqueClean(mergeExisting ? existing.ip6 : []), [mergeExisting, existing.ip6]);
  const advanced = useMemo(() => uniqueClean(mergeExisting ? existing.advanced : []), [mergeExisting, existing.advanced]);

  const record = useMemo(() => buildSPF({
    mx: mergeExisting ? existing.mx || true : true,
    a: mergeExisting ? existing.a : false,
    includes,
    ip4,
    ip6,
    advanced,
    policy,
  }), [mergeExisting, existing, includes, ip4, ip6, advanced, policy]);

  const lookupCount = useMemo(() => {
    const advancedLookups = advanced.filter(x => {
      const lower = x.toLowerCase();
      return lower === "ptr" || lower.startsWith("exists:") || lower.startsWith("redirect=");
    }).length;
    return includes.length + 1 + (mergeExisting && existing.a ? 1 : 0) + advancedLookups;
  }, [includes.length, mergeExisting, existing.a, advanced]);

  const warnings = useMemo(() => {
    const items = [];
    if (existingRecords.length > 1) items.push("Multiple SPF records found. Merge them into one TXT record before publishing.");
    if (lookupCount > 10) items.push("SPF exceeds the 10 DNS lookup limit and may return PermError.");
    if (record.length > 255) items.push("Record is longer than 255 characters. Verify your DNS provider splits TXT strings correctly.");
    if (policy === "+all") items.push("+all allows any server to send mail for this domain. Avoid this policy.");
    if (advanced.length) items.push(`Advanced mechanisms preserved: ${advanced.join(" ")}`);
    return items;
  }, [existingRecords.length, lookupCount, record.length, policy, advanced]);

  async function lookupSPF() {
    const cleanDomain = domain.trim();
    if (!cleanDomain) return;

    setLookupStatus("loading");
    setLookupMessage("");
    setExistingRecords([]);

    try {
      const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(cleanDomain)}&type=TXT`);
      if (!res.ok) throw new Error("DNS lookup failed");
      const data = await res.json();
      const records = (data.Answer || [])
        .map(a => cleanTxtRecord(a.data))
        .filter(txt => txt.toLowerCase().startsWith("v=spf1"));

      setExistingRecords(records);

      if (!records.length) {
        setLookupStatus("warning");
        setLookupMessage("No SPF record found. Create a new TXT record using the generated value below.");
        return;
      }

      const parsed = parseSPF(records[0]);
      setPolicy(parsed.policy);
      setLookupStatus("success");
      setLookupMessage(`${records.length} SPF record${records.length > 1 ? "s" : ""} found for ${cleanDomain}.`);
    } catch {
      setLookupStatus("error");
      setLookupMessage("Lookup failed. Check the domain name and try again.");
    }
  }

  function toggleProvider(include) {
    setSelectedProviders(prev => prev.includes(include) ? prev.filter(x => x !== include) : [...prev, include]);
  }

  function addCustomInclude() {
    const value = customInclude.trim().replace(/^include:/i, "");
    if (!value) return;
    setCustomIncludes(prev => uniqueClean([...prev, value]));
    setCustomInclude("");
  }

  function addIP() {
    const value = ipInput.trim().replace(/^ip4:/i, "");
    if (!value) return;
    setManualIp4(prev => uniqueClean([...prev, value]));
    setIpInput("");
  }

  async function copyRecord() {
    await navigator.clipboard.writeText(record);
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  }

  return (
    <div style={styles.page}>
      <header style={styles.header}>
        <div>
          <div style={styles.brand}>MailAuth Tools</div>
          <h1 style={styles.title}>SPF Lookup + Merge</h1>
          <p style={styles.subtitle}>Check an existing SPF record, add approved senders, and generate a clean DNS TXT value.</p>
        </div>
        <div style={styles.headerBadge}>SPF Builder</div>
      </header>

      <main style={styles.grid}>
        <section style={styles.leftColumn}>
          <Card title="Domain Lookup" description="Enter a domain to find the current SPF TXT record.">
            <div style={styles.searchRow}>
              <input style={styles.searchInput} value={domain} onChange={e => setDomain(e.target.value)} placeholder="contoso.com" />
              <button style={styles.primaryButton} onClick={lookupSPF} disabled={lookupStatus === "loading"}>
                {lookupStatus === "loading" ? "Checking..." : "Lookup SPF"}
              </button>
            </div>
            {lookupMessage && <Status type={lookupStatus}>{lookupMessage}</Status>}
            {existingRecords.length > 0 && (
              <div style={styles.recordList}>
                {existingRecords.map((spf, index) => (
                  <div key={`${spf}-${index}`} style={styles.smallCode}>{spf}</div>
                ))}
                <label style={styles.inlineCheck}>
                  <input type="checkbox" checked={mergeExisting} onChange={e => setMergeExisting(e.target.checked)} />
                  Merge with existing SPF record
                </label>
              </div>
            )}
          </Card>

          <Card title="Add Approved Senders" description="Select common mail platforms or add custom include mechanisms.">
            <div style={styles.providerGrid}>
              {PROVIDERS.map(provider => (
                <button
                  key={provider.include}
                  style={{ ...styles.providerButton, ...(selectedProviders.includes(provider.include) ? styles.providerActive : {}) }}
                  onClick={() => toggleProvider(provider.include)}
                >
                  <strong>{provider.name}</strong>
                  <span>{provider.category}</span>
                  <code>include:{provider.include}</code>
                </button>
              ))}
            </div>

            <div style={styles.inputGroup}>
              <label style={styles.label}>Custom include</label>
              <div style={styles.inlineRow}>
                <input style={styles.input} value={customInclude} onChange={e => setCustomInclude(e.target.value)} placeholder="spf.vendor.com" />
                <button style={styles.secondaryButton} onClick={addCustomInclude}>Add</button>
              </div>
              <TagList items={customIncludes} remove={item => setCustomIncludes(prev => prev.filter(x => x !== item))} prefix="include:" />
            </div>
          </Card>
        </section>

        <aside style={styles.rightColumn}>
          <Card title="Manual Senders" description="Add static IPv4 sources and choose an SPF policy.">
            <label style={styles.label}>IPv4 sender</label>
            <div style={styles.inlineRow}>
              <input style={styles.input} value={ipInput} onChange={e => setIpInput(e.target.value)} placeholder="203.0.113.10 or 203.0.113.0/24" />
              <button style={styles.secondaryButton} onClick={addIP}>Add</button>
            </div>
            <TagList items={manualIp4} remove={item => setManualIp4(prev => prev.filter(x => x !== item))} prefix="ip4:" />

            <div style={styles.inputGroup}>
              <label style={styles.label}>Policy</label>
              <select style={styles.input} value={policy} onChange={e => setPolicy(e.target.value)}>
                <option value="~all">Soft fail (~all)</option>
                <option value="-all">Hard fail (-all)</option>
                <option value="?all">Neutral (?all)</option>
                <option value="+all">Allow all (+all)</option>
              </select>
            </div>
          </Card>

          <Card title="SPF Health" description="Quick checks before publishing.">
            <div style={styles.metrics}>
              <Metric label="DNS Lookups" value={`${lookupCount}/10`} danger={lookupCount > 10} />
              <Metric label="Includes" value={includes.length} />
              <Metric label="Length" value={record.length} danger={record.length > 255} />
            </div>
            {warnings.length ? warnings.map(w => <div key={w} style={styles.warning}>⚠ {w}</div>) : <div style={styles.good}>✓ No obvious SPF issues detected.</div>}
          </Card>

          <Card title="Generated TXT Record" description="Publish this value as a TXT record at the root of your domain.">
            <div style={styles.dnsBox}>
              <div><strong>Type:</strong> TXT</div>
              <div><strong>Host:</strong> @</div>
              <div><strong>Domain:</strong> {domain || "example.com"}</div>
            </div>
            <pre style={styles.largeCode}>{record}</pre>
            <button style={styles.copyButton} onClick={copyRecord}>{copied ? "Copied!" : "Copy SPF Record"}</button>
          </Card>
        </aside>
      </main>
    </div>
  );
}

function Card({ title, description, children }) {
  return (
    <div style={styles.card}>
      <h2 style={styles.cardTitle}>{title}</h2>
      <p style={styles.cardDescription}>{description}</p>
      {children}
    </div>
  );
}

function Status({ type, children }) {
  const map = {
    success: styles.success,
    warning: styles.notice,
    error: styles.error,
    loading: styles.notice,
    idle: styles.notice,
  };
  return <div style={{ ...styles.status, ...map[type] }}>{children}</div>;
}

function TagList({ items, remove, prefix }) {
  if (!items.length) return null;
  return (
    <div style={styles.tags}>
      {items.map(item => (
        <span key={item} style={styles.tag}>
          {prefix}{item}
          <button style={styles.tagButton} onClick={() => remove(item)}>×</button>
        </span>
      ))}
    </div>
  );
}

function Metric({ label, value, danger }) {
  return (
    <div style={{ ...styles.metric, ...(danger ? styles.metricDanger : {}) }}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

const styles = {
  page: { minHeight: "100vh", background: "#f4f6f8", color: "#1f2937", fontFamily: "Inter, Arial, sans-serif", padding: "28px" },
  header: { maxWidth: 1180, margin: "0 auto 24px", background: "linear-gradient(135deg,#0f172a,#1e3a8a)", color: "white", borderRadius: 18, padding: "30px 34px", display: "flex", justifyContent: "space-between", gap: 20, alignItems: "center", boxShadow: "0 14px 35px rgba(15,23,42,.22)" },
  brand: { textTransform: "uppercase", letterSpacing: 2, fontSize: 12, opacity: .8, fontWeight: 700 },
  title: { margin: "8px 0", fontSize: 42, lineHeight: 1 },
  subtitle: { margin: 0, color: "#cbd5e1", maxWidth: 700, fontSize: 16 },
  headerBadge: { background: "rgba(255,255,255,.12)", border: "1px solid rgba(255,255,255,.2)", padding: "10px 14px", borderRadius: 999, fontWeight: 700 },
  grid: { maxWidth: 1180, margin: "0 auto", display: "grid", gridTemplateColumns: "1.3fr .9fr", gap: 22 },
  leftColumn: { display: "flex", flexDirection: "column", gap: 20 },
  rightColumn: { display: "flex", flexDirection: "column", gap: 20 },
  card: { background: "white", border: "1px solid #e5e7eb", borderRadius: 16, padding: 22, boxShadow: "0 8px 22px rgba(15,23,42,.06)" },
  cardTitle: { margin: 0, fontSize: 22 },
  cardDescription: { marginTop: 6, marginBottom: 18, color: "#6b7280", lineHeight: 1.45 },
  searchRow: { display: "flex", gap: 10 },
  searchInput: { flex: 1, fontSize: 17, padding: "13px 14px", border: "1px solid #cbd5e1", borderRadius: 10 },
  inputGroup: { marginTop: 20 },
  input: { width: "100%", boxSizing: "border-box", fontSize: 15, padding: "11px 12px", border: "1px solid #cbd5e1", borderRadius: 10 },
  label: { display: "block", fontWeight: 700, marginBottom: 8 },
  inlineRow: { display: "flex", gap: 8 },
  primaryButton: { background: "#2563eb", color: "white", border: 0, borderRadius: 10, padding: "0 18px", fontWeight: 700, cursor: "pointer", whiteSpace: "nowrap" },
  secondaryButton: { background: "#111827", color: "white", border: 0, borderRadius: 10, padding: "0 14px", fontWeight: 700, cursor: "pointer" },
  providerGrid: { display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 10 },
  providerButton: { textAlign: "left", background: "#f9fafb", border: "1px solid #e5e7eb", borderRadius: 12, padding: 13, cursor: "pointer", display: "flex", flexDirection: "column", gap: 4 },
  providerActive: { background: "#eff6ff", border: "1px solid #2563eb", boxShadow: "inset 0 0 0 1px #2563eb" },
  recordList: { marginTop: 14 },
  inlineCheck: { display: "flex", gap: 8, alignItems: "center", marginTop: 12, fontWeight: 700 },
  smallCode: { background: "#f3f4f6", border: "1px solid #e5e7eb", padding: 12, borderRadius: 10, fontFamily: "Consolas, monospace", wordBreak: "break-all", marginTop: 8 },
  largeCode: { background: "#0f172a", color: "#e2e8f0", padding: 16, borderRadius: 12, fontFamily: "Consolas, monospace", whiteSpace: "pre-wrap", wordBreak: "break-all", lineHeight: 1.5 },
  dnsBox: { background: "#f9fafb", border: "1px solid #e5e7eb", borderRadius: 12, padding: 12, display: "grid", gap: 6, marginBottom: 12, fontSize: 14 },
  copyButton: { width: "100%", background: "#16a34a", color: "white", border: 0, borderRadius: 10, padding: 12, fontWeight: 800, cursor: "pointer" },
  metrics: { display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 8, marginBottom: 14 },
  metric: { background: "#f9fafb", border: "1px solid #e5e7eb", borderRadius: 12, padding: 10, display: "flex", flexDirection: "column", gap: 4 },
  metricDanger: { background: "#fff7ed", borderColor: "#fb923c" },
  warning: { background: "#fff7ed", border: "1px solid #fb923c", color: "#9a3412", padding: 10, borderRadius: 10, marginTop: 8, lineHeight: 1.35 },
  good: { background: "#ecfdf5", border: "1px solid #86efac", color: "#166534", padding: 10, borderRadius: 10 },
  status: { marginTop: 12, borderRadius: 10, padding: 12, fontWeight: 700 },
  success: { background: "#ecfdf5", color: "#166534", border: "1px solid #86efac" },
  notice: { background: "#eff6ff", color: "#1e40af", border: "1px solid #bfdbfe" },
  error: { background: "#fef2f2", color: "#991b1b", border: "1px solid #fecaca" },
  tags: { display: "flex", flexWrap: "wrap", gap: 8, marginTop: 10 },
  tag: { background: "#eef2ff", color: "#3730a3", padding: "7px 9px", borderRadius: 999, fontFamily: "Consolas, monospace", fontSize: 13 },
  tagButton: { marginLeft: 8, border: 0, background: "transparent", cursor: "pointer", color: "#3730a3", fontWeight: 900 },
};
