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

function buildDMARC({ policy, rua, ruf, pct, alignmentSpf, alignmentDkim, subdomainPolicy, failureOptions }) {
  const parts = ["v=DMARC1", `p=${policy}`];
  if (subdomainPolicy) parts.push(`sp=${subdomainPolicy}`);
  if (rua) parts.push(`rua=mailto:${rua}`);
  if (ruf) parts.push(`ruf=mailto:${ruf}`);
  if (pct !== "100") parts.push(`pct=${pct}`);
  parts.push(`aspf=${alignmentSpf}`);
  parts.push(`adkim=${alignmentDkim}`);
  if (failureOptions) parts.push(`fo=${failureOptions}`);
  return parts.join("; ");
}

function parseDMARC(record) {
  const clean = cleanTxtRecord(record);
  const parts = clean.split(";").map(p => p.trim()).filter(Boolean);
  const parsed = {};
  parts.forEach(part => {
    const [key, ...rest] = part.split("=");
    parsed[key.toLowerCase()] = rest.join("=");
  });
  return parsed;
}

export default function App() {
  const [activeTool, setActiveTool] = useState("mx");
  const [theme, setTheme] = useState("light");
  const themeVars = theme === "dark" ? darkThemeVars : lightThemeVars;

  return (
    <div style={{ ...styles.page, ...themeVars }}>
      <header style={styles.header}>
        <div style={styles.logoWrap}>
          <div style={styles.logoMark}>✉</div>
          <div>
            <div style={styles.brand}>MailAuth Tools</div>
            <h1 style={styles.title}>Email DNS Toolkit</h1>
            <p style={styles.subtitle}>Build, inspect, analyze, and publish SPF, DMARC, DKIM, MX, and email header authentication data from one clean admin console.</p>
          </div>
        </div>
        <div style={styles.headerActions}>
          <button style={styles.themeButton} onClick={() => setTheme(theme === "light" ? "dark" : "light")}>{theme === "light" ? "🌙 Dark" : "☀️ Light"}</button>
          <div style={styles.headerBadge}>MX · SPF · DMARC · DKIM · Analyze · Health</div>
        </div>
      </header>

      <nav style={styles.tabs}>
        {[
          ["mx", "📬", "MX Records"],
          ["health", "🌐", "DNS Health"],
          ["spf", "🛡", "SPF Lookup"],
          ["dmarc", "📊", "DMARC Builder"],
          ["dkim", "🔑", "DKIM Helper"],
          ["blacklist", "🚫", "Blacklist"],
          ["score", "⭐", "Domain Score"],
          ["reports", "📄", "DMARC Reports"],
          ["smtp", "🔐", "SMTP/TLS"],
          ["propagation", "📡", "Propagation"],
          ["analyzer", "🔎", "Message Analyzer"],
        ].map(([id, icon, label]) => (
          <button key={id} style={{ ...styles.tab, ...(activeTool === id ? styles.tabActive : {}) }} onClick={() => setActiveTool(id)}>
            <span style={styles.tabIcon}>{icon}</span>
            <span>{label}</span>
          </button>
        ))}
      </nav>

      {activeTool === "mx" && <MXTool />}
      {activeTool === "health" && <DNSHealthTool />}
      {activeTool === "spf" && <SPFTool />}
      {activeTool === "dmarc" && <DMARCTool />}
      {activeTool === "dkim" && <DKIMTool />}
      {activeTool === "blacklist" && <BlacklistTool />}
      {activeTool === "score" && <DomainScoreTool />}
      {activeTool === "reports" && <DMARCReportAnalyzer />}
      {activeTool === "smtp" && <SMTPTLSTool />}
      {activeTool === "propagation" && <DNSPropagationTool />}
      {activeTool === "analyzer" && <MessageAnalyzerTool />}
    </div>
  );
}

function SPFTool() {
  // --- Monetization: simple client-side gate (Step 1) ---
  const [isPro, setIsPro] = useState(() => localStorage.getItem("pro_unlocked") === "true");
  function unlockPro() {
    localStorage.setItem("pro_unlocked", "true");
    setIsPro(true);
  }

  function exportReport() {
    const payload = {
      domain,
      generatedSPF: record,
      includes,
      ip4,
      policy,
      lookupCount,
      warnings,
      timestamp: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${domain || "spf"}-audit.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

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
  const [spfExpandLoading, setSpfExpandLoading] = useState(false);
  const [spfExpandResult, setSpfExpandResult] = useState(null);

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

  const includes = useMemo(() => uniqueClean([...(mergeExisting ? existing.includes : []), ...selectedProviders, ...customIncludes]), [mergeExisting, existing.includes, selectedProviders, customIncludes]);
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

  async function expandSPF() {
    const cleanDomain = domain.trim();
    if (!cleanDomain) return;
    setSpfExpandLoading(true);
    setSpfExpandResult(null);
    try {
      const result = await expandSPFDomain(cleanDomain);
      setSpfExpandResult(result);
    } catch {
      setSpfExpandResult({ domain: cleanDomain, records: [], includes: [], ip4: [], ip6: [], errors: ["SPF expansion failed."], lookupCount: 0, flattened: "" });
    } finally {
      setSpfExpandLoading(false);
    }
  }

  return (
    <main style={styles.grid}>
      <section style={styles.leftColumn}>
        <Card title="Domain Lookup" description="Enter a domain to find the current SPF TXT record.">
          <div style={styles.searchRow}>
            <input style={styles.searchInput} value={domain} onChange={e => setDomain(e.target.value)} placeholder="contoso.com" />
            <button style={styles.primaryButton} onClick={lookupSPF} disabled={lookupStatus === "loading"}>{lookupStatus === "loading" ? "Checking..." : "Lookup SPF"}</button>
          </div>
          {lookupMessage && <Status type={lookupStatus}>{lookupMessage}</Status>}
          {existingRecords.length > 0 && (
            <div style={styles.recordList}>
              {existingRecords.map((spf, index) => <div key={`${spf}-${index}`} style={styles.smallCode}>{spf}</div>)}
              <label style={styles.inlineCheck}>
                <input type="checkbox" checked={mergeExisting} onChange={e => setMergeExisting(e.target.checked)} /> Merge with existing SPF record
              </label>
            </div>
          )}
        </Card>

        <Card title="Add Approved Senders" description="Select common mail platforms or add custom include mechanisms.">
          <div style={styles.providerGrid}>
            {PROVIDERS.map(provider => (
              <button key={provider.include} style={{ ...styles.providerButton, ...(selectedProviders.includes(provider.include) ? styles.providerActive : {}) }} onClick={() => toggleProvider(provider.include)}>
                <strong>{provider.name}</strong>
                <span>{provider.category}</span>
                <code style={styles.providerCode}>include:{provider.include}</code>
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
          <div style={{ display: "flex", gap: 10, marginBottom: 10 }}>
            {isPro ? (
              <button style={styles.primaryButton} onClick={exportReport}>⬇ Export Audit Report</button>
            ) : (
              <button style={{ ...styles.primaryButton, background: "#9333ea" }} onClick={unlockPro}>🔒 Unlock Export ($5)</button>
            )}
          </div>
          <div style={styles.dnsBox}>
            <div><strong>Type:</strong> TXT</div>
            <div><strong>Host:</strong> @</div>
            <div><strong>Domain:</strong> {domain || "example.com"}</div>
          </div>
          <pre style={styles.largeCode}>{record}</pre>
          <button style={styles.copyButton} onClick={copyRecord}>{copied ? "Copied!" : "Copy SPF Record"}</button>
        </Card>

        <Card title="SPF Recursive Expansion" description="Resolve include mechanisms recursively to see actual IP sources and DNS lookup pressure.">
          <button style={styles.copyButton} onClick={expandSPF}>{spfExpandLoading ? "Expanding..." : "Expand SPF Includes"}</button>
          {spfExpandResult && (
            <div style={{ marginTop: 12 }}>
              <div style={styles.metrics}>
                <Metric label="Lookups" value={spfExpandResult.lookupCount} danger={spfExpandResult.lookupCount > 10} />
                <Metric label="Includes" value={spfExpandResult.includes.length} />
                <Metric label="IP Ranges" value={spfExpandResult.ip4.length + spfExpandResult.ip6.length} />
              </div>
              {spfExpandResult.lookupCount > 10 && <div style={styles.warning}>⚠ Expanded SPF exceeds 10 DNS lookups. Receivers may return SPF PermError.</div>}
              {spfExpandResult.errors.map(error => <div key={error} style={styles.warning}>⚠ {error}</div>)}
              <div style={styles.smallCode}>{spfExpandResult.includes.length ? `Includes: ${spfExpandResult.includes.join(", ")}` : "No nested includes found."}</div>
              <pre style={styles.largeCode}>{spfExpandResult.flattened || "No flattened IP mechanisms found."}</pre>
            </div>
          )}
        </Card>
      </aside>
    </main>
  );
}

async function dnsTxtLookup(name) {
  const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=TXT`);
  if (!res.ok) throw new Error(`DNS lookup failed for ${name}`);
  const data = await res.json();
  return (data.Answer || []).map(answer => cleanTxtRecord(answer.data));
}

async function expandSPFDomain(domain, seen = new Set(), depth = 0) {
  const result = { domain, records: [], includes: [], ip4: [], ip6: [], errors: [], lookupCount: 0, flattened: "" };
  if (depth > 10) {
    result.errors.push(`Maximum recursion depth reached at ${domain}.`);
    return result;
  }
  if (seen.has(domain)) {
    result.errors.push(`Loop detected for ${domain}.`);
    return result;
  }
  seen.add(domain);

  try {
    const records = (await dnsTxtLookup(domain)).filter(txt => txt.toLowerCase().startsWith("v=spf1"));
    result.records = records;
    if (!records.length) {
      result.errors.push(`No SPF record found for ${domain}.`);
      return result;
    }
    if (records.length > 1) result.errors.push(`Multiple SPF records found for ${domain}.`);

    const parsed = parseSPF(records[0]);
    result.lookupCount += parsed.includes.length + (parsed.mx ? 1 : 0) + (parsed.a ? 1 : 0) + parsed.advanced.filter(x => x.toLowerCase() === "ptr" || x.toLowerCase().startsWith("exists:") || x.toLowerCase().startsWith("redirect=")).length;
    result.includes.push(...parsed.includes);
    result.ip4.push(...parsed.ip4);
    result.ip6.push(...parsed.ip6);

    for (const include of parsed.includes) {
      const child = await expandSPFDomain(include, seen, depth + 1);
      result.includes.push(...child.includes);
      result.ip4.push(...child.ip4);
      result.ip6.push(...child.ip6);
      result.errors.push(...child.errors);
      result.lookupCount += child.lookupCount;
    }

    result.includes = uniqueClean(result.includes);
    result.ip4 = uniqueClean(result.ip4);
    result.ip6 = uniqueClean(result.ip6);
    result.errors = uniqueClean(result.errors);
    result.flattened = buildSPF({ mx: false, a: false, includes: [], ip4: result.ip4, ip6: result.ip6, advanced: [], policy: parsed.policy });
    return result;
  } catch {
    result.errors.push(`Lookup failed for ${domain}.`);
    return result;
  }
}

function DMARCTool() {
  const [domain, setDomain] = useState("example.com");
  const [policy, setPolicy] = useState("none");
  const [subdomainPolicy, setSubdomainPolicy] = useState("");
  const [rua, setRua] = useState("dmarc-reports@example.com");
  const [ruf, setRuf] = useState("");
  const [pct, setPct] = useState("100");
  const [alignmentSpf, setAlignmentSpf] = useState("r");
  const [alignmentDkim, setAlignmentDkim] = useState("r");
  const [failureOptions, setFailureOptions] = useState("1");
  const [lookupStatus, setLookupStatus] = useState("idle");
  const [lookupMessage, setLookupMessage] = useState("");
  const [existingDMARC, setExistingDMARC] = useState("");
  const [copied, setCopied] = useState(false);

  const record = useMemo(() => buildDMARC({ policy, rua, ruf, pct, alignmentSpf, alignmentDkim, subdomainPolicy, failureOptions }), [policy, rua, ruf, pct, alignmentSpf, alignmentDkim, subdomainPolicy, failureOptions]);

  const dmarcWarnings = useMemo(() => {
    const items = [];
    if (policy === "none") items.push("Monitoring mode only. This does not reject or quarantine spoofed mail.");
    if (!rua) items.push("Add a rua aggregate report mailbox so you can monitor authentication results.");
    if (policy === "reject" && pct !== "100") items.push("Reject policy is set but pct is below 100, so only some mail is enforced.");
    if (ruf) items.push("Forensic reports may include sensitive message data and are not sent by all providers.");
    return items;
  }, [policy, rua, pct, ruf]);

  async function lookupDMARC() {
    const cleanDomain = domain.trim();
    if (!cleanDomain) return;
    setLookupStatus("loading");
    setLookupMessage("");
    setExistingDMARC("");

    try {
      const res = await fetch(`https://dns.google/resolve?name=_dmarc.${encodeURIComponent(cleanDomain)}&type=TXT`);
      if (!res.ok) throw new Error("DNS lookup failed");
      const data = await res.json();
      const record = (data.Answer || []).map(a => cleanTxtRecord(a.data)).find(txt => txt.toLowerCase().startsWith("v=dmarc1"));

      if (!record) {
        setLookupStatus("warning");
        setLookupMessage("No DMARC record found. Create one using the generated TXT record below.");
        return;
      }

      setExistingDMARC(record);
      const parsed = parseDMARC(record);
      if (parsed.p) setPolicy(parsed.p);
      if (parsed.sp) setSubdomainPolicy(parsed.sp);
      if (parsed.rua) setRua(parsed.rua.replace(/^mailto:/i, ""));
      if (parsed.ruf) setRuf(parsed.ruf.replace(/^mailto:/i, ""));
      if (parsed.pct) setPct(parsed.pct);
      if (parsed.aspf) setAlignmentSpf(parsed.aspf);
      if (parsed.adkim) setAlignmentDkim(parsed.adkim);
      if (parsed.fo) setFailureOptions(parsed.fo);
      setLookupStatus("success");
      setLookupMessage(`DMARC record found for ${cleanDomain}.`);
    } catch {
      setLookupStatus("error");
      setLookupMessage("DMARC lookup failed. Check the domain and try again.");
    }
  }

  async function copyDMARC() {
    await navigator.clipboard.writeText(record);
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  }

  return (
    <main style={styles.grid}>
      <section style={styles.leftColumn}>
        <Card title="DMARC Lookup" description="Check the current _dmarc TXT record for a domain.">
          <div style={styles.searchRow}>
            <input style={styles.searchInput} value={domain} onChange={e => setDomain(e.target.value)} placeholder="contoso.com" />
            <button style={styles.primaryButton} onClick={lookupDMARC} disabled={lookupStatus === "loading"}>{lookupStatus === "loading" ? "Checking..." : "Lookup DMARC"}</button>
          </div>
          {lookupMessage && <Status type={lookupStatus}>{lookupMessage}</Status>}
          {existingDMARC && <div style={styles.smallCode}>{existingDMARC}</div>}
        </Card>

        <Card title="DMARC Policy Builder" description="Start with monitoring, then move to quarantine or reject after validating legitimate senders.">
          <div style={styles.formGrid}>
            <Field label="Policy">
              <select style={styles.input} value={policy} onChange={e => setPolicy(e.target.value)}>
                <option value="none">none — monitor only</option>
                <option value="quarantine">quarantine — send failures to spam/junk</option>
                <option value="reject">reject — block failures</option>
              </select>
            </Field>
            <Field label="Subdomain policy">
              <select style={styles.input} value={subdomainPolicy} onChange={e => setSubdomainPolicy(e.target.value)}>
                <option value="">same as main policy</option>
                <option value="none">none</option>
                <option value="quarantine">quarantine</option>
                <option value="reject">reject</option>
              </select>
            </Field>
            <Field label="Aggregate reports rua">
              <input style={styles.input} value={rua} onChange={e => setRua(e.target.value)} placeholder="dmarc-reports@example.com" />
            </Field>
            <Field label="Forensic reports ruf">
              <input style={styles.input} value={ruf} onChange={e => setRuf(e.target.value)} placeholder="optional@example.com" />
            </Field>
            <Field label="Enforcement percentage">
              <select style={styles.input} value={pct} onChange={e => setPct(e.target.value)}>
                <option value="25">25%</option>
                <option value="50">50%</option>
                <option value="75">75%</option>
                <option value="100">100%</option>
              </select>
            </Field>
            <Field label="SPF alignment">
              <select style={styles.input} value={alignmentSpf} onChange={e => setAlignmentSpf(e.target.value)}>
                <option value="r">relaxed</option>
                <option value="s">strict</option>
              </select>
            </Field>
            <Field label="DKIM alignment">
              <select style={styles.input} value={alignmentDkim} onChange={e => setAlignmentDkim(e.target.value)}>
                <option value="r">relaxed</option>
                <option value="s">strict</option>
              </select>
            </Field>
            <Field label="Failure reporting fo">
              <select style={styles.input} value={failureOptions} onChange={e => setFailureOptions(e.target.value)}>
                <option value="0">0 — both SPF and DKIM fail</option>
                <option value="1">1 — either SPF or DKIM fails</option>
                <option value="d">d — DKIM failure</option>
                <option value="s">s — SPF failure</option>
              </select>
            </Field>
          </div>
        </Card>
      </section>

      <aside style={styles.rightColumn}>
        <Card title="DMARC Health" description="Quick policy recommendations.">
          {dmarcWarnings.length ? dmarcWarnings.map(w => <div key={w} style={styles.warning}>⚠ {w}</div>) : <div style={styles.good}>✓ DMARC policy looks enforcement-ready.</div>}
        </Card>
        <Card title="Generated DMARC TXT Record" description="Publish this TXT record at _dmarc on your domain.">
          <div style={styles.dnsBox}>
            <div><strong>Type:</strong> TXT</div>
            <div><strong>Host:</strong> _dmarc</div>
            <div><strong>Domain:</strong> {domain || "example.com"}</div>
          </div>
          <pre style={styles.largeCode}>{record}</pre>
          <button style={styles.copyButton} onClick={copyDMARC}>{copied ? "Copied!" : "Copy DMARC Record"}</button>
        </Card>
      </aside>
    </main>
  );
}

function DKIMTool() {
  const [domain, setDomain] = useState("example.com");
  const [selector, setSelector] = useState("selector1");
  const [provider, setProvider] = useState("Microsoft 365");
  const [publicKey, setPublicKey] = useState("");
  const [lookupStatus, setLookupStatus] = useState("idle");
  const [lookupMessage, setLookupMessage] = useState("");
  const [existingDKIM, setExistingDKIM] = useState("");
  const [copied, setCopied] = useState(false);

  const hostName = `${selector}._domainkey`;
  const lookupName = `${selector}._domainkey.${domain}`;
  const recordType = provider === "Microsoft 365" ? "CNAME" : "TXT";
  const dkimValue = useMemo(() => {
    if (provider === "Microsoft 365") {
      return `${selector}-${domain.replace(/\./g, "-")}._domainkey.${domain}`;
    }
    const cleanKey = publicKey.trim().replace(/^v=DKIM1;\s*/i, "");
    return `v=DKIM1; k=rsa; p=${cleanKey}`;
  }, [provider, selector, domain, publicKey]);

  async function lookupDKIM() {
    const cleanDomain = domain.trim();
    const cleanSelector = selector.trim();
    if (!cleanDomain || !cleanSelector) return;
    setLookupStatus("loading");
    setLookupMessage("");
    setExistingDKIM("");

    try {
      const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(`${cleanSelector}._domainkey.${cleanDomain}`)}&type=TXT`);
      if (!res.ok) throw new Error("DNS lookup failed");
      const data = await res.json();
      const record = (data.Answer || []).map(a => cleanTxtRecord(a.data)).find(txt => txt.toLowerCase().includes("v=dkim1"));

      if (!record) {
        setLookupStatus("warning");
        setLookupMessage("No DKIM TXT record found for that selector. Some providers use CNAME records instead of TXT.");
        return;
      }

      setExistingDKIM(record);
      setLookupStatus("success");
      setLookupMessage(`DKIM TXT record found at ${cleanSelector}._domainkey.${cleanDomain}.`);
    } catch {
      setLookupStatus("error");
      setLookupMessage("DKIM lookup failed. Check the selector and domain.");
    }
  }

  async function copyDKIM() {
    await navigator.clipboard.writeText(dkimValue);
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  }

  return (
    <main style={styles.grid}>
      <section style={styles.leftColumn}>
        <Card title="DKIM Lookup" description="Check whether a selector has a DKIM TXT record published.">
          <div style={styles.formGrid}>
            <Field label="Domain">
              <input style={styles.input} value={domain} onChange={e => setDomain(e.target.value)} placeholder="contoso.com" />
            </Field>
            <Field label="Selector">
              <input style={styles.input} value={selector} onChange={e => setSelector(e.target.value)} placeholder="selector1" />
            </Field>
          </div>
          <button style={{ ...styles.primaryButton, padding: "12px 18px", marginTop: 12 }} onClick={lookupDKIM} disabled={lookupStatus === "loading"}>{lookupStatus === "loading" ? "Checking..." : "Lookup DKIM"}</button>
          {lookupMessage && <Status type={lookupStatus}>{lookupMessage}</Status>}
          {existingDKIM && <div style={styles.smallCode}>{existingDKIM}</div>}
        </Card>

        <Card title="DKIM Record Helper" description="Generate a DNS host/value layout for common DKIM publishing scenarios.">
          <div style={styles.formGrid}>
            <Field label="Provider mode">
              <select style={styles.input} value={provider} onChange={e => setProvider(e.target.value)}>
                <option value="Microsoft 365">Microsoft 365 CNAME-style</option>
                <option value="Generic TXT">Generic TXT public key</option>
              </select>
            </Field>
            <Field label="Selector">
              <input style={styles.input} value={selector} onChange={e => setSelector(e.target.value)} placeholder="selector1" />
            </Field>
          </div>

          {provider === "Generic TXT" && (
            <div style={styles.inputGroup}>
              <label style={styles.label}>Public key value</label>
              <textarea style={{ ...styles.input, minHeight: 130, fontFamily: "Consolas, monospace" }} value={publicKey} onChange={e => setPublicKey(e.target.value)} placeholder="Paste the long DKIM public key without the v=DKIM1 prefix" />
            </div>
          )}
        </Card>
      </section>

      <aside style={styles.rightColumn}>
        <Card title="DKIM DNS Record" description="Publish the DNS record your mail provider gives you. DKIM keys are provider-generated.">
          <div style={styles.dnsBox}>
            <div><strong>Type:</strong> {recordType}</div>
            <div><strong>Host:</strong> {hostName}</div>
            <div><strong>Lookup name:</strong> {lookupName}</div>
          </div>
          <pre style={styles.largeCode}>{dkimValue}</pre>
          <button style={styles.copyButton} onClick={copyDKIM}>{copied ? "Copied!" : "Copy DKIM Value"}</button>
        </Card>

        <Card title="DKIM Notes" description="Important implementation reminders.">
          <div style={styles.notice}>DKIM public/private key pairs are generated by your mail platform. This helper formats DNS records, but it should not invent private keys.</div>
          <div style={styles.warning}>⚠ Microsoft 365 usually requires enabling DKIM in the Defender portal after DNS CNAME records are published.</div>
          <div style={styles.good}>✓ Use two selectors where possible so keys can be rotated without mail interruption.</div>
        </Card>
      </aside>
    </main>
  );
}

function MXTool() {
  const [domain, setDomain] = useState("example.com");
  const [mxRecords, setMxRecords] = useState([]);
  const [aRecords, setARecords] = useState({});
  const [lookupStatus, setLookupStatus] = useState("idle");
  const [lookupMessage, setLookupMessage] = useState("");
  const [copied, setCopied] = useState(false);

  function stripTrailingDot(value) {
    const text = String(value || "").trim();
    return text.endsWith(".") ? text.slice(0, -1) : text;
  }

  const mxWarnings = useMemo(() => {
    const items = [];
    if (!mxRecords.length && lookupStatus === "success") items.push("No MX records found. This domain may not be able to receive email.");
    if (mxRecords.length === 1) items.push("Only one MX record found. Consider redundancy if this is a production mail domain.");
    const priorities = mxRecords.map(record => record.priority);
    if (new Set(priorities).size < priorities.length && mxRecords.length > 1) items.push("Multiple MX records share the same priority. This can be valid for load balancing, but verify it is intentional.");
    mxRecords.forEach(record => {
      if (!aRecords[record.exchange]?.length) items.push(`${record.exchange} did not return A records from the available lookup.`);
    });
    return uniqueClean(items);
  }, [mxRecords, aRecords, lookupStatus]);

  async function lookupMX() {
    const cleanDomain = domain.trim();
    if (!cleanDomain) return;
    setLookupStatus("loading");
    setLookupMessage("");
    setMxRecords([]);
    setARecords({});

    try {
      const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(cleanDomain)}&type=MX`);
      if (!res.ok) throw new Error("MX lookup failed");
      const data = await res.json();
      const records = (data.Answer || []).map(answer => {
        const parts = String(answer.data || "").trim().split(" ").filter(Boolean);
        return { priority: Number(parts[0]), exchange: stripTrailingDot(parts.slice(1).join(" ")), ttl: answer.TTL || "" };
      }).filter(record => record.exchange).sort((a, b) => a.priority - b.priority);

      setMxRecords(records);
      if (!records.length) {
        setLookupStatus("warning");
        setLookupMessage(`No MX records found for ${cleanDomain}.`);
        return;
      }

      const resolved = {};
      await Promise.all(records.map(async record => {
        try {
          const aRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(record.exchange)}&type=A`);
          const aData = await aRes.json();
          resolved[record.exchange] = (aData.Answer || []).map(item => item.data).filter(Boolean);
        } catch {
          resolved[record.exchange] = [];
        }
      }));
      setARecords(resolved);
      setLookupStatus("success");
      setLookupMessage(`${records.length} MX record${records.length > 1 ? "s" : ""} found for ${cleanDomain}.`);
    } catch {
      setLookupStatus("error");
      setLookupMessage("MX lookup failed. Check the domain and try again.");
    }
  }

  async function copyMXSummary() {
    const summary = mxRecords.map(record => {
      const ips = aRecords[record.exchange]?.join(", ") || "No A records found";
      return `${record.priority} ${record.exchange} | TTL: ${record.ttl || "unknown"} | A: ${ips}`;
    }).join(String.fromCharCode(10));
    await navigator.clipboard.writeText(summary || "No MX records found.");
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  }

  return (
    <main style={styles.grid}>
      <section style={styles.leftColumn}>
        <Card title="MX Record Lookup" description="Check which mail exchangers receive email for a domain.">
          <div style={styles.searchRow}>
            <input style={styles.searchInput} value={domain} onChange={e => setDomain(e.target.value)} placeholder="contoso.com" />
            <button style={styles.primaryButton} onClick={lookupMX} disabled={lookupStatus === "loading"}>{lookupStatus === "loading" ? "Checking..." : "Lookup MX"}</button>
          </div>
          {lookupMessage && <Status type={lookupStatus}>{lookupMessage}</Status>}
        </Card>

        <Card title="MX Results" description="Lower priority values are preferred first by sending mail servers.">
          {mxRecords.length ? (
            <div style={styles.tableWrap}>
              <table style={styles.table}>
                <thead>
                  <tr>
                    <th style={styles.th}>Priority</th>
                    <th style={styles.th}>Exchange</th>
                    <th style={styles.th}>TTL</th>
                    <th style={styles.th}>A Records</th>
                  </tr>
                </thead>
                <tbody>
                  {mxRecords.map(record => (
                    <tr key={`${record.priority}-${record.exchange}`}>
                      <td style={styles.td}><strong>{record.priority}</strong></td>
                      <td style={styles.td}>{record.exchange}</td>
                      <td style={styles.td}>{record.ttl || "—"}</td>
                      <td style={styles.td}>{aRecords[record.exchange]?.length ? aRecords[record.exchange].join(", ") : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={styles.notice}>Run an MX lookup to see mail exchangers.</div>
          )}
        </Card>
      </section>

      <aside style={styles.rightColumn}>
        <Card title="MX Health" description="Quick checks for mail-receiving reliability.">
          <div style={styles.metrics}>
            <Metric label="MX Records" value={mxRecords.length} danger={lookupStatus === "success" && !mxRecords.length} />
            <Metric label="Unique Priorities" value={new Set(mxRecords.map(r => r.priority)).size} />
            <Metric label="Hosts w/ A" value={Object.values(aRecords).filter(v => v?.length).length} />
          </div>
          {mxWarnings.length ? mxWarnings.map(w => <div key={w} style={styles.warning}>⚠ {w}</div>) : <div style={styles.good}>✓ MX records look healthy from available checks.</div>}
        </Card>

        <Card title="Common MX Providers" description="Useful patterns for identifying hosted mail platforms.">
          <div style={styles.smallCode}>Microsoft 365: *.mail.protection.outlook.com</div>
          <div style={styles.smallCode}>Google Workspace: aspmx.l.google.com</div>
          <div style={styles.smallCode}>Proofpoint: pphosted.com</div>
          <div style={styles.smallCode}>Mimecast: mimecast.com</div>
        </Card>

        <Card title="MX Summary" description="Copy a compact MX summary for tickets or documentation.">
          <button style={styles.copyButton} onClick={copyMXSummary}>{copied ? "Copied!" : "Copy MX Summary"}</button>
        </Card>
      </aside>
    </main>
  );
}

function DNSHealthTool() {
  const [domain, setDomain] = useState("example.com");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  async function runHealthCheck() {
    const cleanDomain = domain.trim();
    if (!cleanDomain) return;
    setLoading(true);
    try {
      const [mx, txt, a, aaaa, ns, dmarc] = await Promise.all([
        dnsLookup(cleanDomain, "MX"),
        dnsLookup(cleanDomain, "TXT"),
        dnsLookup(cleanDomain, "A"),
        dnsLookup(cleanDomain, "AAAA"),
        dnsLookup(cleanDomain, "NS"),
        dnsLookup(`_dmarc.${cleanDomain}`, "TXT"),
      ]);
      const spfRecords = txt.filter(record => cleanTxtRecord(record.data).toLowerCase().startsWith("v=spf1"));
      const dmarcRecords = dmarc.filter(record => cleanTxtRecord(record.data).toLowerCase().startsWith("v=dmarc1"));
      const warnings = [];
      if (!mx.length) warnings.push("No MX records found.");
      if (!spfRecords.length) warnings.push("No SPF record found.");
      if (spfRecords.length > 1) warnings.push("Multiple SPF records found.");
      if (!dmarcRecords.length) warnings.push("No DMARC record found.");
      if (dmarcRecords[0] && cleanTxtRecord(dmarcRecords[0].data).toLowerCase().includes("p=none")) warnings.push("DMARC is in monitoring mode only.");
      if (!ns.length) warnings.push("No NS records returned from lookup.");
      setResults({ mx, txt, a, aaaa, ns, spfRecords, dmarcRecords, warnings });
    } finally {
      setLoading(false);
    }
  }

  return (
    <main style={styles.grid}>
      <section style={styles.leftColumn}>
        <Card title="DNS Health Dashboard" description="Run an all-in-one check across MX, SPF, DMARC, A, AAAA, and NS records.">
          <div style={styles.searchRow}>
            <input style={styles.searchInput} value={domain} onChange={e => setDomain(e.target.value)} placeholder="contoso.com" />
            <button style={styles.primaryButton} onClick={runHealthCheck}>{loading ? "Checking..." : "Run Health Check"}</button>
          </div>
        </Card>
        {results && <Card title="DNS Findings" description="Raw DNS records returned from public DNS.">
          <DnsList title="MX" records={results.mx} />
          <DnsList title="SPF" records={results.spfRecords} />
          <DnsList title="DMARC" records={results.dmarcRecords} />
          <DnsList title="A" records={results.a} />
          <DnsList title="AAAA" records={results.aaaa} />
          <DnsList title="NS" records={results.ns} />
        </Card>}
      </section>
      <aside style={styles.rightColumn}>
        <Card title="Health Summary" description="High-level email DNS readiness.">
          {results ? <>
            <div style={styles.metrics}>
              <Metric label="MX" value={results.mx.length} danger={!results.mx.length} />
              <Metric label="SPF" value={results.spfRecords.length} danger={results.spfRecords.length !== 1} />
              <Metric label="DMARC" value={results.dmarcRecords.length} danger={!results.dmarcRecords.length} />
            </div>
            {results.warnings.length ? results.warnings.map(w => <div key={w} style={styles.warning}>⚠ {w}</div>) : <div style={styles.good}>✓ Core email DNS records look healthy.</div>}
          </> : <div style={styles.notice}>Run a health check to see results.</div>}
        </Card>
      </aside>
    </main>
  );
}

function BlacklistTool() {
  const [ip, setIp] = useState("8.8.8.8");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function checkIp() {
    const cleanIp = ip.trim();
    if (!cleanIp) return;
    setLoading(true);
    try {
      const response = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(cleanIp)}`);
      const data = response.ok ? await response.json() : {};
      setResult({
        ip: cleanIp,
        ports: data.ports || [],
        tags: data.tags || [],
        vulns: data.vulns || [],
        hostnames: data.hostnames || [],
        cpes: data.cpes || [],
      });
    } catch {
      setResult({ ip: cleanIp, error: "Public reputation lookup failed." });
    } finally {
      setLoading(false);
    }
  }

  return (
    <main style={styles.grid}>
      <section style={styles.leftColumn}>
        <Card title="IP Blacklist / Exposure Check" description="Browser-safe public exposure check using InternetDB signals. Add a backend later for Spamhaus/Barracuda-style RBL checks.">
          <div style={styles.searchRow}>
            <input style={styles.searchInput} value={ip} onChange={e => setIp(e.target.value)} placeholder="203.0.113.25" />
            <button style={styles.primaryButton} onClick={checkIp}>{loading ? "Checking..." : "Check IP"}</button>
          </div>
        </Card>
        {result && <Card title="Reputation Signals" description="Open ports, hostnames, tags, and known vulnerability exposure when available.">
          {result.error ? <div style={styles.warning}>⚠ {result.error}</div> : <>
            <Finding label="IP" value={result.ip} />
            <Finding label="Hostnames" value={result.hostnames?.join(", ") || "None reported"} />
            <Finding label="Open Ports" value={result.ports?.join(", ") || "None reported"} />
            <Finding label="Tags" value={result.tags?.join(", ") || "None reported"} />
            <Finding label="Vulnerabilities" value={result.vulns?.join(", ") || "None reported"} />
          </>}
        </Card>}
      </section>
      <aside style={styles.rightColumn}>
        <Card title="Blacklist Notes" description="Why this tab is designed this way.">
          <div style={styles.notice}>DNSBL/RBL providers usually require server-side DNS queries or paid APIs. This frontend version uses public exposure signals and is ready for a backend connector later.</div>
          <div style={styles.good}>✓ Good next backend APIs: AbuseIPDB, VirusTotal, Spamhaus DQS, Google Safe Browsing.</div>
        </Card>
      </aside>
    </main>
  );
}

function DomainScoreTool() {
  const [domain, setDomain] = useState("example.com");
  const [loading, setLoading] = useState(false);
  const [score, setScore] = useState(null);

  async function calculateScore() {
    const cleanDomain = domain.trim();
    if (!cleanDomain) return;
    setLoading(true);
    try {
      const [mx, txt, dmarc] = await Promise.all([
        dnsLookup(cleanDomain, "MX"),
        dnsLookup(cleanDomain, "TXT"),
        dnsLookup(`_dmarc.${cleanDomain}`, "TXT"),
      ]);
      const spf = txt.filter(r => cleanTxtRecord(r.data).toLowerCase().startsWith("v=spf1"));
      const dmarcRecord = dmarc.find(r => cleanTxtRecord(r.data).toLowerCase().startsWith("v=dmarc1"));
      let points = 100;
      const findings = [];
      if (!mx.length) { points -= 25; findings.push("No MX records found."); }
      if (!spf.length) { points -= 25; findings.push("No SPF record found."); }
      if (spf.length > 1) { points -= 20; findings.push("Multiple SPF records found."); }
      if (!dmarcRecord) { points -= 25; findings.push("No DMARC record found."); }
      if (dmarcRecord && cleanTxtRecord(dmarcRecord.data).toLowerCase().includes("p=none")) { points -= 10; findings.push("DMARC policy is monitoring-only."); }
      setScore({ value: Math.max(points, 0), findings, mx, spf, dmarcRecord });
    } finally {
      setLoading(false);
    }
  }

  return (
    <main style={styles.grid}>
      <section style={styles.leftColumn}>
        <Card title="Domain Reputation Score" description="Score a domain based on core email authentication posture.">
          <div style={styles.searchRow}>
            <input style={styles.searchInput} value={domain} onChange={e => setDomain(e.target.value)} placeholder="contoso.com" />
            <button style={styles.primaryButton} onClick={calculateScore}>{loading ? "Scoring..." : "Score Domain"}</button>
          </div>
        </Card>
      </section>
      <aside style={styles.rightColumn}>
        <Card title="Score" description="Simple posture score based on DNS authentication checks.">
          {score ? <>
            <div style={styles.scoreCircle}>{score.value}</div>
            {score.findings.length ? score.findings.map(f => <div key={f} style={styles.warning}>⚠ {f}</div>) : <div style={styles.good}>✓ Strong baseline email DNS posture.</div>}
          </> : <div style={styles.notice}>Run a domain score to begin.</div>}
        </Card>
      </aside>
    </main>
  );
}

function DMARCReportAnalyzer() {
  const sample = `<feedback><report_metadata><org_name>Example</org_name></report_metadata><record><row><source_ip>203.0.113.25</source_ip><count>42</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers></record></feedback>`;
  const [xml, setXml] = useState(sample);
  const parsed = useMemo(() => parseDmarcXml(xml), [xml]);

  return (
    <main style={styles.grid}>
      <section style={styles.leftColumn}>
        <Card title="DMARC XML Report Analyzer" description="Paste an aggregate DMARC XML report to summarize sending sources and pass/fail results.">
          <textarea style={{ ...styles.input, minHeight: 360, fontFamily: "Consolas, monospace" }} value={xml} onChange={e => setXml(e.target.value)} />
        </Card>
        <Card title="Parsed Sources" description="Aggregate report records found in the XML.">
          {parsed.records.length ? parsed.records.map((r, i) => <div key={`${r.sourceIp}-${i}`} style={styles.smallCode}>{r.sourceIp} · Count {r.count} · SPF {r.spf} · DKIM {r.dkim} · From {r.headerFrom}</div>) : <div style={styles.notice}>No DMARC records parsed.</div>}
        </Card>
      </section>
      <aside style={styles.rightColumn}>
        <Card title="Report Summary" description="Fast aggregate view.">
          <div style={styles.metrics}>
            <Metric label="Sources" value={parsed.records.length} />
            <Metric label="Messages" value={parsed.total} />
            <Metric label="Failures" value={parsed.failures} danger={parsed.failures > 0} />
          </div>
          {parsed.failures ? <div style={styles.warning}>⚠ Some reported sources failed SPF or DKIM evaluation.</div> : <div style={styles.good}>✓ No failures found in parsed report records.</div>}
        </Card>
      </aside>
    </main>
  );
}

function SMTPTLSTool() {
  return (
    <main style={styles.grid}>
      <section style={styles.leftColumn}>
        <Card title="SMTP / TLS Tester" description="Browser apps cannot open raw SMTP sockets to ports 25, 465, or 587. This page gives safe commands and can be connected to a backend later.">
          <div style={styles.largeCode}>openssl s_client -connect mail.example.com:25 -starttls smtp</div>
          <div style={styles.largeCode}>openssl s_client -connect smtp.example.com:587 -starttls smtp</div>
          <div style={styles.largeCode}>Test-NetConnection smtp.example.com -Port 587</div>
        </Card>
      </section>
      <aside style={styles.rightColumn}>
        <Card title="Backend Upgrade Path" description="To make this live, add a small Node/Express or serverless backend that performs TCP/TLS checks.">
          <div style={styles.notice}>Frontend JavaScript cannot test SMTP ports directly due browser network restrictions.</div>
          <div style={styles.good}>✓ Backend checks can return banner, STARTTLS support, certificate issuer, expiration, and protocol errors.</div>
        </Card>
      </aside>
    </main>
  );
}

function DNSPropagationTool() {
  const [domain, setDomain] = useState("example.com");
  const [type, setType] = useState("MX");
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(false);

  async function checkPropagation() {
    setLoading(true);
    try {
      const result = await dnsLookup(domain.trim(), type);
      setRecords(result);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main style={styles.grid}>
      <section style={styles.leftColumn}>
        <Card title="DNS Propagation Checker" description="Basic public resolver check. Add multi-region resolvers later through a backend API.">
          <div style={styles.searchRow}>
            <input style={styles.searchInput} value={domain} onChange={e => setDomain(e.target.value)} />
            <select style={styles.input} value={type} onChange={e => setType(e.target.value)}>
              <option>MX</option><option>TXT</option><option>A</option><option>AAAA</option><option>NS</option><option>CNAME</option>
            </select>
            <button style={styles.primaryButton} onClick={checkPropagation}>{loading ? "Checking..." : "Check"}</button>
          </div>
        </Card>
        <Card title="Resolver Result" description="DNS answer from Google DNS-over-HTTPS.">
          {records.length ? records.map((r, i) => <div key={`${r.data}-${i}`} style={styles.smallCode}>{r.data} · TTL {r.TTL}</div>) : <div style={styles.notice}>Run a lookup to see results.</div>}
        </Card>
      </section>
      <aside style={styles.rightColumn}>
        <Card title="Propagation Notes" description="True global propagation needs multiple resolvers or regions.">
          <div style={styles.notice}>This frontend version checks Google DNS. A backend can query Cloudflare, Quad9, OpenDNS, and regional resolvers.</div>
        </Card>
      </aside>
    </main>
  );
}

async function dnsLookup(name, type) {
  const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`);
  if (!res.ok) return [];
  const data = await res.json();
  return data.Answer || [];
}

function DnsList({ title, records }) {
  return (
    <div style={{ marginTop: 14 }}>
      <strong>{title}</strong>
      {records.length ? records.map((record, index) => <div key={`${title}-${index}-${record.data}`} style={styles.smallCode}>{cleanTxtRecord(record.data)} · TTL {record.TTL}</div>) : <div style={styles.notice}>No {title} records found.</div>}
    </div>
  );
}

function parseDmarcXml(xml) {
  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(xml, "application/xml");
    const records = [...doc.querySelectorAll("record")].map(record => {
      const get = selector => record.querySelector(selector)?.textContent || "unknown";
      return { sourceIp: get("source_ip"), count: Number(get("count")) || 0, spf: get("policy_evaluated > spf"), dkim: get("policy_evaluated > dkim"), headerFrom: get("header_from") };
    });
    return { records, total: records.reduce((sum, r) => sum + r.count, 0), failures: records.filter(r => r.spf !== "pass" || r.dkim !== "pass").length };
  } catch {
    return { records: [], total: 0, failures: 0 };
  }
}

function MessageAnalyzerTool() {
  const sampleHeaders = [
    "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=sender.com; dkim=pass header.d=sender.com; dmarc=pass header.from=sender.com",
    "From: Sender <sender@sender.com>",
    "Return-Path: <bounce@sender.com>",
    "Reply-To: Sender <sender@sender.com>",
    "Received: from mail.sender.com (mail.sender.com. [203.0.113.25]) by mx.example.com with ESMTPS id abc123",
    "Subject: Example message"
  ].join(String.fromCharCode(10));

  const [headers, setHeaders] = useState(sampleHeaders);
  const [copied, setCopied] = useState(false);
  const [ipIntelLoading, setIpIntelLoading] = useState(false);
  const [ipIntel, setIpIntel] = useState([]);
  const analysis = useMemo(() => analyzeMessageHeaders(headers), [headers]);

  async function lookupIpIntel() {
    setIpIntelLoading(true);
    try {
      const results = await Promise.all(analysis.ips.slice(0, 8).map(async ip => {
        const base = { ip, country: "Unknown", region: "", city: "", isp: "Unknown", org: "", asn: "", risk: "Unknown", riskNotes: [] };
        try {
          const geoRes = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
          const geo = await geoRes.json();
          if (geo && geo.success !== false) {
            base.country = geo.country || "Unknown";
            base.region = geo.region || "";
            base.city = geo.city || "";
            base.isp = geo.connection?.isp || "Unknown";
            base.org = geo.connection?.org || "";
            base.asn = geo.connection?.asn ? `AS${geo.connection.asn}` : "";
          }
        } catch {
          base.riskNotes.push("Geo lookup failed");
        }
        try {
          const repRes = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`);
          if (repRes.ok) {
            const rep = await repRes.json();
            if (rep.vulns?.length) base.riskNotes.push(`${rep.vulns.length} vulnerabilities reported by InternetDB`);
            if (rep.tags?.length) base.riskNotes.push(`Tags: ${rep.tags.join(", ")}`);
            if (rep.ports?.length) base.riskNotes.push(`Open ports: ${rep.ports.slice(0, 8).join(", ")}`);
          }
        } catch {
          base.riskNotes.push("Reputation lookup unavailable");
        }
        base.risk = base.riskNotes.some(note => note.includes("vulnerabilities")) ? "Elevated" : base.riskNotes.length ? "Review" : "Low";
        return base;
      }));
      setIpIntel(results);
    } finally {
      setIpIntelLoading(false);
    }
  }

  async function copySummary() {
    const summary = [
      `SPF: ${analysis.auth.spf || "not found"}`,
      `DKIM: ${analysis.auth.dkim || "not found"}`,
      `DMARC: ${analysis.auth.dmarc || "not found"}`,
      `From: ${analysis.from || "not found"}`,
      `Return-Path: ${analysis.returnPath || "not found"}`,
      `Reply-To: ${analysis.replyTo || "not found"}`,
      `Source IPs: ${analysis.ips.join(", ") || "none found"}`,
      `Warnings: ${analysis.warnings.join(" | ") || "none"}`,
    ].join(String.fromCharCode(10));
    await navigator.clipboard.writeText(summary);
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  }

  return (
    <main style={styles.grid}>
      <section style={styles.leftColumn}>
        <Card title="Message Header Analyzer" description="Paste raw email headers to inspect SPF, DKIM, DMARC, relay hops, sending IPs, and alignment clues.">
          <textarea
            style={{ ...styles.input, minHeight: 360, fontFamily: "Consolas, monospace", lineHeight: 1.45 }}
            value={headers}
            onChange={e => setHeaders(e.target.value)}
            placeholder="Paste full message headers here..."
          />
          <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
            <button style={{ ...styles.secondaryButton, padding: "12px 16px" }} onClick={() => setHeaders("")}>Clear</button>
            <button style={{ ...styles.primaryButton, padding: "12px 16px" }} onClick={() => setHeaders(sampleHeaders)}>Load Sample</button>
          </div>
        </Card>

        <Card title="Detected Header Fields" description="Key values pulled from the pasted message headers.">
          <div style={styles.findingGrid}>
            <Finding label="From" value={analysis.from || "Not found"} />
            <Finding label="Return-Path" value={analysis.returnPath || "Not found"} />
            <Finding label="Reply-To" value={analysis.replyTo || "Not found"} />
            <Finding label="Subject" value={analysis.subject || "Not found"} />
            <Finding label="Message-ID" value={analysis.messageId || "Not found"} />
            <Finding label="Received Hops" value={analysis.receivedCount} />
          </div>
        </Card>
      </section>

      <aside style={styles.rightColumn}>
        <Card title="Authentication Results" description="Pass/fail indicators found in Authentication-Results or ARC headers.">
          <div style={styles.metrics}>
            <AuthMetric label="SPF" value={analysis.auth.spf} />
            <AuthMetric label="DKIM" value={analysis.auth.dkim} />
            <AuthMetric label="DMARC" value={analysis.auth.dmarc} />
          </div>
          {analysis.authDetails && <div style={styles.smallCode}>{analysis.authDetails}</div>}
        </Card>

        <Card title="Risk Signals" description="Common warning signs from the message metadata.">
          {analysis.warnings.length ? analysis.warnings.map(w => <div key={w} style={styles.warning}>⚠ {w}</div>) : <div style={styles.good}>✓ No obvious header risks detected.</div>}
        </Card>

        <Card title="Source IPs and Relay Path" description="IPs and Received headers extracted from the message.">
          <div style={styles.tags}>{analysis.ips.length ? analysis.ips.map(ip => <span key={ip} style={styles.tag}>{ip}</span>) : <span style={styles.tag}>No IPs found</span>}</div>
          <div style={{ marginTop: 14 }}>
            {analysis.receivedHeaders.slice(0, 6).map((line, index) => <div key={`${line}-${index}`} style={styles.smallCode}>{index + 1}. {line}</div>)}
          </div>
        </Card>

        <Card title="IP Geo + Reputation" description="Enrich extracted source IPs with geo, ISP, ASN, and basic public exposure signals.">
          <button style={styles.copyButton} onClick={lookupIpIntel} disabled={!analysis.ips.length || ipIntelLoading}>{ipIntelLoading ? "Checking IPs..." : "Lookup IP Intelligence"}</button>
          {ipIntel.map(item => (
            <div key={item.ip} style={styles.intelCard}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                <strong>{item.ip}</strong>
                <span style={{ ...styles.riskPill, ...(item.risk === "Elevated" ? styles.riskHigh : item.risk === "Review" ? styles.riskReview : styles.riskLow) }}>{item.risk}</span>
              </div>
              <div style={{ marginTop: 8, color: "#4b5563" }}>{[item.city, item.region, item.country].filter(Boolean).join(", ") || "Location unknown"}</div>
              <div style={{ marginTop: 4, color: "#4b5563" }}>{[item.asn, item.isp, item.org].filter(Boolean).join(" · ") || "Network unknown"}</div>
              {item.riskNotes.length ? item.riskNotes.map(note => <div key={note} style={styles.warning}>⚠ {note}</div>) : <div style={styles.good}>✓ No public exposure signals found from available sources.</div>}
            </div>
          ))}
        </Card>

        <Card title="Analysis Summary" description="Copy a compact summary for tickets or incident notes.">
          <button style={styles.copyButton} onClick={copySummary}>{copied ? "Copied!" : "Copy Analysis Summary"}</button>
        </Card>
      </aside>
    </main>
  );
}

function analyzeMessageHeaders(rawHeaders) {
  const raw = String(rawHeaders || "");
  const lines = raw.split(String.fromCharCode(10)).map(line => line.trim()).filter(Boolean);
  const combined = lines.join(" ");
  const lowerCombined = combined.toLowerCase();

  function getHeader(name) {
    const prefix = `${name.toLowerCase()}:`;
    const line = lines.find(item => item.toLowerCase().startsWith(prefix));
    return line ? line.slice(name.length + 1).trim() : "";
  }

  function getAuthResult(name) {
    const token = `${name}=`;
    const index = lowerCombined.indexOf(token);
    if (index < 0) return "";
    const after = lowerCombined.slice(index + token.length);
    return after.split(";")[0].split(" ")[0].trim();
  }

  function findIps(text) {
    return uniqueClean(text.replaceAll("[", " ").replaceAll("]", " ").replaceAll("(", " ").replaceAll(")", " ").split(" ").filter(part => {
      const pieces = part.split(".");
      return pieces.length === 4 && pieces.every(piece => piece !== "" && !Number.isNaN(Number(piece)) && Number(piece) >= 0 && Number(piece) <= 255);
    }));
  }

  const authLines = lines.filter(line => {
    const lower = line.toLowerCase();
    return lower.startsWith("authentication-results:") || lower.startsWith("arc-authentication-results:");
  });
  const receivedHeaders = lines.filter(line => line.toLowerCase().startsWith("received:"));
  const from = getHeader("From");
  const returnPath = getHeader("Return-Path").replaceAll("<", "").replaceAll(">", "");
  const replyTo = getHeader("Reply-To");
  const subject = getHeader("Subject");
  const messageId = getHeader("Message-ID");
  const auth = { spf: getAuthResult("spf"), dkim: getAuthResult("dkim"), dmarc: getAuthResult("dmarc") };
  const ips = findIps(combined);
  const warnings = [];

  if (!auth.spf) warnings.push("SPF result was not found in the headers.");
  if (!auth.dkim) warnings.push("DKIM result was not found in the headers.");
  if (!auth.dmarc) warnings.push("DMARC result was not found in the headers.");
  if ([auth.spf, auth.dkim, auth.dmarc].some(value => ["fail", "softfail", "temperror", "permerror"].includes(value))) warnings.push("One or more authentication checks failed or returned an error.");
  if (replyTo && from && !sameDomain(replyTo, from)) warnings.push("Reply-To domain appears different from the From domain.");
  if (returnPath && from && !sameDomain(returnPath, from)) warnings.push("Return-Path domain appears different from the From domain. This may be normal for third-party senders, but verify alignment.");
  if (!receivedHeaders.length) warnings.push("No Received headers found. The pasted content may be incomplete.");
  if (ips.length > 8) warnings.push("Many IP addresses detected. Review the relay chain carefully.");

  return { from, returnPath, replyTo, subject, messageId, auth, authDetails: authLines.join(" "), receivedHeaders, receivedCount: receivedHeaders.length, ips, warnings };
}

function extractDomain(value) {
  const atIndex = String(value || "").lastIndexOf("@");
  if (atIndex < 0) return "";
  return String(value).slice(atIndex + 1).toLowerCase().replaceAll(">", "").replaceAll(")", "").trim();
}

function sameDomain(a, b) {
  const domainA = extractDomain(a);
  const domainB = extractDomain(b);
  if (!domainA || !domainB) return true;
  return domainA === domainB || domainA.endsWith(`.${domainB}`) || domainB.endsWith(`.${domainA}`);
}

function Finding({ label, value }) {
  return (
    <div style={styles.finding}>
      <span>{label}</span>
      <strong>{String(value)}</strong>
    </div>
  );
}

function AuthMetric({ label, value }) {
  const result = value || "missing";
  const bad = ["fail", "softfail", "temperror", "permerror", "missing"].includes(result);
  return <Metric label={label} value={result.toUpperCase()} danger={bad} />;
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

function Field({ label, children }) {
  return (
    <div>
      <label style={styles.label}>{label}</label>
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

const lightThemeVars = {
  "--page-bg": "#f1f5f9",
  "--card-bg": "#ffffff",
  "--card-border": "#e2e8f0",
  "--text": "#0f172a",
  "--muted": "#64748b",
  "--soft-bg": "#f8fafc",
  "--code-bg": "#0f172a",
  "--code-text": "#e2e8f0",
  "--input-border": "#cbd5e1",
  "--tab-bg": "#ffffff",
  "--tab-text": "#1e293b",
  "--tab-hover": "#eff6ff",
  "--shadow": "0 12px 30px rgba(15,23,42,.08)",
};

const darkThemeVars = {
  "--page-bg": "#020617",
  "--card-bg": "#0f172a",
  "--card-border": "#1e293b",
  "--text": "#e5e7eb",
  "--muted": "#94a3b8",
  "--soft-bg": "#111827",
  "--code-bg": "#020617",
  "--code-text": "#dbeafe",
  "--input-border": "#334155",
  "--tab-bg": "#0f172a",
  "--tab-text": "#cbd5e1",
  "--tab-hover": "#172554",
  "--shadow": "0 18px 40px rgba(0,0,0,.35)",
};

const styles = {
  page: { minHeight: "100vh", background: "var(--page-bg)", color: "var(--text)", fontFamily: "Inter, Arial, sans-serif", padding: "28px", transition: "background .2s ease, color .2s ease" },
  header: { maxWidth: 1180, margin: "0 auto 24px", background: "linear-gradient(135deg,#0f172a,#1d4ed8,#2563eb)", color: "white", borderRadius: 24, padding: "30px 34px", display: "flex", justifyContent: "space-between", gap: 20, alignItems: "center", boxShadow: "0 22px 50px rgba(15,23,42,.28)" },
  logoWrap: { display: "flex", gap: 18, alignItems: "center" },
  logoMark: { width: 54, height: 54, borderRadius: 18, background: "rgba(255,255,255,.16)", border: "1px solid rgba(255,255,255,.22)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 28, boxShadow: "inset 0 1px 0 rgba(255,255,255,.2)" },
  brand: { textTransform: "uppercase", letterSpacing: 2, fontSize: 12, opacity: .82, fontWeight: 800 },
  title: { margin: "6px 0", fontSize: 42, lineHeight: 1, color: "white", fontWeight: 900 },
  subtitle: { margin: 0, color: "#dbeafe", maxWidth: 760, fontSize: 16, lineHeight: 1.45 },
  headerActions: { display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap", justifyContent: "flex-end" },
  headerBadge: { background: "rgba(255,255,255,.12)", border: "1px solid rgba(255,255,255,.22)", padding: "10px 14px", borderRadius: 999, fontWeight: 800, whiteSpace: "nowrap" },
  themeButton: { background: "rgba(255,255,255,.95)", color: "#0f172a", border: 0, borderRadius: 999, padding: "10px 14px", fontWeight: 800, cursor: "pointer", boxShadow: "0 8px 18px rgba(15,23,42,.18)" },

  tabs: { maxWidth: 1180, margin: "0 auto 26px", display: "flex", flexWrap: "wrap", gap: 12, background: "transparent", padding: 0, borderRadius: 999 },
  tab: { border: "1px solid var(--card-border)", background: "var(--tab-bg)", color: "var(--tab-text)", borderRadius: 999, padding: "14px 20px", fontWeight: 850, cursor: "pointer", display: "flex", alignItems: "center", gap: 9, boxShadow: "var(--shadow)", minHeight: 52, transition: "transform .15s ease, background .15s ease, border .15s ease, color .15s ease" },
  tabActive: { background: "linear-gradient(135deg,#2563eb,#1d4ed8)", color: "white", border: "1px solid #2563eb", boxShadow: "0 14px 30px rgba(37,99,235,.35)", transform: "translateY(-1px)" },
  tabIcon: { fontSize: 18, lineHeight: 1 },

  grid: { maxWidth: 1180, margin: "0 auto", display: "grid", gridTemplateColumns: "1.3fr .9fr", gap: 22 },
  leftColumn: { display: "flex", flexDirection: "column", gap: 20 },
  rightColumn: { display: "flex", flexDirection: "column", gap: 20 },
  card: { background: "var(--card-bg)", border: "1px solid var(--card-border)", borderRadius: 20, padding: 24, boxShadow: "var(--shadow)" },
  cardTitle: { margin: 0, fontSize: 22, color: "var(--text)", fontWeight: 850 },
  cardDescription: { marginTop: 6, marginBottom: 18, color: "var(--muted)", lineHeight: 1.45 },
  searchRow: { display: "flex", gap: 10 },
  searchInput: { flex: 1, fontSize: 17, padding: "13px 14px", border: "1px solid var(--input-border)", borderRadius: 12, background: "var(--card-bg)", color: "var(--text)", outline: "none" },
  inputGroup: { marginTop: 20 },
  input: { width: "100%", boxSizing: "border-box", fontSize: 15, padding: "11px 12px", border: "1px solid var(--input-border)", borderRadius: 12, background: "var(--card-bg)", color: "var(--text)", outline: "none" },
  label: { display: "block", fontWeight: 800, marginBottom: 8, color: "var(--text)" },
  inlineRow: { display: "flex", gap: 8 },
  formGrid: { display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 14 },
  primaryButton: { background: "linear-gradient(135deg,#2563eb,#1d4ed8)", color: "white", border: 0, borderRadius: 12, padding: "0 18px", fontWeight: 800, cursor: "pointer", whiteSpace: "nowrap", boxShadow: "0 10px 20px rgba(37,99,235,.25)" },
  secondaryButton: { background: "#111827", color: "white", border: 0, borderRadius: 12, padding: "0 14px", fontWeight: 800, cursor: "pointer" },
  providerGrid: { display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 10 },
  providerButton: { textAlign: "left", background: "var(--soft-bg)", color: "var(--text)", border: "1px solid var(--card-border)", borderRadius: 14, padding: 13, cursor: "pointer", display: "flex", flexDirection: "column", gap: 4, overflow: "hidden" },
  providerCode: { display: "block", background: "var(--code-bg)", color: "var(--code-text)", border: "1px solid var(--card-border)", borderRadius: 8, padding: "8px 10px", fontFamily: "Consolas, monospace", fontSize: 13, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" },
  providerActive: { background: "var(--tab-hover)", border: "1px solid #2563eb", boxShadow: "inset 0 0 0 1px #2563eb" },
  recordList: { marginTop: 14 },
  inlineCheck: { display: "flex", gap: 8, alignItems: "center", marginTop: 12, fontWeight: 800, color: "var(--text)" },
  smallCode: { background: "var(--soft-bg)", border: "1px solid var(--card-border)", color: "var(--text)", padding: 12, borderRadius: 12, fontFamily: "Consolas, monospace", wordBreak: "break-all", marginTop: 8 },
  largeCode: { background: "var(--code-bg)", color: "var(--code-text)", padding: 16, borderRadius: 14, fontFamily: "Consolas, monospace", whiteSpace: "pre-wrap", wordBreak: "break-all", lineHeight: 1.5 },
  dnsBox: { background: "var(--soft-bg)", border: "1px solid var(--card-border)", color: "var(--text)", borderRadius: 14, padding: 12, display: "grid", gap: 6, marginBottom: 12, fontSize: 14 },
  copyButton: { width: "100%", background: "linear-gradient(135deg,#16a34a,#15803d)", color: "white", border: 0, borderRadius: 12, padding: 12, fontWeight: 900, cursor: "pointer", boxShadow: "0 10px 20px rgba(22,163,74,.2)" },
  metrics: { display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 8, marginBottom: 14 },
  metric: { background: "var(--soft-bg)", border: "1px solid var(--card-border)", borderRadius: 14, padding: 10, display: "flex", flexDirection: "column", gap: 4, color: "var(--text)" },
  metricDanger: { background: "#fff7ed", borderColor: "#fb923c", color: "#9a3412" },
  warning: { background: "#fff7ed", border: "1px solid #fb923c", color: "#9a3412", padding: 10, borderRadius: 12, marginTop: 8, lineHeight: 1.35 },
  good: { background: "#ecfdf5", border: "1px solid #86efac", color: "#166534", padding: 10, borderRadius: 12, marginTop: 8 },
  notice: { background: "#eff6ff", color: "#1e40af", border: "1px solid #bfdbfe", padding: 10, borderRadius: 12, marginTop: 8, lineHeight: 1.35 },
  status: { marginTop: 12, borderRadius: 12, padding: 12, fontWeight: 800 },
  success: { background: "#ecfdf5", color: "#166534", border: "1px solid #86efac" },
  error: { background: "#fef2f2", color: "#991b1b", border: "1px solid #fecaca" },
  tags: { display: "flex", flexWrap: "wrap", gap: 8, marginTop: 10 },
  tag: { background: "#eef2ff", color: "#3730a3", padding: "7px 9px", borderRadius: 999, fontFamily: "Consolas, monospace", fontSize: 13 },
  tagButton: { marginLeft: 8, border: 0, background: "transparent", cursor: "pointer", color: "#3730a3", fontWeight: 900 },
  findingGrid: { display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 10 },
  finding: { background: "var(--soft-bg)", border: "1px solid var(--card-border)", borderRadius: 14, padding: 12, display: "flex", flexDirection: "column", gap: 6, wordBreak: "break-word", color: "var(--text)" },
  intelCard: { background: "var(--soft-bg)", border: "1px solid var(--card-border)", borderRadius: 14, padding: 12, marginTop: 12, color: "var(--text)" },
  riskPill: { borderRadius: 999, padding: "4px 9px", fontSize: 12, fontWeight: 800 },
  riskLow: { background: "#dcfce7", color: "#166534" },
  riskReview: { background: "#fef3c7", color: "#92400e" },
  riskHigh: { background: "#fee2e2", color: "#991b1b" },
  scoreCircle: { width: 120, height: 120, borderRadius: "50%", background: "linear-gradient(135deg,#2563eb,#1d4ed8)", color: "white", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 42, fontWeight: 900, margin: "0 auto 18px" },
  tableWrap: { overflowX: "auto", border: "1px solid var(--card-border)", borderRadius: 14 },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 14, color: "var(--text)" },
  th: { textAlign: "left", background: "var(--soft-bg)", color: "var(--text)", padding: 12, borderBottom: "1px solid var(--card-border)" },
  td: { padding: 12, borderBottom: "1px solid var(--card-border)", verticalAlign: "top", color: "var(--text)" },
};
