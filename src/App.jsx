import React, { useMemo, useState } from "react";

const PROVIDERS = [
  { name: "Microsoft 365", include: "spf.protection.outlook.com" },
  { name: "Google Workspace", include: "_spf.google.com" },
  { name: "Proofpoint", include: "spf.protection.proofpoint.com" },
  { name: "Mailchimp", include: "servers.mcsv.net" },
  { name: "SendGrid", include: "sendgrid.net" },
  { name: "Salesforce", include: "_spf.salesforce.com" },
  { name: "Zendesk", include: "mail.zendesk.com" },
  { name: "HubSpot", include: "spf.hubspotemail.net" },
];

function uniqueClean(values) {
  return [...new Set(values.map(v => String(v).trim()).filter(Boolean))];
}

function parseSPF(spf) {
  const parts = spf.split(" ");
  return {
    includes: parts.filter(p => p.startsWith("include:")).map(p => p.replace("include:", "")),
    ip4: parts.filter(p => p.startsWith("ip4:")).map(p => p.replace("ip4:", "")),
    policy: parts.find(p => p.includes("all")) || "~all"
  };
}

function buildSPF({ includes, ip4, policy }) {
  return [
    "v=spf1",
    "mx",
    ...uniqueClean(ip4).map(ip => `ip4:${ip}`),
    ...uniqueClean(includes).map(i => `include:${i}`),
    policy
  ].join(" ");
}

export default function App() {
  const [domain, setDomain] = useState("example.com");
  const [existing, setExisting] = useState("");
  const [includes, setIncludes] = useState([]);
  const [ip4, setIp4] = useState([]);
  const [ipInput, setIpInput] = useState("");
  const [policy, setPolicy] = useState("~all");

  async function lookup() {
    try {
      const res = await fetch(`https://dns.google/resolve?name=${domain}&type=TXT`);
      const data = await res.json();

      const spf = data.Answer?.map(a => a.data)
        .find(txt => txt.includes("v=spf1"));

      if (!spf) {
        alert("No SPF found");
        return;
      }

      const clean = spf.replace(/"/g, "");
      setExisting(clean);

      const parsed = parseSPF(clean);
      setIncludes(parsed.includes);
      setIp4(parsed.ip4);
      setPolicy(parsed.policy);
    } catch {
      alert("Lookup failed");
    }
  }

  function addIP() {
    if (!ipInput) return;
    setIp4(prev => [...prev, ipInput]);
    setIpInput("");
  }

  const mergedIncludes = useMemo(() => {
    return uniqueClean([
      ...includes,
      ...PROVIDERS.filter(p => p.selected).map(p => p.include)
    ]);
  }, [includes]);

  const record = buildSPF({
    includes: mergedIncludes,
    ip4,
    policy
  });

  return (
    <div style={{ maxWidth: 700, margin: "auto", padding: 20 }}>
      <h1>SPF Lookup + Merge</h1>

      <input value={domain} onChange={e => setDomain(e.target.value)} />
      <button onClick={lookup}>Lookup SPF</button>

      {existing && (
        <>
          <h3>Existing SPF</h3>
          <pre>{existing}</pre>
        </>
      )}

      <h3>Add IP</h3>
      <input value={ipInput} onChange={e => setIpInput(e.target.value)} />
      <button onClick={addIP}>Add</button>

      <h3>Policy</h3>
      <select value={policy} onChange={e => setPolicy(e.target.value)}>
        <option value="~all">~all</option>
        <option value="-all">-all</option>
      </select>

      <h3>Merged SPF</h3>
      <pre>{record}</pre>
    </div>
  );
}
