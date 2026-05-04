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

function buildSPFRecord({ mx, ipv4s, includes, allPolicy }) {
  const parts = ["v=spf1"];
  if (mx) parts.push("mx");
  uniqueClean(ipv4s).forEach(ip => parts.push(`ip4:${ip}`));
  uniqueClean(includes).forEach(inc => parts.push(`include:${inc}`));
  parts.push(allPolicy || "~all");
  return parts.join(" ");
}

export default function SPFRecordBuilder() {
  const [domain, setDomain] = useState("example.com");
  const [selectedProviders, setSelectedProviders] = useState(["Microsoft 365"]);
  const [ipv4s, setIpv4s] = useState([]);
  const [input, setInput] = useState("");
  const [allPolicy, setAllPolicy] = useState("~all");

  const includes = useMemo(() => {
    return PROVIDERS.filter(p => selectedProviders.includes(p.name)).map(p => p.include);
  }, [selectedProviders]);

  const record = useMemo(() => {
    return buildSPFRecord({ mx: true, ipv4s, includes, allPolicy });
  }, [ipv4s, includes, allPolicy]);

  function toggleProvider(name) {
    setSelectedProviders(prev =>
      prev.includes(name) ? prev.filter(p => p !== name) : [...prev, name]
    );
  }

  function addIP() {
    if (!input) return;
    setIpv4s(prev => uniqueClean([...prev, input]));
    setInput("");
  }

  return (
    <div style={{ padding: 20, fontFamily: "Arial" }}>
      <h1>SPF Record Builder</h1>

      <div>
        <h3>Domain</h3>
        <input value={domain} onChange={e => setDomain(e.target.value)} />
      </div>

      <div>
        <h3>Providers</h3>
        {PROVIDERS.map(p => (
          <div key={p.name}>
            <label>
              <input
                type="checkbox"
                checked={selectedProviders.includes(p.name)}
                onChange={() => toggleProvider(p.name)}
              />
              {p.name}
            </label>
          </div>
        ))}
      </div>

      <div>
        <h3>Add IP</h3>
        <input value={input} onChange={e => setInput(e.target.value)} />
        <button onClick={addIP}>Add</button>
      </div>

      <div>
        <h3>Policy</h3>
        <select value={allPolicy} onChange={e => setAllPolicy(e.target.value)}>
          <option value="~all">Soft fail (~all)</option>
          <option value="-all">Hard fail (-all)</option>
        </select>
      </div>

      <div style={{ marginTop: 20 }}>
        <h3>SPF Record</h3>
        <code>{record}</code>
      </div>
    </div>
  );
}

