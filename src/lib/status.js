export function protectionChecks(status) {
  if (!status) return [];
  const d = status.defender || {};
  const f = status.firewall || {};
  const threats = status.threats || {};
  const defenderAvailable = d.available === true;
  const flag = (value) => value === true ? 'good' : value === false ? 'warning' : 'unknown';
  const profiles = Array.isArray(f.profiles) ? f.profiles : [];
  const firewallAvailable = f.available === true && profiles.length > 0;
  const signatureAgeKnown = defenderAvailable && Number.isFinite(d.signatureAgeDays) && d.signatureAgeDays >= 0 && d.signatureAgeDays < 65535;
  const items = Array.isArray(threats.items) ? threats.items : null;
  const threatsAvailable = threats.available === true && items !== null;
  const activeThreat = threatsAvailable && items.some(t => t?.active === true);
  const unknownThreat = threatsAvailable && items.some(t => t?.active !== true && t?.active !== false);
  return [
    { id: 'antivirus', title: 'Antivirus engine', state: defenderAvailable ? flag(d.antivirusEnabled) : 'unknown', detail: defenderAvailable ? d.antivirusEnabled === true ? 'Microsoft Defender Antivirus is enabled.' : d.antivirusEnabled === false ? 'Defender Antivirus is off or another provider is in use. Review Windows Security.' : 'Defender did not report its antivirus state.' : d.error || 'Defender status is not available.' },
    { id: 'realtime', title: 'Real-time protection', state: defenderAvailable ? flag(d.realTimeEnabled) : 'unknown', detail: defenderAvailable ? d.realTimeEnabled === true ? 'Defender is monitoring files as they are used.' : d.realTimeEnabled === false ? 'Defender real-time monitoring is off. Review your antivirus provider.' : 'The real-time protection state was not reported.' : d.error || 'Real-time protection status is not available.' },
    { id: 'behavior', title: 'Behavior monitoring', state: defenderAvailable ? flag(d.behaviorMonitorEnabled) : 'unknown', detail: defenderAvailable ? d.behaviorMonitorEnabled === true ? 'Defender behavior monitoring is enabled.' : d.behaviorMonitorEnabled === false ? 'Defender behavior monitoring is off.' : 'Behavior monitoring state was not reported.' : 'Behavior monitoring status is not available.' },
    { id: 'firewall', title: 'Windows Firewall', state: firewallAvailable ? profiles.every(p => p?.enabled === true) ? 'good' : profiles.some(p => p?.enabled === false) ? 'warning' : 'unknown' : 'unknown', detail: firewallAvailable ? profiles.map(p => `${p?.name || 'Unknown profile'}: ${p?.enabled === true ? 'on' : p?.enabled === false ? 'off' : 'unknown'}`).join(' · ') : f.error || 'Firewall status is not available.' },
    { id: 'signatures', title: 'Security intelligence', state: signatureAgeKnown ? d.signatureAgeDays <= 3 ? 'good' : 'warning' : 'unknown', detail: signatureAgeKnown ? `Defender signatures were updated ${d.signatureAgeDays === 0 ? 'today' : `${d.signatureAgeDays} day${d.signatureAgeDays === 1 ? '' : 's'} ago`}.` : 'Signature freshness was not reported.' },
    { id: 'threats', title: 'Known active threats', state: !threatsAvailable ? 'unknown' : activeThreat ? 'danger' : unknownThreat ? 'unknown' : 'good', detail: !threatsAvailable ? threats.error || 'Threat history is not available.' : activeThreat ? 'Defender reports active threats. Open Windows Security to review and remediate.' : unknownThreat ? 'Defender returned threat records without a confirmed active or inactive state. Review protection history in Windows Security.' : 'No active threats were reported by Defender at this check.' },
  ];
}
export function overallStatus(checks) {
  if (!checks.length) return { state: 'unknown', label: 'Not checked', description: 'Run a security check to see your protection status.' };
  if (checks.some(c => c.state === 'danger')) return { state: 'danger', label: 'Action needed', description: 'Windows Defender reports active threats that need your attention.' };
  if (checks.some(c => c.state === 'warning')) return { state: 'warning', label: 'Needs attention', description: 'Some protection settings need a closer look.' };
  if (checks.every(c => c.state === 'unknown')) return { state: 'unknown', label: 'Not verified', description: 'Protection checks are unavailable. Review the details and Windows Security to verify your protection.' };
  if (checks.some(c => c.state === 'unknown')) return { state: 'unknown', label: 'Partially verified', description: 'Some checks are unavailable. Review the details to see what is verified.' };
  return { state: 'good', label: 'Checks passed', description: 'Your reported Windows protection settings are enabled and up to date.' };
}
