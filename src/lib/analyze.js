// Local pattern checks only. This module never fetches a URL or executes input.
// Pattern rationale: https://support.microsoft.com/en-gb/security/protect-yourself-from-phishing
// and https://consumer.ftc.gov/articles/how-spot-avoid-and-report-tech-support-scams

const URL_LIMIT = 4096;
const MESSAGE_LIMIT = 20000;
const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at', 'rebrand.ly']);
const BRANDS = [
  { name: 'PayPal', token: /paypal/i, domains: ['paypal.com', 'paypal.me'] },
  { name: 'Microsoft', token: /microsoft/i, domains: ['microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'azure.com', 'windows.com'] },
  { name: 'Apple', token: /(?:^|[.-])apple(?:[.-]|$)/i, domains: ['apple.com', 'icloud.com'] },
  { name: 'Google', token: /google/i, domains: ['google.com', 'google.co.uk', 'google.de', 'google.at', 'google.fr', 'google.ca', 'google.com.au', 'google.co.in', 'google.co.jp', 'googleapis.com', 'googleusercontent.com', 'withgoogle.com', 'blog.google'] },
  { name: 'Amazon', token: /amazon/i, domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.at', 'amazon.fr', 'amazon.ca', 'amazon.com.au', 'amazon.in', 'amazon.co.jp', 'amazon.es', 'amazon.it', 'amazon.nl', 'amazonaws.com'] },
  { name: 'Coinbase', token: /coinbase/i, domains: ['coinbase.com'] },
];

function result(kind, fields = {}) {
  return {
    kind,
    verdict: 'low',
    title: 'No obvious warning signs',
    summary: kind === 'url'
      ? 'Local address patterns only. No reputation lookup or live page check was performed; this does not establish that a site is safe.'
      : 'Local text patterns only. Sender identity and linked pages were not verified; this does not establish that a message is genuine.',
    score: 0,
    signals: [],
    checkedAt: new Date().toISOString(),
    advice: [],
    ...fields,
  };
}

function invalid(kind, detail) {
  return result(kind, {
    verdict: 'invalid', title: kind === 'url' ? 'Enter a valid web address' : 'Enter a message to check',
    summary: detail,
    advice: [kind === 'url' ? 'Paste one HTTP or HTTPS address, or a domain such as example.com.' : 'Paste the message as text. Links will not be opened.'],
  });
}

function finish(kind, score, signals, fields = {}) {
  const bounded = Math.max(0, Math.min(100, Math.round(score)));
  const verdict = bounded >= 60 ? 'high' : bounded >= 25 ? 'medium' : 'low';
  return result(kind, {
    ...fields,
    score: bounded,
    signals,
    verdict,
    title: verdict === 'high' ? 'Strong warning signs detected' : verdict === 'medium' ? 'Review before you proceed' : 'No obvious warning signs',
  });
}

function underDomain(hostname, domain) {
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

function decodeForInspection(value) {
  try { return decodeURIComponent(value); } catch { return value; }
}

export function analyzeUrl(input) {
  if (typeof input !== 'string' || !input.trim()) return invalid('url', 'Enter a web address to inspect locally.');
  if (input.length > URL_LIMIT) return invalid('url', `Keep the address under ${URL_LIMIT + 1} characters.`);
  const raw = input.trim();
  if (/[\u0000-\u0020\u007f<>"`]/.test(raw)) return invalid('url', 'The address contains whitespace, control characters, or markup. Paste only the web address.');
  let candidate = raw;
  const explicitScheme = /^[a-z][a-z\d+.-]*:/i.test(raw);
  const bareHostWithPort = /^[a-z\d.-]+:\d+(?:[/?#]|$)/i.test(raw);
  if (explicitScheme && !bareHostWithPort && !/^https?:\/\//i.test(raw)) {
    return invalid('url', 'Only HTTP and HTTPS web addresses are supported.');
  }
  if (!explicitScheme || bareHostWithPort) candidate = raw.startsWith('//') ? `https:${raw}` : `https://${raw}`;
  let url;
  try { url = new URL(candidate); } catch { return invalid('url', 'This address could not be parsed. Check the hostname and formatting.'); }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) return invalid('url', 'Only HTTP and HTTPS addresses with a hostname are supported.');
  const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  const isIp = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.startsWith('[');
  if (!isIp && (hostname.includes('..') || hostname.split('.').some(label => !label || label.length > 63 || !/^[a-z\d](?:[a-z\d-]*[a-z\d])?$/.test(label)) || hostname.length > 253)) {
    return invalid('url', 'The hostname is not a valid web hostname.');
  }
  // A single word is usually a pasted sentence fragment, not a public web link.
  if (!isIp && !hostname.includes('.') && hostname !== 'localhost') return invalid('url', 'Use a complete hostname, such as example.com.');

  const signals = [];
  let score = 0;
  const add = (id, title, detail, severity, weight) => { signals.push({ id, title, detail, severity }); score += weight; };
  if (url.username || url.password || /^[a-z]+:\/\/[^/?#]*@/i.test(candidate)) {
    add('embedded-credentials', 'Misleading address before @', `Text before @ is not the destination. The actual hostname is ${hostname}.`, 'high', 65);
  }
  if (isIp) add('ip-address', 'Numeric network destination', 'This link uses an IP address instead of a recognizable domain. Local devices can also use these addresses.', 'medium', 28);
  if (hostname.split('.').some(part => part.startsWith('xn--')) || /[^\x00-\x7f]/.test(candidate.split('/')[2] || '')) {
    add('international-host', 'Internationalized hostname', 'Internationalized domains can be legitimate, but similar-looking characters can disguise another address. Compare the exact hostname.', 'low', 14);
  }
  if (url.protocol === 'http:') add('unencrypted-http', 'Connection is not encrypted', 'HTTP does not protect data in transit. Avoid entering passwords or payment details.', 'medium', 16);

  for (const brand of BRANDS) {
    if (brand.token.test(hostname) && !brand.domains.some(domain => underDomain(hostname, domain))) {
      add(`brand-${brand.name.toLowerCase()}`, `Possible ${brand.name} lookalike`, `The hostname mentions ${brand.name} but is outside the common domains in ATGuard's local list. The list is incomplete; independently verify ownership.`, 'medium', 42);
      break;
    }
  }
  if (!isIp && hostname.split('.').length >= 6) add('many-subdomains', 'Complex hostname', 'Many hostname segments can hide the real destination. Read the entire hostname, especially its ending.', 'low', 12);
  if ([...SHORTENERS].some(domain => underDomain(hostname, domain))) add('shortened-link', 'Destination is hidden by a short link', 'The final destination is unknown. ATGuard does not follow redirects or expand shortened links.', 'medium', 28);
  const path = decodeForInspection(`${url.pathname}${url.search}`).toLowerCase();
  if (/(?:^|[\W_])(?:login|log-in|signin|sign-in|verify|verification|password|wallet|payment|billing|account|refund)(?:[\W_]|$)/i.test(path)) {
    add('sensitive-path', 'Account or payment wording', 'The path mentions an account, sign-in, or payment action. This is common on genuine sites too and is not evidence of fraud by itself.', 'info', 6);
  }
  if (signals.some(signal => signal.id.startsWith('brand-')) && signals.some(signal => ['sensitive-path', 'unencrypted-http'].includes(signal.id))) score += 14;
  return finish('url', score, signals, {
    // Omit user-info from the returned address to avoid persisting pasted secrets.
    normalizedUrl: `${url.protocol}//${url.host}${url.pathname}${url.search}${url.hash}`,
    hostname,
    advice: [
      'For sign-in or payments, use a saved bookmark or type the organization’s known address yourself.',
      'Verify unexpected requests through a separate, trusted contact method.',
      'A low score is not a safety guarantee. HTTPS alone does not prove a site is genuine.',
    ],
  });
}

function actionableClauses(text) {
  // Negation must directly modify an action. "Do not delay; send your OTP"
  // does not negate "send". Contrast and punctuation start fresh clauses;
  // retain any request before a warning rather than deleting its sentence.
  const boundary = /(?<=[.!?])\s+|[;\r\n]+|\s+(?:but|however|instead|then)\s+|,\s*(?=(?:please\s+)?(?:send|share|give|enter|provide|transfer|pay|buy|purchase|install|download|reveal|submit|confirm|verify|tell|grant|allow|enable)\b)/i;
  const negatedAction = /\b(?:never|do not|don't|should not|shouldn't)\s+(?:(?:ever|blindly|willingly)\s+){0,2}(?:send|share|give|enter|provide|transfer|pay|buy|purchase|install|download|click|reveal|submit|confirm|verify|tell|grant|allow|enable)\b|\b(?:avoid|beware of)\s+(?:sending|sharing|giving|entering|providing|transferring|paying|buying|purchasing|installing|downloading|clicking|revealing|submitting|confirming|verifying|telling|granting|allowing|enabling)\b/i;
  return text.split(boundary).map(clause => {
    const negated = negatedAction.exec(clause);
    return negated ? clause.slice(0, negated.index) : clause;
  }).join('. ');
}

export function analyzeMessage(input) {
  if (typeof input !== 'string' || !input.trim()) return invalid('message', 'Paste an email, text message, or chat message to inspect locally.');
  if (input.length > MESSAGE_LIMIT) return invalid('message', `Keep the message under ${MESSAGE_LIMIT + 1} characters.`);
  const text = input.trim();
  const actionable = actionableClauses(text);
  const signals = [];
  let score = 0;
  const add = (id, title, detail, severity, weight) => { signals.push({ id, title, detail, severity }); score += weight; };
  const urgency = /\b(?:urgent|immediately|act now|right now|final warning|last chance|within (?:\d+|one|two|three|24|48) (?:minutes?|hours?)|account (?:will be |is )?(?:suspended|closed|locked)|today only)\b/i.test(actionable);
  const credential = /\b(?:send|share|give|provide|enter|confirm|reply with|tell|submit|verify)\b[^.!?\n]{0,80}\b(?:password|passcode|one[ -]time (?:password|code)|otp|verification code|security code|pin|credit card|card number|bank details|seed phrase|recovery phrase)\b/i.test(actionable);
  const transfer = /\b(?:send|transfer|wire|pay|deposit|move)\b[^.!?\n]{0,70}\b(?:money|funds|cash|payment|bitcoin|crypto(?:currency)?|wallet|safe account|bank account|\d+\s?(?:usd|eur|dollars|euros))\b/i.test(actionable) || /\b(?:wire transfer|bank transfer|transfer your savings)\b/i.test(actionable);
  const giftCard = /\b(?:buy|purchase|pay|send|provide)\b[^.!?\n]{0,60}\bgift ?cards?\b/i.test(actionable);
  const remote = /\b(?:install|download|grant|allow|enable|give)\b[^.!?\n]{0,65}\b(?:anydesk|teamviewer|remote (?:access|desktop|control)|screen sharing|support (?:app|tool))\b/i.test(actionable);
  const impersonation = /\b(?:(?:i am|i'm|we are|this is|from)\s+(?:the |your )?(?:microsoft|apple|amazon|paypal|bank|it support|technical support|tech support|fraud (?:team|department)|ceo|irs)|(?:your bank|microsoft support|apple support|fraud department|tax authority))\b/i.test(actionable);
  const secrecy = /\b(?:do not tell|don't tell|keep (?:this|it) (?:a )?secret|keep this confidential|do not contact (?:your |the )?bank)\b/i.test(text);
  if (urgency) add('urgency', 'Pressure to act quickly', 'Deadlines or threats can discourage you from checking a request. Urgency alone does not establish fraud.', 'medium', 14);
  if (credential) add('credentials', 'Request for sensitive information', 'The text asks for a password, authentication code, financial information, or recovery phrase. Independently verify the request; do not share sign-in codes.', 'high', 36);
  if (transfer) add('money-transfer', 'Money transfer request', 'The text discusses sending money or moving funds. Confirm the recipient and purpose through a trusted channel.', 'medium', 22);
  if (giftCard) add('gift-cards', 'Gift card payment request', 'Requests to buy or send gift cards can be a scam payment tactic. Verify who is asking and why.', 'high', 35);
  if (remote) add('remote-access', 'Remote access request', 'The message asks you to install or enable a remote access tool. An unknown caller could use this to control your device.', 'high', 30);
  if (impersonation) add('impersonation', 'Claim of a trusted identity', 'The text claims an organizational or trusted role. ATGuard cannot verify the sender’s identity from pasted text.', 'info', 10);
  if (secrecy) add('secrecy', 'Pressure to keep the request secret', 'Discouraging independent advice is a warning sign, especially alongside money or access requests.', 'medium', 18);
  if ((credential && urgency) || (remote && (transfer || impersonation)) || (giftCard && (urgency || impersonation)) || (transfer && secrecy)) score += 15;

  const urls = [...new Set((text.match(/(?:https?:\/\/|www\.)[^\s<>"'`]+/gi) || []).map(value => value.replace(/[.,!?;:)\]}]+$/, '')))];
  const inspected = urls.slice(0, 12).map(analyzeUrl).filter(item => item.verdict !== 'invalid');
  const suspicious = inspected.filter(item => item.verdict === 'medium' || item.verdict === 'high');
  if (suspicious.length) {
    const worst = suspicious.reduce((left, right) => left.score > right.score ? left : right);
    const detail = `${suspicious.length} linked address${suspicious.length === 1 ? ' has' : 'es have'} local warning signs. Most concerning hostname: ${worst.hostname}. ${worst.signals.filter(signal => signal.severity !== 'info').map(signal => signal.title).slice(0, 2).join('; ')}. Links were not opened.`;
    add('suspicious-links', 'Linked address needs review', detail, worst.verdict === 'high' ? 'high' : 'medium', worst.verdict === 'high' ? 50 : 25);
    if (credential || transfer || giftCard) score += 10;
  }
  if (urls.length > 12) signals.push({ id: 'link-limit', title: 'Link inspection limit reached', detail: 'Only the first 12 unique web links were inspected. Check additional links individually.', severity: 'info' });
  return finish('message', score, signals, {
    advice: [
      'Pause before sending money, sharing codes, or granting remote access.',
      'Confirm the request using a phone number or app you already trust, not contact details in the message.',
      'If you already sent money or shared account access, contact your bank or service provider through its official channel.',
    ],
  });
}
