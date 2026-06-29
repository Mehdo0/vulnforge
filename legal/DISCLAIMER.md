# Legal Disclaimer — VulnForge

## ⚠️ IMPORTANT — READ BEFORE USING

VulnForge performs **real security testing** against live targets. This is not a simulation.

---

## Swiss Legal Framework

### Swiss Penal Code — Art. 143bis (Unauthorized Access to a Data Processing System)

> Any person who, without authorization, accesses a data processing system that is specially secured against unauthorized access by means of data transmission shall be liable to a custodial sentence not exceeding three years or to a monetary penalty.

**What this means for you:**
- Scanning a website you do not own or are not authorized to test is a **criminal offense** in Switzerland
- Penalty: up to **3 years imprisonment** or monetary fine
- This applies regardless of whether you use VulnForge, manual tools, or any other method

### Art. 143 (Unauthorized Obtaining of Data)

> Any person who, without authorization, obtains data for himself or for another from a data processing system that is specially secured against unauthorized access shall be liable to a custodial sentence not exceeding five years or to a monetary penalty.

### Art. 144bis (Damage to Data)

> Any person who, without authorization, alters, deletes, or renders unusable data that is stored or transmitted electronically shall be liable to a custodial sentence.

---

## EU Legal Framework

### Directive 2013/40/EU (Attacks Against Information Systems)

EU member states criminalize:
- Illegal access to information systems (Art. 3)
- Illegal system interference (Art. 4)
- Illegal data interference (Art. 5)

Penalties: minimum 2-5 years imprisonment for intentional offenses.

---

## VulnForge's Position

### We Require Explicit Consent

VulnForge will **NOT** initiate any scan without:
1. A signed **Consent & Authorization Form**
2. **Domain ownership verification** (DNS TXT, file upload, or email)
3. **Scope definition** — exact URLs/IPs to test

### We Design for Safety

Our agents are programmed to:
- **Minimize impact** — non-destructive testing, no data exfiltration
- **Respect scope** — never test URLs outside the defined scope
- **Rate limit** — avoid overwhelming target servers
- **Identify themselves** — custom User-Agent header: `VulnForge-Scanner/1.0`

### We Report, We Don't Exploit

- Findings are reported to the Client only
- We never sell, share, or exploit discovered vulnerabilities
- We never maintain access to tested systems

---

## What Happens If You Violate These Rules

If VulnForge detects that a Client has submitted a Target without authorization:
1. The scan is **immediately terminated**
2. The Client's account is **permanently suspended**
3. We **reserve the right** to report the incident to relevant authorities
4. The Client assumes **full legal liability**

---

## The "Good Faith" Principle

VulnForge exists to help organizations **improve** their security posture. We operate on good faith:

- We trust Clients to submit only authorized Targets
- We design agents to be as safe and non-destructive as possible
- We provide clear, actionable reports to fix problems, not to shame

**Security testing without consent is not hacking — it's a crime. Don't do it.** Use VulnForge responsibly.

---

*If you have questions about the legal aspects of security testing, consult a qualified attorney. This document does not constitute legal advice.*
