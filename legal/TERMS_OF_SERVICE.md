# Terms of Service — VulnForge

**Last Updated:** June 29, 2026  
**Company:** VulnForge (to be registered, Switzerland)  

## 1. Definitions

- **"Platform"** — VulnForge, the automated security audit service accessible at vulnforge.io
- **"Client"** — Any individual or organization using the Platform
- **"Target"** — The website, application, API, repository, or infrastructure submitted for audit
- **"Audit"** — The automated penetration testing and vulnerability assessment performed by the Platform
- **"Findings"** — Vulnerabilities, misconfigurations, and security issues discovered during an Audit

## 2. Eligibility & Authorization

### 2.1 Ownership or Authorization
The Client represents and warrants that they:
- **Own** the Target; OR
- Have obtained **explicit written authorization** from the Target owner to perform security testing.

### 2.2 Proof of Authorization
Before any Audit begins, the Client MUST:
1. Upload a signed **Consent Form** (provided by VulnForge) authorizing the scan
2. Verify domain ownership via DNS TXT record, file upload, or email verification

### 2.3 Prohibited Targets
The Client MAY NOT submit:
- Targets they do not own or lack authorization to test
- Government, military, or critical infrastructure systems without explicit sector-specific authorization
- Healthcare systems containing protected health information (unless HIPAA/GDPR compliant)

## 3. Scope of Service

### 3.1 What We Do
VulnForge performs **automated security audits** using AI-powered agents. This includes:
- Reconnaissance (subdomain enumeration, port scanning, technology detection)
- Web application testing (XSS, SQLi, CSRF, etc.)
- API security analysis
- Configuration auditing (TLS, headers, CORS)
- Code repository scanning (secrets, vulnerable dependencies)

### 3.2 What We Do NOT Do
- Manual penetration testing by human experts
- Physical security testing
- Social engineering
- Denial of Service (DoS) attacks
- Exploitation that modifies, deletes, or exfiltrates data
- Guarantee of finding all vulnerabilities

### 3.3 Limitations
- Audits are **point-in-time assessments** — new vulnerabilities may emerge after the audit
- False positives may occur — all findings should be manually verified
- The Platform does not guarantee compliance with any specific regulatory framework (PCI-DSS, HIPAA, etc.)

## 4. Client Responsibilities

The Client agrees to:
1. Provide **accurate scope** — only submit URLs/systems they are authorized to test
2. **Notify relevant teams** — inform their IT/security team that a scan is in progress
3. **Back up data** — VulnForge is not responsible for data loss during testing (though we design agents to be non-destructive)
4. **Review findings** — not all findings may be exploitable in their specific context
5. **Remediate** — VulnForge provides recommendations but does not fix vulnerabilities (except Gold tier)

## 5. Limitation of Liability

### 5.1 Disclaimer
THE PLATFORM IS PROVIDED "AS IS". VULNFORGE MAKES NO WARRANTIES, EXPRESS OR IMPLIED, REGARDING THE COMPLETENESS, ACCURACY, OR RELIABILITY OF AUDIT FINDINGS.

### 5.2 Liability Cap
TO THE MAXIMUM EXTENT PERMITTED BY SWISS LAW, VULNFORGE'S TOTAL LIABILITY FOR ANY CLAIM ARISING FROM THE USE OF THE PLATFORM SHALL NOT EXCEED THE FEES PAID BY THE CLIENT FOR THE SPECIFIC AUDIT IN QUESTION.

### 5.3 Indirect Damages
VULNFORGE SHALL NOT BE LIABLE FOR INDIRECT, INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, DATA LOSS, OR BUSINESS INTERRUPTION.

### 5.4 Third-Party Targets
If a Client submits a Target they do not own or lack authorization to test, the Client assumes **full legal liability** for any consequences, including criminal prosecution under Swiss Penal Code Art. 143bis (unauthorized access to computer systems).

## 6. Data Handling & Privacy

### 6.1 Scan Data
- Findings and scan artifacts are stored for **30 days** after audit completion
- Clients may request immediate deletion at any time
- Scan data is encrypted at rest and in transit

### 6.2 Personal Data
- VulnForge processes personal data in accordance with our **Privacy Policy** and the **Swiss Federal Act on Data Protection (FADP)** / **EU GDPR** where applicable
- We do not sell, share, or use Client data for any purpose other than providing the Audit service

### 6.3 Confidentiality
- All Findings are confidential to the Client
- VulnForge will not disclose Findings to any third party without explicit Client consent
- VulnForge may use anonymized, aggregated data for platform improvement

## 7. Payment Terms

### 7.1 Pricing
- Audit pricing is based on token consumption + service margin
- An **estimated cost** is provided before the Audit begins
- Final cost is calculated after Audit completion

### 7.2 Payment Methods
- Credit/debit card via Stripe
- Invoice for enterprise clients (Net 30)

### 7.3 Refunds
- Refunds are evaluated on a case-by-case basis
- Technical failures on VulnForge's side: full refund
- Client dissatisfaction with findings: at VulnForge's discretion

## 8. Termination

VulnForge reserves the right to:
- Suspend or terminate access for **Terms of Service violations**
- Refuse service to any Client for any reason
- Cancel an in-progress Audit if unauthorized targeting is suspected

## 9. Governing Law

These Terms are governed by the laws of **Switzerland**. Any disputes shall be resolved in the courts of **Lausanne, Vaud, Switzerland**.

## 10. Contact

For legal inquiries: legal@vulnforge.io (to be configured)

---

*By using VulnForge, you acknowledge that you have read, understood, and agree to these Terms of Service.*
