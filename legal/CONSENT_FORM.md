# Security Audit Consent & Authorization Form

**This document must be signed before any audit begins.**

---

## Authorizing Party

| Field | Value |
|-------|-------|
| **Company/Individual Name** | _________________________________ |
| **Authorized Signatory** | _________________________________ |
| **Title/Position** | _________________________________ |
| **Email** | _________________________________ |
| **Phone** | _________________________________ |
| **Date** | _________________________________ |

## Target Specification

| Field | Value |
|-------|-------|
| **Primary Target URL** | _________________________________ |
| **Additional URLs/Domains** | _________________________________ |
| **IP Ranges (if applicable)** | _________________________________ |
| **GitHub Repositories** | _________________________________ |
| **Excluded URLs/Paths** | _________________________________ |

## Audit Scope

- [ ] Web Application Security (OWASP Top 10)
- [ ] API Security
- [ ] Infrastructure / Network Security
- [ ] Cloud Configuration
- [ ] Code Repository Analysis
- [ ] TLS / SSL Configuration
- [ ] Authentication & Authorization

## Authorization Statement

I, the undersigned, hereby:

1. **Confirm ownership or authorization** — I am the owner of the Target(s) listed above, or I have been duly authorized by the owner to commission this security audit.

2. **Authorize testing** — I authorize VulnForge to perform automated security testing, including but not limited to:
   - Port scanning and service enumeration
   - Web application vulnerability scanning
   - Automated payload injection (non-destructive)
   - Configuration and header analysis
   - Repository scanning (if applicable)

3. **Acknowledge risks** — I understand that:
   - Automated scanning may generate log entries, trigger alerts, or cause temporary performance impact
   - Non-destructive testing will be used; however, rare edge cases may cause unexpected behavior
   - I am responsible for notifying my IT/security team before the audit begins

4. **Accept Terms** — I have read and accept VulnForge's [Terms of Service](TERMS_OF_SERVICE.md) and [Privacy Policy](PRIVACY_POLICY.md).

5. **Indemnify** — I agree to indemnify and hold harmless VulnForge against any claims arising from testing of Targets I am not authorized to test.

---

## Legal Notice

**Swiss Penal Code Art. 143bis** — Unauthorized access to a data processing system is a criminal offense punishable by imprisonment of up to three years or a monetary penalty.

By signing below, you confirm under penalty of law that you are authorized to commission security testing of the Target(s) listed above.

---

| | |
|---|---|
| **Signature:** ________________________ | **Date:** ________________________ |
| **Printed Name:** ________________________ | |

---

## For VulnForge Internal Use

| Field | Value |
|-------|-------|
| **Consent Verified By** | _________________________________ |
| **Verification Method** | [ ] DNS TXT [ ] File Upload [ ] Email |
| **Verification Date** | _________________________________ |
| **Scan ID** | _________________________________ |
