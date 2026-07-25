# CesaConn

<div align="center">
  <img src="./image2.webp" alt="CesaConn Logo" width="200"/>
  
  ### Ready. Set. Connect.
  
  *CesaConn — connecting all your devices together securely.*

  ![Status](https://img.shields.io/badge/status-in%20development-yellow)
  ![License](https://img.shields.io/badge/license-AGPL%203.0-blue)
  ![Language](https://img.shields.io/badge/language-Rust-orange)
  ![Coming](https://img.shields.io/badge/coming-2026%2F2027-gold)
</div>

---

## What is CesaConn?

CesaConn is a **secure, serverless, cross-platform device synchronization application** built by CesaSec.

Sync your files, clipboard, notifications, and more — across all your devices — without any central server ever seeing your data. Your data stays yours. Always.

---

## Why CesaConn?

Most sync solutions force you to trust a third party with your data. CesaConn is different:

- **No central server** — data travels directly between your devices
- **End-to-end encrypted** — nobody can read your data, not even us
- **Two independent keys** — one for authentication, one for data
- **You are in full control** — every feature can be turned on or off
- **Zero data collection** — we don't know who you are, and we don't want to
- **Every feature is off by default after updates** — you decide what to enable

---

### Two Independent Keys

CesaConn uses **two completely separate passwords and keys**:

```
Password 1 (auth)   → Argon2 → Auth Key    → used ONLY for authentication & discovery
Password 2 (data)   → Argon2 → Data Key    → used ONLY for data transfer
```

If one key is compromised — the other remains secure. Both must be broken simultaneously for an attacker to succeed.

---

## Philosophy

> Every feature is **off by default** after updates. You decide what to enable. We don't decide for you.

CesaConn is built on the belief that software should serve the user — not the developer. No forced features. No hidden telemetry. No dark patterns.

---

## Privacy

CesaConn is designed with privacy as a core principle, not an afterthought:

- **No account required** to use the application
- **No telemetry** — we don't collect usage data
- **No analytics** — we don't track you
- **No servers** — there is nothing to breach
- **Open source** — verify our claims yourself

---

## License

CesaConn is licensed under [AGPL 3.0](LICENSE).

This means any modified version of CesaConn must also be released under AGPL 3.0, including when run over a network.

CesaConn application — Proprietary (CesaSec)

---

## About CesaSec

**CesaSec** — *Where Innovation Meets Security.*

CesaConn is a product of CesaSec, an independent security-focused software company.

---

<div align="center">
  <i>Built with ❤️ and Rust 🦀</i>
</div>
