# 🛡️ CSRF & Insecure CORS Exploit Lab – Email Change Vulnerability

This lab demonstrates how an attacker can exploit **Cross-Site Request Forgery (CSRF)** and **Insecure CORS configuration** to change the email address of a logged-in user.

---

## 🎯 Objective

Exploit a vulnerability where:

- A **CSRF token** is generated per account and refreshed on every `/account` page load.
- The application validates CSRF tokens on all update requests.

Your goal is to **perform a cross-origin email change without the user’s consent** while they're logged in.

---

## 🚀 Run the Lab via Docker

Start the lab locally using:

```bash
docker pull xploiterd/tokenbypass
docker run -p 8000:8000 xploiterd/tokenbypass
