# 🚀 Identity Provider (IDP) with OIDC and JWTs (Go)

This project implements a basic **Identity Provider (IDP)** in **Go** with support for **OpenID Connect (OIDC)** and authentication using **JSON Web Tokens (JWTs)**.  
It includes JWT generation and validation signed with **RS256 (RSA)** and exposes public keys via **JWKS (JSON Web Key Set)**.

---

## ✨ Features

- ✅ **OIDC-compliant Identity Provider** in Go.  
- 🔑 JWT generation and signing using **RS256**.  
- 🌍 Public keys exposed at `/.well-known/jwks.json`.  
- 🔐 Token verification from external clients using JWKS.  
- 🛠 Easily extensible to support more authentication flows (PKCE, refresh tokens, etc.).

---

## ⚙️ Setup

- Clone the repository:

git clone https://github.com/dasolerfo/hennge-one-Backend.git
cd hennge-one-Backend 

- Install dependencies:

go mod tidy

 - Run the server:

go run main.go

## 📜 License

This project is licensed under the MIT License.
Feel free to use, modify, and distribute it :)

pel grafiquito uwu