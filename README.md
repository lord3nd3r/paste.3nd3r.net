# paste.3nd3r.net
**A beautiful, private, forever Pastebin clone – built in just 2 files.**

[![Live Demo](https://img.shields.io/badge/live-paste.3nd3r.net-38bdf8?style=for-the-badge&logo=cloudflare)](https://paste.3nd3r.net)
![Node.js](https://img.shields.io/badge/Node.js-%3E=18-339933?style=flat-square&logo=node.js)
![License](https://img.shields.io/github/license/lord3nd3r/paste.3nd3r.net?style=flat-square)
![Stars](https://img.shields.io/github/stars/lord3nd3r/paste.3nd3r.net?style=social)

https://paste.3nd3r.net

## Features
- Instant file & text sharing
- 1 GB storage quota per account
- Full user accounts (email + password)
- Private dashboard with delete & copy links
- View counters
- Dark / Light mode (remembers preference)
- Drag-and-drop anywhere on the page
- Highlight.js syntax highlighting for pastes
- Zero tracking, zero ads, zero JavaScript frameworks
- Works perfectly on mobile
- Fully self-hostable in **two files** (`server.js` + `index.html`)

## Live Demo
https://paste.3nd3r.net

## Quick Start (5 minutes)

### 1. Prerequisites
- Node.js 18 or higher
- A domain name with DNS A record pointing to your server
- (Optional but recommended) Certbot / Let’s Encrypt for HTTPS

### 2. Clone & Install
```bash
git clone https://github.com/lord3nd3r/paste.3nd3r.net.git
cd paste.3nd3r.net
npm install

npm start
