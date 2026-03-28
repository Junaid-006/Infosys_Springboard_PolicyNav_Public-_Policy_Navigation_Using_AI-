# ⚡ PolicyNav — Milestone 4

> **AI-Powered Policy Document Navigation System**
> Infosys Springboard Internship · Final Milestone

---

## 📑 Table of Contents

1. [Project Overview](#project-overview)
2. [What's New in Milestone 4](#whats-new-in-milestone-4)
3. [Full Feature List](#full-feature-list)
4. [Tech Stack](#tech-stack)
5. [Project Structure](#project-structure)
6. [Setup & Installation](#setup--installation)
7. [Environment Variables](#environment-variables)
8. [Running the App](#running-the-app)
9. [Admin Dashboard Guide](#admin-dashboard-guide)
10. [User Dashboard Guide](#user-dashboard-guide)
11. [Database Schema](#database-schema)
12. [Milestone History](#milestone-history)

---

## Project Overview

**PolicyNav** is a AI based web application that helps citizens, researchers, and policy analysts navigate complex government policy documents with ease. It combines Retrieval-Augmented Generation (RAG), multilingual translation, knowledge graph visualization, readability analysis, and a complete user management system — all in a single Streamlit application hosted via Google Colab + Ngrok.

---

## What's New in Milestone 4

Milestone 4 integrates all new enterprise-grade features on top of the existing Milestone 3.

### 🛡️ Admin Dashboard (Management & Analytics)
| Feature | Details |
|---|---|
| **User Control** | Promote users to Admin, lock / unlock accounts, delete users with email notification |
| **Pending Registrations** | Review and approve / reject re-registrations for previously deleted accounts |
| **Real-time Active Users** | Live counter with auto-refresh showing currently online users |
| **System Activity Log** | Full history of all user interactions across the platform |
| **Model Usage Chart** | Interactive Plotly bar chart showing which AI models are being used |
| **Language Usage Chart** | Pie chart of which languages users query in |
| **Feature Popularity Chart** | Breakdown of which app sections (RAG, Summarization, KG, Readability) are most used |
| **Feedback WordCloud** | Matplotlib WordCloud generated from all submitted user feedback comments |
| **Data Export** | CSV download buttons for feedback logs, activity history, and full user roster |

### 👤 User Dashboard & Profile Personalization
| Feature | Details |
|---|---|
| **Avatar Upload** | Users can upload and update a profile picture (stored persistently on Google Drive) |
| **Change Email** | OTP-verified email update flow |
| **Change Password** | Secure password update with history check (prevents reuse of last 3 passwords) |
| **Points & Badges** | Gamification system — earn XP for using features, unlock achievement badges |
| **Login Streak** | Daily login streak tracker with bonus points at 7-day and 30-day milestones |
| **Leaderboard** | Global top-20 leaderboard ranked by total points |
| **Deadline Tracker** | Save and manage policy compliance deadlines extracted from documents |

---

## Full Feature List

### 🔐 Authentication & Security
- Email + password login with **bcrypt** hashing
- **JWT** session tokens (60-minute expiry)
- **OTP email verification** on signup and login
- Account lockout after **3 failed attempts** with admin + user email notification
- **Password strength meter** with real-time feedback
- Security question for account recovery / forgot password flow
- Password history enforcement (cannot reuse last 3 passwords)

### 🔍 RAG Search (Retrieval-Augmented Generation)
- Upload PDF or HTML policy documents
- Documents chunked and embedded using **sentence-transformers** (`all-MiniLM-L6-v2`)
- **FAISS** vector index for fast semantic search
- Answer generation via **Qwen/Qwen2.5-1.5B-Instruct** (runs on GPU)
- "Simplify Language" toggle for plain-English answers
- Source snippets shown with each answer

### 🌐 Multilingual Support
- Powered by **facebook/nllb-200-distilled-600M** translation model
- Supported languages: **English, French, Japanese, German, Hindi, Assamese, Bhojpuri, Gujarati, Kashmiri, Maithili, Malayalam, Meitei, Nepali, Odia, Punjabi, Sanskrit, Sindhi, Urdu, Tamil, Kannada, Telugu, Marathi, Bengali**
- Ask questions in any language, receive answers in the same language

### 📄 Document Summarization
- Generates 3 concise bullet-point summaries from any uploaded document
- Fully multilingual — summaries translated to the user's chosen language

### 🕸️ Knowledge Graph
- Named Entity Recognition via **spaCy** (`en_core_web_sm`)
- Interactive graph built with **NetworkX + PyVis**
- Dark-themed graph rendered directly in Streamlit
- Nodes coloured by type (document vs. entity)

### 📊 Readability Analyzer
- Powered by **textstat** library
- Metrics: Flesch Reading Ease, Flesch-Kincaid Grade, SMOG Index, Gunning Fog, Coleman-Liau
- Overall grade level aggregation
- Word, sentence, syllable, and complex-word counts

### ⭐ Feedback System
- Per-section star ratings (1–5)
- Free-text comments stored in SQLite
- Admin can visualise feedback trends via WordCloud and charts

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | Streamlit 1.55, streamlit-option-menu, streamlit-autorefresh |
| **AI / NLP** | Qwen2.5-1.5B-Instruct, NLLB-200 (translation), sentence-transformers, spaCy |
| **Vector Search** | FAISS (CPU) |
| **Visualisation** | Plotly Express, Matplotlib, WordCloud, PyVis, NetworkX |
| **Auth** | PyJWT, bcrypt, SMTP (Gmail) |
| **Database** | SQLite 3 (persisted on Google Drive) |
| **Document Parsing** | PyPDF2, BeautifulSoup4 |
| **Readability** | textstat |
| **Hosting** | Google Colab (T4 GPU) + pyngrok |
| **Storage** | Google Drive (`/content/drive/MyDrive/PolicyNav`) |

---

## Project Structure

```
Milestone4/
│
├── policynav_project.ipynb   # Main Colab notebook (run this)
│
│── Source files written by the notebook:
├── app.py                    # Streamlit UI — all pages & routing
├── db.py                     # SQLite schema, queries, gamification
├── auth.py                   # JWT, bcrypt, OTP, email helpers
├── config.py                 # Environment variable constants
├── nlp_engine.py             # Qwen model + NLLB translator wrappers
├── vector_store.py           # FAISS index build & semantic search
├── knowledge_graph.py        # spaCy NER + NetworkX + PyVis graph
├── readability.py            # textstat readability metrics
│
└── README.md                 # This file
```

**Google Drive folders created automatically:**
```
/content/drive/MyDrive/PolicyNav/
├── policynav_users.db    # SQLite database
├── documents/            # Uploaded policy PDFs / HTMLs
├── graphs/               # Saved knowledge graph HTML files
└── avatars/              # User profile pictures
```

---

## Setup & Installation

### Prerequisites
- A Google account with Google Drive access
- A **pyngrok** account → get a free auth token at [ngrok.com](https://ngrok.com)
- A Gmail account with an **App Password** enabled (for OTP emails)

### Step 1 — Open in Google Colab
Upload `policynav_project.ipynb` to [colab.research.google.com](https://colab.research.google.com) and open it.

> **Runtime type:** Change to `T4 GPU` via *Runtime → Change runtime type → T4 GPU*

### Step 2 — Add Colab Secrets
Go to the 🔑 **Secrets** panel (left sidebar) and add the following keys:

| Secret Key | Value |
|---|---|
| `NGROK_AUTHTOKEN` | Your ngrok auth token |
| `JWT_SECRET_KEY` | Any long random string (e.g. `my-super-secret-key-123`) |
| `EMAIL_ID` | Your Gmail address |
| `EMAIL_APP_PASSWORD` | Your Gmail App Password |
| `ADMIN_EMAIL_ID` | Email address that will receive admin alerts |
| `ADMIN_PASSWORD` | Password for the admin account |

### Step 3 — Run All Cells
Click *Runtime → Run all* and wait for all cells to execute in order.

- Cell 1 installs all dependencies
- Cell 2 mounts Google Drive & creates directories
- Cells 3–9 write the source `.py` files to disk
- The final cell starts Streamlit and prints the public ngrok URL

---

## Environment Variables

All variables are loaded from **Colab Secrets** via `os.getenv()` in `config.py`:

```python
JWT_SECRET          = os.getenv("JWT_SECRET_KEY")
EMAIL_ID            = os.getenv("EMAIL_ID")
EMAIL_APP_PASSWORD  = os.getenv("EMAIL_APP_PASSWORD")
ADMIN_EMAIL         = os.getenv("ADMIN_EMAIL_ID")
ADMIN_PASSWORD      = os.getenv("ADMIN_PASSWORD")

# Hardcoded defaults in config.py
MAX_LOGIN_ATTEMPTS      = 3
LOCK_TIME_MINUTES       = 5
PASSWORD_HISTORY_COUNT  = 3
TOKEN_EXPIRY_MINUTES    = 60
```

---

## Running the App

After all cells complete, the last cell will print a line like:

```
🔗 Streamlit URL: https://xxxx-xxxx.ngrok-free.app
```

Open that URL in any browser. The app is now live.

To **stop** the server, stop the last Colab cell. The database and uploaded documents are safely preserved on Google Drive.

---

## Admin Dashboard Guide

Log in with the `ADMIN_EMAIL_ID` and `ADMIN_PASSWORD` you set in Colab Secrets. Admin users are routed directly to the Admin Dashboard (no OTP required).

### Tabs

| Tab | What you can do |
|---|---|
| **👥 User Management** | View all registered users, promote to admin, lock / unlock accounts, delete users. All actions trigger email notifications to the affected user. |
| **📋 Pending Registrations** | Approve or reject re-registration requests from users whose accounts were previously deleted. |
| **📡 Live Activity** | Auto-refreshing panel showing currently online users and a live feed of recent system events. |
| **📈 Analytics** | Interactive charts: model usage (bar), language distribution (pie), feature popularity (bar). All built with Plotly. |
| **💬 Feedback Analysis** | Star-rating breakdown per feature section + a WordCloud generated from all user comments. |
| **⬇️ Export Data** | One-click CSV download for feedback logs, activity history, and the full user table. |

---

## User Dashboard Guide

After OTP-verified login, regular users land on their personal dashboard.

### Navigation Sections

| Section | Description |
|---|---|
| **🔍 RAG Search** | Ask questions about uploaded policy documents in any supported language. |
| **📄 Summarization** | Upload a PDF and get a concise 3-point summary. |
| **🕸️ Knowledge Graph** | Visualise entity relationships extracted from uploaded documents. |
| **📊 Readability** | Analyse the complexity of any policy text. |
| **🏆 Leaderboard** | See the top 20 users ranked by XP points. |
| **👤 Profile** | Upload/change avatar, update email (OTP-verified), change password, view badges and login streak. |
| **📅 Deadlines** | Save policy deadlines extracted from documents. |
| **⭐ Feedback** | Rate and comment on any feature. |

---
### 〰️ Dashboard

![Dashboard](../images/profile_avatar.jpeg)

### 🔐 Admin

![Admin](../images/admin.jpeg)

### 🧭 Pending Registrations

![Pending Registration](../images/pending.jpeg)

### 🔒 Admin Security Monitor

![Admin Security Monitor](../images/admin_security_monitor.jpeg)

### 🔁 User Activity

![User Activity](../images/user_activity.jpeg)

### 🔍 Analytics Dashboard

![Analytics Dashboard](../images/analytics_dashboard.jpeg)
![Analytics Dashboard2](../images/analytics_dashboard2.jpeg)

### 🔐 Feedback

![Feedback](../images/feedback_analysis.jpeg)
![WordCloud](../images/wordcloud.jpeg)
![Feedback Export](../images/feedback_analysis_export.jpeg)

### 🎯 Gamification

![Gamification](../images/gamification.jpeg)
---

# Author

**Infosys Springboard Virtual Internship – Batch 13** <br>
Bhavithravanan C A - User control in admin dashboard and identity in user dashboard <br>
Gaurav Mehtha - Data Visualization: Plot interactive charts <br>
Junaid Bin Riyaz - User Dashboard: Security and Ui/Ux <br>
Prapti Nikam - User Engagement Gamification leaderboard unique feature and Activity Tracking <br>
Srinivasa Rajan M - Admin Dashboard, Feedback analysis, Added 20+ multi Lingual support, News & Updates from admin Dashboard for Users.
