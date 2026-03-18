# 📘 PolicyNav – Milestone 4

## 🚀 Project Overview

**PolicyNav** is an AI-powered policy analysis system that enables users to:

* Upload and analyze policy documents (PDFs)
* Generate intelligent summaries using LLMs
* Perform semantic search across documents
* Understand document complexity using readability metrics
* Visualize insights through graphs and analytics

---

## 🆕 Updates in Milestone 4

This milestone introduces major enhancements that improve the system’s intelligence, usability, and security.

---

### 🔐 Authentication & Security Improvements

* Implemented **JWT-based authentication**
* Added **password hashing using bcrypt**
* Introduced **login validation and security checks**
* Enabled **email-based password recovery**

---

### 🧠 Advanced LLM Integration

* Integrated **Qwen 2.5** for improved summarization
* Enhanced contextual understanding and response quality

---

### 🔎 Semantic Search (FAISS)

* Added **FAISS-based vector database**
* Enables **semantic document search**
* Uses embeddings for faster and more accurate retrieval

📸
![Semantic Search](assets/vector_search.png)

---

### 📊 Readability Analysis

* Introduced readability metrics:

  * Flesch Reading Ease
  * Flesch-Kincaid Grade
  * SMOG Index
  * Gunning Fog Index
* Helps users understand document complexity

📸
![Readability](assets/readability_analysis.png)

---

### 🕸️ Knowledge Graph Visualization

* Built using **spaCy, NetworkX, and PyVis**
* Extracts and visualizes relationships between entities

### ☁️ Structured Storage System

* Ensures better file management and persistence

---

### 🖼️ Visual Analytics

* Added:

  * WordCloud generation
  * Interactive visualizations (Plotly)
* Provides quick insights from documents

📸
![WordCloud](assets/wordcloud.png)

---

### 🌐 Multilingual Support

* Added translation using **facebook/nllb**
* Enables understanding of policies in multiple languages

---

### ⚡ Auto Document Ingestion

* Automatically detects and processes new documents
* Prevents duplicate processing
* Improves performance and efficiency

---

### 👤 Avatar System

* Added user avatar support
* Enhances personalization of the application

---

### 🛠️ Admin & Feedback Enhancements

* Improved feedback tracking system
* Added better control and monitoring features for admin

---


## ⚙️ Setup Instructions

```bash
pip install -r requirements.txt
```

Run the application:

```bash
streamlit run app.py
```

---

## 🔑 Environment Variables

* `JWT_SECRET_KEY`
* `EMAIL_ID`
* `EMAIL_APP_PASSWORD`
* `ADMIN_EMAIL_ID`
* `ADMIN_PASSWORD`
* `ANTHROPIC_API_KEY` *(optional)*

---

## 🎯 Outcome

Milestone 4 upgrades PolicyNav into a:

* Secure
* Scalable
* AI-driven policy intelligence platform

with:

* Semantic search
* Knowledge visualization
* Readability insights
* Multilingual capabilities

---
Just tell me 👍
