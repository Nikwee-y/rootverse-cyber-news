# 🌐 RootVerse Cyber News

> Automated cybersecurity news intelligence for the RootVerse Discord community.

RootVerse Cyber News is a Python-based RSS aggregation and ranking system that automatically collects cybersecurity news, filters duplicate stories, cleans RSS content, ranks articles by security relevance, and publishes a daily cybersecurity brief to a Discord channel.

The system runs automatically using GitHub Actions and sends the results through a Discord Webhook.

---

## 🚀 Features

- 📰 Aggregates cybersecurity news from multiple RSS feeds
- 🧹 Removes HTML formatting from RSS content
- ♻️ Detects and prevents duplicate articles
- 🏆 Ranks news based on security relevance
- 🚨 Identifies critical, high, medium, and informational stories
- ⏱️ Filters outdated articles
- 🔗 Links directly to original sources
- 🤖 Automatically posts to Discord
- 🔐 Stores the Discord webhook securely using GitHub Secrets
- ☁️ Runs automatically through GitHub Actions
- 💰 No paid API or AI service required

---

## 🏗️ Architecture

```text
              Cybersecurity RSS Feeds
                       │
          ┌────────────┼────────────┐
          │            │            │
         CISA     BleepingComputer  Krebs
          │            │            │
          └────────────┼────────────┘
                       │
                       ▼
                Python News Bot
                       │
              ┌────────┴────────┐
              │                 │
        HTML Cleanup       Duplicate Filter
              │                 │
              └────────┬────────┘
                       │
                       ▼
                  News Ranking
                       │
                       ▼
                 Top Articles
                       │
                       ▼
                Discord Webhook
                       │
                       ▼
             📰 RootVerse #cyber-news
