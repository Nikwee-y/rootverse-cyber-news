import os
import requests
import feedparser
from datetime import datetime, timezone


DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")


RSS_FEEDS = {
    "CISA": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "KrebsOnSecurity": "https://krebsonsecurity.com/feed/",
    "CIS/MS-ISAC": "https://www.cisecurity.org/feed/advisories",
}


def get_latest_news():
    articles = []

    for source, feed_url in RSS_FEEDS.items():

        print(f"Reading {source}...")

        feed = feedparser.parse(feed_url)

        if not feed.entries:
            print(f"No articles found from {source}")
            continue

        article = feed.entries[0]

        articles.append({
            "source": source,
            "title": article.get("title", "Untitled"),
            "link": article.get("link", ""),
            "summary": article.get("summary", "")
        })

    return articles


def send_to_discord(articles):

    today = datetime.now(timezone.utc).strftime("%d %B %Y")

    embeds = []

    for article in articles:

        embed = {
            "title": article["title"],
            "url": article["link"],
            "description": article["summary"][:1000],
            "footer": {
                "text": f"Source: {article['source']}"
            }
        }

        embeds.append(embed)

    payload = {
        "username": "RootVerse Cyber News",

        "content": (
            f"🌐 **ROOTVERSE DAILY CYBER BRIEF**\n"
            f"📅 {today}\n"
            f"━━━━━━━━━━━━━━━━━━━━"
        ),

        "embeds": embeds
    }

    response = requests.post(
        DISCORD_WEBHOOK,
        json=payload,
        timeout=30
    )

    if response.status_code in [200, 204]:
        print("✅ News successfully sent to Discord!")

    else:
        print("❌ Discord error:")
        print(response.status_code)
        print(response.text)


def main():

    if not DISCORD_WEBHOOK:
        raise ValueError("DISCORD_WEBHOOK secret is missing.")

    articles = get_latest_news()

    if not articles:
        print("No news found.")
        return

    send_to_discord(articles)


if __name__ == "__main__":
    main()
