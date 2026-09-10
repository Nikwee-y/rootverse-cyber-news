import os
import re
import json
import html
import requests
import feedparser

from bs4 import BeautifulSoup
from difflib import SequenceMatcher
from datetime import datetime, timezone, timedelta


DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")

SEEN_FILE = "seen_articles.json"

MAX_ARTICLES_PER_FEED = 5
MAX_FINAL_ARTICLES = 6
ARTICLE_MAX_AGE_HOURS = 36


RSS_FEEDS = {
    "CISA": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "KrebsOnSecurity": "https://krebsonsecurity.com/feed/",
    "CIS/MS-ISAC": "https://www.cisecurity.org/feed/advisories",
}


# --------------------------------------------------
# SOURCE IMPORTANCE
# --------------------------------------------------

SOURCE_WEIGHTS = {
    "CISA": 10,
    "CIS/MS-ISAC": 9,
    "KrebsOnSecurity": 8,
    "BleepingComputer": 8,
}


# --------------------------------------------------
# SECURITY KEYWORDS
# --------------------------------------------------

CRITICAL_KEYWORDS = [
    "remote code execution",
    "rce",
    "zero-day",
    "zero day",
    "actively exploited",
    "critical vulnerability",
    "authentication bypass",
    "unauthenticated",
    "arbitrary code execution",
]

HIGH_KEYWORDS = [
    "ransomware",
    "data breach",
    "credential theft",
    "privilege escalation",
    "command injection",
    "sql injection",
    "supply chain attack",
    "malware campaign",
    "apt",
    "exploitation",
    "exploit",
]

MEDIUM_KEYWORDS = [
    "vulnerability",
    "security update",
    "patch",
    "phishing",
    "malware",
    "botnet",
    "security flaw",
    "cyberattack",
]


# --------------------------------------------------
# CLEAN HTML
# --------------------------------------------------

def clean_html(text):
    if not text:
        return ""

    text = html.unescape(text)

    soup = BeautifulSoup(text, "html.parser")

    text = soup.get_text(" ", strip=True)

    text = re.sub(r"\s+", " ", text)

    return text.strip()


# --------------------------------------------------
# LOAD PREVIOUSLY POSTED ARTICLES
# --------------------------------------------------

def load_seen_articles():

    if not os.path.exists(SEEN_FILE):
        return {
            "urls": [],
            "titles": []
        }

    try:
        with open(SEEN_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except Exception:
        return {
            "urls": [],
            "titles": []
        }


# --------------------------------------------------
# SAVE ARTICLE HISTORY
# --------------------------------------------------

def save_seen_articles(seen):

    # Keep the history reasonably small
    seen["urls"] = seen["urls"][-500:]
    seen["titles"] = seen["titles"][-500:]

    with open(SEEN_FILE, "w", encoding="utf-8") as file:
        json.dump(seen, file, indent=2)


# --------------------------------------------------
# TITLE NORMALIZATION
# --------------------------------------------------

def normalize_title(title):

    title = title.lower()

    title = re.sub(
        r"[^a-z0-9\s]",
        "",
        title
    )

    title = re.sub(
        r"\s+",
        " ",
        title
    )

    return title.strip()


# --------------------------------------------------
# CHECK DUPLICATE TITLE
# --------------------------------------------------

def is_similar_title(title, existing_titles):

    normalized = normalize_title(title)

    for old_title in existing_titles:

        ratio = SequenceMatcher(
            None,
            normalized,
            old_title
        ).ratio()

        if ratio >= 0.88:
            return True

    return False


# --------------------------------------------------
# GET ARTICLE DATE
# --------------------------------------------------

def get_article_datetime(entry):

    for field in [
        "published_parsed",
        "updated_parsed"
    ]:

        parsed = entry.get(field)

        if parsed:

            try:
                return datetime(
                    parsed.tm_year,
                    parsed.tm_mon,
                    parsed.tm_mday,
                    parsed.tm_hour,
                    parsed.tm_min,
                    parsed.tm_sec,
                    tzinfo=timezone.utc
                )

            except Exception:
                pass

    return datetime.now(timezone.utc)


# --------------------------------------------------
# CALCULATE NEWS SCORE
# --------------------------------------------------

def calculate_score(article):

    text = (
        article["title"] +
        " " +
        article["summary"]
    ).lower()

    score = SOURCE_WEIGHTS.get(
        article["source"],
        5
    )

    severity = "INFO"

    # Critical
    for keyword in CRITICAL_KEYWORDS:

        if keyword in text:

            score += 10
            severity = "CRITICAL"
            break

    # High
    if severity == "INFO":

        for keyword in HIGH_KEYWORDS:

            if keyword in text:

                score += 7
                severity = "HIGH"
                break

    # Medium
    if severity == "INFO":

        for keyword in MEDIUM_KEYWORDS:

            if keyword in text:

                score += 4
                severity = "MEDIUM"
                break

    # Recency bonus
    age_hours = (
        datetime.now(timezone.utc)
        - article["published"]
    ).total_seconds() / 3600

    if age_hours <= 6:
        score += 5

    elif age_hours <= 12:
        score += 3

    elif age_hours <= 24:
        score += 2

    article["score"] = score
    article["severity"] = severity

    return article


# --------------------------------------------------
# FETCH NEWS
# --------------------------------------------------

def fetch_news(seen):

    articles = []

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(hours=ARTICLE_MAX_AGE_HOURS)
    )

    for source, feed_url in RSS_FEEDS.items():

        print(f"Reading {source}...")

        try:

            feed = feedparser.parse(feed_url)

            for entry in feed.entries[
                :MAX_ARTICLES_PER_FEED
            ]:

                title = clean_html(
                    entry.get(
                        "title",
                        "Untitled"
                    )
                )

                link = entry.get(
                    "link",
                    ""
                )

                summary = clean_html(
                    entry.get(
                        "summary",
                        ""
                    )
                )

                published = get_article_datetime(
                    entry
                )

                # Ignore old articles
                if published < cutoff:
                    continue

                # Ignore URLs already posted
                if link in seen["urls"]:
                    continue

                # Ignore titles already posted
                if is_similar_title(
                    title,
                    seen["titles"]
                ):
                    continue

                article = {
                    "source": source,
                    "title": title,
                    "link": link,
                    "summary": summary,
                    "published": published
                }

                # Score the article
                article = calculate_score(
                    article
                )

                articles.append(article)

        except Exception as error:

            print(
                f"Error reading {source}: {error}"
            )

    return articles


# --------------------------------------------------
# REMOVE DUPLICATES FROM CURRENT BATCH
# --------------------------------------------------

def remove_current_duplicates(articles):

    unique = []

    for article in sorted(
        articles,
        key=lambda x: x["score"],
        reverse=True
    ):

        duplicate = False

        for existing in unique:

            title_similarity = SequenceMatcher(
                None,
                normalize_title(
                    article["title"]
                ),
                normalize_title(
                    existing["title"]
                )
            ).ratio()

            if (
                article["link"]
                == existing["link"]
                or title_similarity >= 0.82
            ):

                duplicate = True
                break

        if not duplicate:
            unique.append(article)

    return unique


# --------------------------------------------------
# SHORTEN SUMMARY
# --------------------------------------------------

def shorten_summary(text, limit=500):

    text = text.strip()

    if len(text) <= limit:
        return text

    return text[:limit].rsplit(
        " ",
        1
    )[0] + "..."


# --------------------------------------------------
# DISCORD EMBED COLOR / ICON
# --------------------------------------------------

def severity_icon(severity):

    icons = {
        "CRITICAL": "🚨",
        "HIGH": "🔴",
        "MEDIUM": "🟡",
        "INFO": "🔵"
    }

    return icons.get(
        severity,
        "🔵"
    )


# --------------------------------------------------
# SEND NEWS TO DISCORD
# --------------------------------------------------

def send_to_discord(articles):

    today = datetime.now(
        timezone.utc
    ).strftime("%d %B %Y")

    embeds = []

    for article in articles:

        icon = severity_icon(
            article["severity"]
        )

        description = (
            f"**{icon} {article['severity']}**\n\n"
            f"{shorten_summary(article['summary'])}\n\n"
            f"**Source:** {article['source']}"
        )

        embed = {
            "title": article["title"][:256],
            "url": article["link"],
            "description": description[:2048],
            "footer": {
                "text": (
                    f"RootVerse Cyber News • "
                    f"Score: {article['score']}"
                )
            }
        }

        embeds.append(embed)

    payload = {

        "username": "RootVerse Cyber News",

        "content": (
            "🌐 **ROOTVERSE | DAILY CYBER NEWS**\n"
            f"📅 {today}\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "🏆 **Top Cybersecurity Stories**"
        ),

        "embeds": embeds
    }

    response = requests.post(
        DISCORD_WEBHOOK,
        json=payload,
        timeout=30
    )

    if response.status_code in [
        200,
        204
    ]:

        print(
            "✅ News successfully sent to Discord!"
        )

    else:

        print(
            "❌ Discord error:"
        )

        print(
            response.status_code
        )

        print(
            response.text
        )

        response.raise_for_status()


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():

    if not DISCORD_WEBHOOK:

        raise ValueError(
            "DISCORD_WEBHOOK secret is missing."
        )

    seen = load_seen_articles()

    articles = fetch_news(
        seen
    )

    print(
        f"Found {len(articles)} new articles."
    )

    # Remove duplicates from today's batch
    articles = remove_current_duplicates(
        articles
    )

    # Rank by score
    articles.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    # Keep only top stories
    articles = articles[
        :MAX_FINAL_ARTICLES
    ]

    if not articles:

        print(
            "No new cybersecurity stories found."
        )

        return

    # Send to Discord
    send_to_discord(
        articles
    )

    # Remember posted articles
    for article in articles:

        if article["link"] not in seen["urls"]:

            seen["urls"].append(
                article["link"]
            )

        normalized = normalize_title(
            article["title"]
        )

        if normalized not in seen["titles"]:

            seen["titles"].append(
                normalized
            )

    save_seen_articles(
        seen
    )


if __name__ == "__main__":
    main()
