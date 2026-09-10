import os
import re
import json
import html
import time
import requests
import feedparser

from bs4 import BeautifulSoup
from difflib import SequenceMatcher
from datetime import datetime, timezone, timedelta


# ============================================================
# CONFIGURATION
# ============================================================

DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")
SEEN_FILE = "seen_articles.json"

MAX_ARTICLES_PER_FEED = 10
MAX_FINAL_ARTICLES = 10
ARTICLE_MAX_AGE_HOURS = 36
DISCORD_DELAY_SECONDS = 1


# ============================================================
# RSS SOURCES
# ============================================================

RSS_FEEDS = {
    "CISA": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "KrebsOnSecurity": "https://krebsonsecurity.com/feed/",
    "CIS/MS-ISAC": "https://www.cisecurity.org/feed/advisories",
}


# ============================================================
# SECURITY KEYWORDS
# ============================================================

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
    "ddos",
    "denial of service",
]


# ============================================================
# ATTACK CLASSIFICATION
# ============================================================

ATTACK_TYPES = {
    "Ransomware": [
        "ransomware",
        "ransom",
        "encrypted files",
        "file encryption",
    ],

    "Phishing / Social Engineering": [
        "phishing",
        "spear phishing",
        "social engineering",
        "credential harvesting",
        "fake login",
    ],

    "Malware": [
        "malware",
        "trojan",
        "backdoor",
        "infostealer",
        "spyware",
        "loader",
        "remote access trojan",
        "rat",
    ],

    "Vulnerability / Exploitation": [
        "vulnerability",
        "exploit",
        "exploitation",
        "zero-day",
        "zero day",
        "remote code execution",
        "rce",
        "security flaw",
    ],

    "Data Breach": [
        "data breach",
        "breached",
        "stolen data",
        "data leak",
        "exposed data",
        "records exposed",
    ],

    "Credential Attack": [
        "credential theft",
        "stolen credentials",
        "password theft",
        "account takeover",
        "credential stuffing",
        "password spraying",
        "brute force",
    ],

    "Supply Chain Attack": [
        "supply chain attack",
        "supply-chain attack",
        "compromised package",
        "malicious package",
        "dependency attack",
        "third-party compromise",
    ],

    "DDoS / DoS": [
        "ddos",
        "denial of service",
        "distributed denial",
    ],

    "Privilege Escalation": [
        "privilege escalation",
        "local privilege escalation",
        "lpe",
    ],

    "Command / Code Injection": [
        "command injection",
        "sql injection",
        "code injection",
        "template injection",
    ],

    "Authentication Bypass": [
        "authentication bypass",
        "auth bypass",
        "bypass authentication",
        "unauthenticated access",
    ],

    "APT / Targeted Campaign": [
        "apt",
        "advanced persistent threat",
        "targeted campaign",
        "espionage campaign",
    ],
}


# ============================================================
# IMPACT
# ============================================================

IMPACT = {
    "Ransomware":
        "Can disrupt operations, encrypt systems and cause data loss, extortion or recovery costs.",

    "Phishing / Social Engineering":
        "Can trick users into revealing credentials, approving malicious actions or opening malicious content.",

    "Malware":
        "Can provide attackers with persistence, information theft, remote access or a foothold inside systems.",

    "Vulnerability / Exploitation":
        "A vulnerable product may allow attackers to compromise systems before defenders can patch or mitigate it.",

    "Data Breach":
        "Exposed information can lead to identity theft, fraud, privacy loss and further targeted attacks.",

    "Credential Attack":
        "Compromised credentials can lead to account takeover and unauthorized access to internal resources.",

    "Supply Chain Attack":
        "Compromising a trusted vendor, package or dependency can spread the attack to downstream organizations.",

    "DDoS / DoS":
        "Can make applications or network services unavailable to legitimate users.",

    "Privilege Escalation":
        "Can turn limited access into higher-level control over a system.",

    "Command / Code Injection":
        "Can cause an application or server to execute attacker-controlled commands or code.",

    "Authentication Bypass":
        "Can allow access without satisfying the intended authentication controls.",

    "APT / Targeted Campaign":
        "Long-running targeted activity can enable espionage, persistence and theft of sensitive information.",
}


# ============================================================
# WHAT TO LEARN
# ============================================================

LEARN = {
    "Ransomware":
        "Learn endpoint detection, backups, segmentation, incident response and containment.",

    "Phishing / Social Engineering":
        "Learn email security, URL analysis, identity protection, MFA and awareness.",

    "Malware":
        "Learn IOC analysis, process investigation, persistence hunting, EDR and malware triage.",

    "Vulnerability / Exploitation":
        "Learn vulnerability management, CVE analysis, patching and exploit detection.",

    "Data Breach":
        "Learn access control, data protection, logging, DLP and incident response.",

    "Credential Attack":
        "Learn MFA, password security, identity monitoring and authentication logs.",

    "Supply Chain Attack":
        "Learn dependency security, software inventory, package integrity and third-party risk.",

    "DDoS / DoS":
        "Learn traffic analysis, rate limiting, network protection and availability monitoring.",

    "Privilege Escalation":
        "Learn least privilege, OS hardening, endpoint monitoring and escalation detection.",

    "Command / Code Injection":
        "Learn secure input handling, application logging, WAF controls and injection detection.",

    "Authentication Bypass":
        "Learn secure authentication, access-control testing, MFA and authorization monitoring.",

    "APT / Targeted Campaign":
        "Learn threat intelligence, MITRE ATT&CK, hunting and incident response.",
}


# ============================================================
# CLEAN HTML
# ============================================================

def clean_html(text):
    soup = BeautifulSoup(
        html.unescape(text or ""),
        "html.parser"
    )

    return re.sub(
        r"\s+",
        " ",
        soup.get_text(" ", strip=True)
    ).strip()


# ============================================================
# LOAD SEEN ARTICLES
# ============================================================

def load_seen():

    if not os.path.exists(SEEN_FILE):
        return {
            "urls": [],
            "titles": []
        }

    try:

        with open(
            SEEN_FILE,
            encoding="utf-8"
        ) as file:

            data = json.load(file)

            return {
                "urls": data.get("urls", []),
                "titles": data.get("titles", [])
            }

    except Exception:

        return {
            "urls": [],
            "titles": []
        }


# ============================================================
# SAVE SEEN ARTICLES
# ============================================================

def save_seen(seen):

    seen["urls"] = seen["urls"][-1000:]
    seen["titles"] = seen["titles"][-1000:]

    with open(
        SEEN_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            seen,
            file,
            indent=2
        )


# ============================================================
# NORMALIZE TITLE
# ============================================================

def normalize_title(title):

    title = re.sub(
        r"[^a-z0-9\s]",
        "",
        title.lower()
    )

    return re.sub(
        r"\s+",
        " ",
        title
    ).strip()


# ============================================================
# CHECK SIMILAR TITLE
# ============================================================

def is_similar_title(
    title,
    existing_titles
):

    current = normalize_title(title)

    return any(
        SequenceMatcher(
            None,
            current,
            old
        ).ratio() >= 0.88
        for old in existing_titles
    )


# ============================================================
# ARTICLE DATE
# ============================================================

def article_date(entry):

    for field in (
        "published_parsed",
        "updated_parsed"
    ):

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


# ============================================================
# CALCULATE SECURITY SCORE
# ============================================================

def calculate_score(article):

    text = (
        article["title"]
        + " "
        + article["summary"]
    ).lower()

    source_score = {
        "CISA": 2,
        "CIS/MS-ISAC": 2,
        "KrebsOnSecurity": 1,
        "BleepingComputer": 1,
    }

    score = source_score.get(
        article["source"],
        0
    )

    if any(
        keyword in text
        for keyword in CRITICAL_KEYWORDS
    ):

        score += 5

    elif any(
        keyword in text
        for keyword in HIGH_KEYWORDS
    ):

        score += 4

    elif any(
        keyword in text
        for keyword in MEDIUM_KEYWORDS
    ):

        score += 2

    age = (
        datetime.now(timezone.utc)
        - article["published"]
    ).total_seconds() / 3600

    if age <= 6:

        score += 2

    elif age <= 24:

        score += 1

    article["score"] = min(
        score,
        10
    )

    if article["score"] >= 9:

        article["severity"] = "CRITICAL"

    elif article["score"] >= 7:

        article["severity"] = "VERY HIGH"

    elif article["score"] >= 5:

        article["severity"] = "HIGH"

    elif article["score"] >= 3:

        article["severity"] = "MEDIUM"

    else:

        article["severity"] = "INFO"

    return article


# ============================================================
# CLASSIFY ATTACK TYPE
# ============================================================

def classify(article):

    text = (
        article["title"]
        + " "
        + article["summary"]
    ).lower()

    found = []

    for attack_type, keywords in ATTACK_TYPES.items():

        if any(
            keyword in text
            for keyword in keywords
        ):

            found.append(
                attack_type
            )

    if found:

        return " + ".join(
            found[:2]
        )

    return "Cybersecurity Incident / Security Update"


# ============================================================
# FETCH NEWS
# ============================================================

def fetch_news(seen):

    articles = []

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(
            hours=ARTICLE_MAX_AGE_HOURS
        )
    )

    for source, feed_url in RSS_FEEDS.items():

        print(
            f"Reading {source}..."
        )

        try:

            feed = feedparser.parse(
                feed_url
            )

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

                published = article_date(
                    entry
                )

                if published < cutoff:
                    continue

                if not link:
                    continue

                if link in seen["urls"]:
                    continue

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

                calculate_score(
                    article
                )

                article["attack_type"] = classify(
                    article
                )

                primary = (
                    article["attack_type"]
                    .split(" + ")[0]
                )

                article["impact"] = IMPACT.get(
                    primary,
                    "May affect confidentiality, integrity or availability depending on the event."
                )

                article["learning"] = LEARN.get(
                    primary,
                    "Learn how defenders detect, investigate, contain and remediate this type of security event."
                )

                articles.append(
                    article
                )

        except Exception as error:

            print(
                f"Error reading {source}: {error}"
            )

    return articles


# ============================================================
# REMOVE CURRENT BATCH DUPLICATES
# ============================================================

def remove_duplicates(articles):

    unique = []

    for article in sorted(
        articles,
        key=lambda item: item["score"],
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

            unique.append(
                article
            )

    return unique


# ============================================================
# CREATE 5–10 NUMBERED NEWS POINTS
# ============================================================

def make_numbered_points(
    article,
    minimum=5,
    maximum=10
):

    summary = re.sub(
        r"\s+",
        " ",
        article.get(
            "summary",
            ""
        )
    ).strip()

    sentences = [
        sentence.strip()
        for sentence in re.split(
            r"(?<=[.!?])\s+",
            summary
        )
        if len(sentence.strip()) > 20
    ]

    points = []

    def add_point(text):

        text = re.sub(
            r"\s+",
            " ",
            text
        ).strip()

        if (
            text
            and text not in points
            and len(points) < maximum
        ):

            points.append(
                text
            )

    # Use factual information from the RSS source first.
    for sentence in sentences:

        add_point(
            sentence
        )

    # Free fallback points if the RSS summary is short.
    fallback_points = [

        f"Reported by {article['source']}.",

        f"The report is classified as {article['attack_type']}.",

        f"Security score for this report is {article['score']}/10.",

        article["impact"],

        article["learning"],

        "Security teams should review related logs and indicators where applicable.",

        "Organizations should review vendor guidance, patches or mitigations where applicable.",
    ]

    for point in fallback_points:

        if len(points) >= minimum:
            break

        add_point(
            point
        )

    return "\n".join(
        f"{number}. {point}"
        for number, point
        in enumerate(
            points,
            1
        )
    )


# ============================================================
# SEVERITY ICON
# ============================================================

def severity_icon(
    severity
):

    return {
        "CRITICAL": "🚨",
        "VERY HIGH": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "INFO": "🔵"
    }.get(
        severity,
        "🔵"
    )


# ============================================================
# SEND TO DISCORD
# ============================================================

def send_to_discord(
    articles
):

    posted = []

    for article in articles:

        summary_points = make_numbered_points(
            article,
            minimum=5,
            maximum=10
        )

        description = (

            f"**{severity_icon(article['severity'])} "
            f"{article['severity']} • "
            f"Security Score: "
            f"{article['score']}/10**\n\n"

            f"🎯 **Attack Type**\n"
            f"{article['attack_type']}\n\n"

            f"💥 **What Happened / Impact**\n"
            f"1. {article['impact']}\n\n"

            f"📚 **What You Should Learn**\n"
            f"1. {article['learning']}\n\n"

            f"📰 **News Summary**\n"
            f"{summary_points}"
        )

        embed = {

            "title": article["title"][:256],

            "url": article["link"],

            "description": description[:4096],

            "footer": {
                "text": (
                    f"RootVerse Cyber News • "
                    f"Source: "
                    f"{article['source']}"
                )
            }
        }

        payload = {
            "embeds": [
                embed
            ]
        }

        response = requests.post(
            DISCORD_WEBHOOK,
            json=payload,
            timeout=20
        )

        if response.status_code not in (
            200,
            204
        ):

            raise RuntimeError(
                f"Discord error "
                f"{response.status_code}: "
                f"{response.text}"
            )

        print(
            f"Posted: {article['title']}"
        )

        posted.append(
            article
        )

        time.sleep(
            DISCORD_DELAY_SECONDS
        )

    return posted


# ============================================================
# MAIN
# ============================================================

def main():

    if not DISCORD_WEBHOOK:

        raise ValueError(
            "DISCORD_WEBHOOK is missing."
        )

    seen = load_seen()

    articles = fetch_news(
        seen
    )

    print(
        f"Found {len(articles)} new articles "
        f"before deduplication."
    )

    articles = remove_duplicates(
        articles
    )

    # Score ranks stories only.
    # Low-score stories are NOT filtered out.
    articles.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    articles = articles[
        :MAX_FINAL_ARTICLES
    ]

    print(
        f"Selected {len(articles)} "
        f"articles to post."
    )

    if not articles:

        print(
            "No new cybersecurity stories found."
        )

        return

    posted = send_to_discord(
        articles
    )

    # Save only successfully posted articles.
    for article in posted:

        if article["link"] not in seen["urls"]:

            seen["urls"].append(
                article["link"]
            )

        title = normalize_title(
            article["title"]
        )

        if title not in seen["titles"]:

            seen["titles"].append(
                title
            )

    save_seen(
        seen
    )

    print(
        f"Successfully posted "
        f"{len(posted)} articles."
    )


if __name__ == "__main__":
    main()
