"""Username enumeration across public platforms."""

import concurrent.futures

import requests

import utils

# each platform is a distinct host, so firing all checks at once doesn't
# hammer any single server the way sequential-with-no-delay would - the
# per-request 0.3s "politeness" sleep from the sequential version served no
# purpose here and was dropped along with it. Capped well under the
# platform count so a future long PLATFORMS list doesn't open dozens of
# sockets at once.
MAX_WORKERS = 10

# --- platform list for username enumeration -------------------------------
# format: name -> {"url": template, "reliable": bool, "not_found_text": str|None}
# where {u} is replaced with the target username.
#
# "reliable" reflects how each platform serves pages:
#
# reliable=True  = server-rendered. A missing profile gets a real HTTP 404
# from the server itself, so the status code is a trustworthy signal.
#
# reliable=False = JavaScript single-page app (SPA). The server returns the
# same 200 "app shell" for ANY url, real or fake - the actual "does this
# user exist" check happens client-side via JS after the page loads, which
# requests.get() never executes. Confirmed empirically: a deliberately
# fake Instagram username still returned 200. For these platforms a 200
# is NOT evidence the account exists - only an explicit 404 counts as
# real signal here.
#
# "not_found_text" (optional) = a string that appears in the page body when
# the account does NOT exist, even though the platform still returns HTTP
# 200. Some "reliable" platforms aren't fully reliable on status code alone
# - they serve a real 200 page that just happens to say "user not found"
# in the content. When set, a 200 response is only trusted as a real FOUND
# if this text is absent; if present, it gets reclassified as not_found
# despite the 200. Sourced from the Sherlock project's actively maintained
# platform-detection database (github.com/sherlock-project/sherlock),
# cross-checked rather than guessed, since a wrong string here just
# reintroduces the same false-positive problem in a sneakier form. Left
# unset (None) for platforms we haven't verified this way yet - status
# code is still used as-is for those rather than guessing at content.
#
# "requires_og_title" (optional, default False) = a different shape of the
# same problem: instead of a "not found" phrase appearing, a MISSING piece
# of content signals absence. Medium serves a 200 for every URL, real or
# fake, but only populates the <meta property="og:title"> tag with the
# person's name when the profile is real - a fake user gets no og:title
# tag at all. Verified empirically by comparing a known-real profile
# against a deliberately fake one side by side (real: og:title =
# "Patricia Torvalds - Medium"; fake: og:title absent entirely).
#
# One dict instead of two: adding a platform means adding one entry here,
# not remembering which of two collections it belongs in.
PLATFORMS = {
    "GitHub":      {"url": "https://github.com/{u}",                    "reliable": True, "not_found_text": None},
    # Reddit: DOWNGRADED to unreliable after investigation. Sherlock's
    # documented not_found_text ("Sorry, nobody on Reddit goes by that
    # name.") no longer applies - confirmed empirically that Reddit now
    # serves the SAME "Please wait for verification" bot-check interstitial
    # for BOTH a known-real username (torvalds) and a fake one, with nearly
    # identical body length (8438 vs 8442 bytes). That means a 200 from
    # Reddit currently confirms nothing - same practical problem as the SPA
    # platforms below, just manifesting as an anti-bot wall instead of a JS
    # app shell. Moved here rather than left as a broken "reliable" check.
    "Reddit":      {"url": "https://www.reddit.com/user/{u}",           "reliable": False, "not_found_text": None},
    # GitLab: investigated, no content-check added on purpose. GitLab sits
    # behind Cloudflare bot protection that frequently 403s plain
    # requests.get() calls - confirmed this happens even for a KNOWN-REAL
    # username (yukihiro-matz) and persists well after waiting, not just a
    # short burst-rate cooldown. That means we often can't see real page
    # content to check in the first place, so a not_found_text/og_title
    # check can't be reliably built or verified right now. This is fine:
    # our existing 403 handling already reports these as "unclear" rather
    # than a false FOUND, which is the honest answer. Expect GitLab to
    # show up as unclear more often than other reliable platforms.
    "GitLab":      {"url": "https://gitlab.com/{u}",                    "reliable": True, "not_found_text": None},
    "Medium":      {"url": "https://medium.com/@{u}",                   "reliable": True, "not_found_text": None, "requires_og_title": True},
    "Steam":       {"url": "https://steamcommunity.com/id/{u}",         "reliable": True, "not_found_text": "The specified profile could not be found"},
    "HackerNews":  {"url": "https://news.ycombinator.com/user?id={u}",  "reliable": True, "not_found_text": None},
    "Keybase":     {"url": "https://keybase.io/{u}",                    "reliable": True, "not_found_text": None},
    "Dev.to":      {"url": "https://dev.to/{u}",                        "reliable": True, "not_found_text": None},
    "Docker Hub":  {"url": "https://hub.docker.com/u/{u}",              "reliable": True, "not_found_text": None},
    "Twitter/X":   {"url": "https://x.com/{u}",                         "reliable": False, "not_found_text": None},
    "Instagram":   {"url": "https://www.instagram.com/{u}/",            "reliable": False, "not_found_text": None},
    "TikTok":      {"url": "https://www.tiktok.com/@{u}",               "reliable": False, "not_found_text": None},
    "Pinterest":   {"url": "https://www.pinterest.com/{u}/",            "reliable": False, "not_found_text": None},
    "YouTube":     {"url": "https://www.youtube.com/@{u}",              "reliable": False, "not_found_text": None},
    "Twitch":      {"url": "https://www.twitch.tv/{u}",                 "reliable": False, "not_found_text": None},
}


def _check_one(name, platform_info, username):
    """
    Runs a single platform's check and returns (bucket, entry, log_line)
    rather than printing/appending directly - this runs inside a worker
    thread, and interleaving prints from multiple threads at once would
    produce garbled output, so the caller prints once results are back in
    deterministic, PLATFORMS-ordered sequence.
    """
    url = platform_info["url"].format(u=username)
    is_reliable = platform_info["reliable"]
    try:
        r = utils.get_with_retry(url)
        entry = {"platform": name, "url": url, "status": r.status_code}
        # r.history is non-empty whenever a redirect happened - surface it
        # rather than silently following, since the final URL sometimes
        # differs meaningfully (e.g. GitHub normalizes case: JohnDoe -> johndoe)
        if r.history:
            entry["redirected_to"] = r.url
        if r.status_code == 404:
            # a real 404 is trustworthy on every platform, reliable or not
            return "not_found", entry, f"    [-] {name:12s} not found"
        elif r.status_code == 200 and is_reliable:
            not_found_text = platform_info.get("not_found_text")
            needs_og_title = platform_info.get("requires_og_title", False)
            if not_found_text and not_found_text in r.text:
                # status said "found", but the page content itself says
                # otherwise - trust the content, not the status code.
                entry["reason"] = "HTTP 200 but page content matched known 'not found' text"
                return "not_found", entry, f"    [-] {name:12s} not found (200 status, but page content confirms no such user)"
            elif needs_og_title and 'property="og:title"' not in r.text:
                # inverse case: absence of a piece of content signals
                # absence of the account, not presence of "not found" text
                entry["reason"] = "HTTP 200 but no og:title meta tag present (profile shell, not a real user page)"
                return "not_found", entry, f"    [-] {name:12s} not found (200 status, but no og:title meta tag - generic shell page)"
            else:
                return "found", entry, f"    [+] {name:12s} FOUND     {url}"
        elif r.status_code == 200 and not is_reliable:
            # this platform is marked unreliable because a 200 here doesn't
            # confirm anything - could be a JS SPA serving the same app
            # shell for any URL (Instagram, TikTok, etc), or a bot-check/
            # verification wall served regardless of username (Reddit,
            # confirmed empirically). Either way, the status code alone
            # can't distinguish a real account from a fake one here.
            entry["reason"] = "Platform marked unreliable: HTTP 200 does not confirm account existence here"
            return "unclear", entry, f"    [?] {name:12s} status=200 but this platform can't be reliably checked - not confirmed, verify manually  {url}"
        else:
            # unclear = could be a block (403), rate limit, redirect quirk, etc.
            # NOT the same as "not found" - the account may well exist, we just can't tell.
            # give a specific reason per known status code so downstream logic
            # (risk scoring, correlation) doesn't have to re-derive it from a raw number.
            if r.status_code == 403:
                reason = "HTTP 403 Forbidden - likely anti-bot block, not evidence of absence"
            elif r.status_code == 429:
                reason = "HTTP 429 Too Many Requests - rate limited, try again later"
            elif 500 <= r.status_code < 600:
                reason = f"HTTP {r.status_code} - platform server error, not related to this username"
            else:
                reason = f"HTTP {r.status_code} - unrecognized status, not confirmed absent"
            entry["reason"] = reason
            return "unclear", entry, f"    [?] {name:12s} status={r.status_code} (unclear - {reason}) {url}"
    except requests.exceptions.RequestException as e:
        entry = {
            "platform": name,
            "url": url,
            "reason": f"Request failed: {e.__class__.__name__}",
        }
        return "error", entry, f"    [!] {name:12s} error: {e.__class__.__name__}"


def check_username(username):
    print(f"\n[*] Checking username '{username}' across {len(PLATFORMS)} platforms...")
    # every platform lands in exactly one bucket - nothing gets silently dropped anymore.
    results = {"found": [], "not_found": [], "unclear": [], "error": []}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(PLATFORMS))) as executor:
        futures = {
            name: executor.submit(_check_one, name, platform_info, username)
            for name, platform_info in PLATFORMS.items()
        }
        # iterate in PLATFORMS order (not completion order) so CLI output
        # and bucket ordering stay deterministic across runs regardless of
        # which platform happens to respond fastest
        for name, future in futures.items():
            bucket, entry, log_line = future.result()
            print(log_line)
            results[bucket].append(entry)
    return results
