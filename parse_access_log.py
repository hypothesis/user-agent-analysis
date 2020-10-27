#!/usr/bin/env python3

import csv
import re
import sys


class AccessLogEntry:
    """
    Parsed log line from an nginx access log
    """

    def __init__(
        self, remote_addr, date_str, request, status, body_size, referrer, user_agent
    ):
        self.remote_addr = remote_addr
        self.date_str = date_str
        self.request = request
        self.status = status
        self.body_size = body_size
        self.referrer = referrer
        self.user_agent = user_agent


def parse_nginx_combined_log(lines):
    """
    Parse an nginx access log using the default "combined" format.

    See http://nginx.org/en/docs/http/ngx_http_log_module.html

    For convenience this function will also parse log lines which contain additional
    information in front of the nginx access log line. For example logs from Papertrail
    contain `<timestamp> <machine> <log source>:` entries in front of the log
    line.
    """

    # The "combined" log line format consists of:
    #
    # $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
    # "$http_referer" "$http_user_agent"

    ip_pat = "[0-9.]{4}"
    user_pat = "[^ ]+"
    time_pat = "[^]]+"
    quoted_str_pat = '[^"]*'
    number_pat = "[0-9]+"
    combined_pat = f'({ip_pat}) - ({user_pat}) \[({time_pat})\] "({quoted_str_pat})" ({number_pat}) ({number_pat}) "({quoted_str_pat})" "({quoted_str_pat})"'

    for line in lines:
        match = re.search(combined_pat, line)
        if not match:
            raise Exception(f"Failed to parse log line `{line}`")
        yield AccessLogEntry(
            remote_addr=match[1],
            date_str=match[3],
            request=match[4],
            status=int(match[5]),
            body_size=int(match[6]),
            referrer=match[7],
            user_agent=match[8],
        )


def parse_user_agent(user_agent_str):
    """
    Parse an HTTP User-Agent header.

    The User-Agent header is a space-delimited sequence of "product tokens", where each token
    consists of a product name, optional version and optional comment.

    eg. `Mozilla/5.0 (FooOS; x64; BarPhone (6)) ShinyBrowser/2.0`

    See https://tools.ietf.org/html/rfc7231#section-5.5.3.

    Returns a list of (product_name, version, comment) tuples.
    """

    name_version_pat = "^([\w .]+)(/([^ ]+))?"
    product_tokens = []

    user_agent_str = user_agent_str.strip()

    while True:
        # Parse product name and version.
        match = re.match(name_version_pat, user_agent_str)
        if not match:
            break
        name = match[1]
        version = match[3]
        user_agent_str = user_agent_str[len(match[0]) :].strip()

        # Parse comment.
        comment = None
        if len(user_agent_str) and user_agent_str[0] == "(":
            depth = 1
            for pos in range(1, len(user_agent_str)):
                if user_agent_str[pos] == "(":
                    depth += 1
                elif user_agent_str[pos] == ")":
                    depth -= 1
                    if depth == 0:
                        break
            comment = user_agent_str[1:pos]
            user_agent_str = user_agent_str[pos + 1 :].strip()

        product_tokens.append((name, version, comment))

    return product_tokens


def sort_user_agent_tokens(tokens):
    """
    Sort parsed tokens from a User-Agent header in order of uniqueness.

    Returns a sorted list of User-Agent tokens such that the least-generic tokens
    are at the front end the most generic ones (eg. "Mozilla") are at the end.

    The first token in the result will typically identify the browser, with the
    subsequent tokens providing fallbacks to recognize a user agent if the specific
    UA is not recognized.
    """
    generic_product_names = [
        # Most browser user agents start with "Mozilla/5.0".
        "Mozilla",
        # All Firefox user agents include "Gecko/<Version>". Most browser user
        # agents include "like Gecko", but that appears in a comment.
        "Gecko",
        # Most modern browser user agents include "AppleWebKit" or "Safari" for
        # mobile web compatibility. For non-Safari user agents, the version is
        # typically fixed at "537.36". In recent Safari versions the AppleWebKit
        # product version is frozen at "605.1.15".
        "AppleWebKit",
        "Safari",
        "Mobile Safari",
        # iOS applications with an embedded browser will contain `Mobile/15E148`
        # or similar. In this case the User Agent may not the equivalent Safari
        # version, however it can be inferred from the iOS/iPhone OS/iPad OS version.
        "Mobile",
        # Chrome-derived browsers will include Chrome in the UA. Some non-Chrome
        # user agents may include Chrome as well.
        "Chrome",
    ]

    def token_priority(token):
        name = token[0]
        try:
            return len(generic_product_names) - generic_product_names.index(name)
        except ValueError:
            return -1

    return sorted(tokens, key=token_priority)


def get_major_version(version_str):
    return version_str.split(".")[0]


def equivalent_major_browser(user_agent_tokens):
    """
    Return the major browser name and version that is equivalent to a given user agent

    This attempts to match a user agent to the main browser associated with the
    engine which the browser uses. For example, Chrome-derived browsers such
    as Edge and Brave are mapped to Chrome, and iOS browsers are mapped to Safari.

    The resulting browser/version is one which can be checked against compatibility
    data on MDN or caniuse.com.
    """

    def find_token(*names):
        matches = [t for t in user_agent_tokens if t[0] in names]
        return matches[0] if matches else None

    # Find EdgeHTML-based versions of Edge. Note that modern Edge versions use
    # "Edg" as the product token and are Chrome-based.
    edge_legacy_token = find_token("Edge")
    if edge_legacy_token:
        return ("Edge (Legacy)", get_major_version(edge_legacy_token[1]))

    firefox_token = find_token("Firefox")
    if firefox_token:
        return ("Firefox", get_major_version(firefox_token[1]))

    # Check for Chrome-based browsers. This comes after the check for Edge (Legacy)
    # because Edge Legacy had to pretend to be Chrome for web compatibility reasons.
    chrome_token = find_token("Chrome", "Brave Chrome", "like Chrome", "HeadlessChrome")
    if chrome_token:
        return ("Chrome", get_major_version(chrome_token[1]))

    safari_token = find_token("Version")
    if safari_token:
        return ("Safari", get_major_version(safari_token[1]))

    # In some environments there isn't a product token that directly identifies
    # the browser engine. In this situation we fall back to inferring it from
    # the platform information contained in the comment of the `Mozilla/5.0`
    # product token.
    moz_token = find_token("Mozilla")
    platform_info = moz_token[2] if moz_token else None
    if platform_info:
        # Embedded web views on iOS all run the same WebKit release as Safari.
        # The WebKit/Safari version can be inferred from the iOS version.
        ios_version_match = re.search("(?:iPhone|CPU) OS ([0-9_]+)", platform_info)
        if ios_version_match:
            ios_version = ios_version_match[1].replace("_", ".")
            return ("Safari", get_major_version(ios_version))

        # If a web page on iOS is being presented with the "Request Desktop Site" mode,
        # then the user agent changes to be a macOS user agent. As of 2020-10,
        # the macOS "version" is hard-coded. See https://bugs.webkit.org/show_bug.cgi?id=196275.
        macos_version_match = re.search("Mac OS X ([0-9]+_[0-9_]+)", platform_info)
        if macos_version_match:
            major_version, minor_version, *patch_version = macos_version_match[1].split(
                "_"
            )
            macos_version = (int(major_version), int(minor_version))

            if macos_version >= (10, 10) and macos_version <= (10, 14):
                safari_version = minor_version
            elif macos_version > (10, 14):
                # On macOS Big Sur and above Safari will be at least version 14.
                # In future there will be new releases as well.
                safari_version = 14
            if safari_version:
                return ("Safari", safari_version)

        # Internet Explorer version information is contained inside the comment
        # of the Mozilla/5.0 token, rather than being its own token.
        ie_match = re.search("Trident/7.0; rv:([0-9.]+)", platform_info)
        if ie_match:
            ie_version = ie_match[1]
            return ("Internet Explorer", get_major_version(ie_version))

    return None


# Mapping between product names in the user agent string and browser names.
ua_product_name_to_browser = {
    "CriOS": "Chrome (iOS)",  # Chrome for iOS. Uses same WebKit engine as Safari.
    "Edg": "Edge (Modern)",  # Chromium-based Edge.
    "Edge": "Edge (Legacy)",  # EdgeHTML-based Edge.
    "OPR": "Opera",  # Chromium-based Opera.
    # Modern versions of Safari include both a `Safari/<Version>` and `Version/<Version>` token.
    # The token with the product name `Version` actually contains the user-facing
    # Safari version.
    "Version": "Safari",
}


def is_user_agent_a_bot(tokens):
    """
    Return true if a parsed User-Agent header from a request probably indicates a bot.
    """

    # Collect candidate bot names from product tokens. The bot name will often,
    # but not always, appear in a comment rather than as the `name` part of a product token.
    #
    # See https://support.google.com/webmasters/answer/1061943?hl=en for example.
    terms = set()
    for name, version, comment in tokens:
        terms.add(name)
        if comment:
            comment_terms = [t.strip() for t in comment.split(";")]
            for ct in comment_terms:
                if "/" in ct:
                    # If a term like "Googlebot/2.1" appears in a comment, extract
                    # just the first part.
                    ct = ct.split("/")[0]
                terms.add(ct)

    # Check candidates to see if there is a name which suggests user agent is
    # a bot.
    for term in terms:
        # Match names like "Googlebot" or "FooBot".
        if re.match(".*bot$", term, re.IGNORECASE):
            return True

        # Match names like "Pingdom_bot_1.0"
        if re.search("[^A-Za-z]bot[^A-Za-z]", name, re.IGNORECASE):
            return True

    return False


csv_writer = csv.writer(sys.stdout)
for entry in parse_nginx_combined_log(line.strip() for line in sys.stdin):
    # Skip entries with no User-Agent header.
    if entry.user_agent == "-":
        continue

    # Skip entries from likely bots.
    tokens = parse_user_agent(entry.user_agent)
    if is_user_agent_a_bot(tokens):
        continue

    tokens = sort_user_agent_tokens(tokens)
    compat_token = equivalent_major_browser(tokens)

    if tokens:
        main_token = tokens[0]
        name = main_token[0]
        name = ua_product_name_to_browser.get(name) or name
        version = main_token[1]
        version_major = get_major_version(version) if version else None
        compat_name = compat_token[0] if compat_token else None
        compat_version = compat_token[1] if compat_token else None

        csv_writer.writerow(
            [name, version_major, compat_name, compat_version, entry.user_agent]
        )
    else:
        print("Failed to parse user agent: ", entry.user_agent, file=sys.stderr)
