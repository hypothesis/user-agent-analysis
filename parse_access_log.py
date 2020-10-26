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
    """

    # The "combined" log line format consists of:
    #
    # $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
    # "$http_referer" "$http_user_agent"

    ip_pat = "[0-9.]+"
    user_pat = "[^ ]+"
    time_pat = "[^]]+"
    quoted_str_pat = '[^"]*'
    number_pat = "[0-9]+"
    combined_pat = f'({ip_pat}) - ({user_pat}) \[({time_pat})\] "({quoted_str_pat})" ({number_pat}) ({number_pat}) "({quoted_str_pat})" "({quoted_str_pat})"'

    for line in lines:
        match = re.match(combined_pat, line)
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


def major_version(version_str):
    return version_str.split(".")[0]


def equivalent_major_browser(user_agent_tokens):
    """
    Return the major browser name and version that is equivalent to a given user agent

    This attempts to match a user agent to the closest equivalent major browser
    and version, which can be used to check what features the browser is likely
    to support based on information in MDN or caniuse.com.
    """

    def find_token(*names):
        matches = [t for t in user_agent_tokens if t[0] in names]
        return matches[0] if matches else None

    chrome_token = find_token("Chrome", "Brave Chrome", "like Chrome", "HeadlessChrome")
    if chrome_token:
        return ("Chrome", major_version(chrome_token[1]))

    firefox_token = find_token("Firefox")
    if firefox_token:
        return ("Firefox", major_version(firefox_token[1]))

    safari_token = find_token("Version")
    if safari_token:
        return ("Safari", major_version(safari_token[1]))

    # Embedded web views on iOS all run the same WebKit release as Safari.
    #
    # The Safari version number doesn't appear as a product token, but it can be
    # inferred from the iOS version info in the `Mozilla/5.0` token.
    #
    # This does not work if the user is using "Request Desktop Site". In that
    # case the user agent returns a hard-coded macOS version. See
    # https://bugs.webkit.org/show_bug.cgi?id=196275. We could however infer
    # the Safari version to be whatever shipped with the given hard-coded macOS
    # version.
    moz_token = find_token("Mozilla")
    platform_info = moz_token[2] if moz_token else None
    if platform_info:
        ios_version_match = re.search("(?:iPhone|CPU) OS ([0-9_]+)", platform_info)
        if ios_version_match:
            ios_version = ios_version_match[1].replace("_", ".")
            return ("Safari", major_version(ios_version))

        ie_match = re.search("Trident/7.0; rv:([0-9.]+)", platform_info)
        if ie_match:
            ie_version = ie_match[1]
            return ("Internet Explorer", major_version(ie_version))

    return None


# Mapping between product names in the user agent string and browser names.
ua_product_name_to_browser = {
    "CriOS": "Chrome (iOS)",
    "Edg": "Edge (Modern)",  # Chromium-based Edge.
    "Edge": "Edge (Legacy)",  # EdgeHTML-based Edge.
    "OPR": "Opera",  # Chromium-based Opera.
    # Modern versions of Safari include both a `Safari/<Version>` and `Version/<Version>` token.
    # The token with the product name `Version` actually contains the user-facing
    # Safari version.
    "Version": "Safari",
}


csv_writer = csv.writer(sys.stdout)
for entry in parse_nginx_combined_log(line.strip() for line in sys.stdin):
    tokens = parse_user_agent(entry.user_agent)
    tokens = sort_user_agent_tokens(tokens)
    compat_token = equivalent_major_browser(tokens)

    if tokens:
        main_token = tokens[0]
        name = main_token[0]
        name = ua_product_name_to_browser.get(name) or name
        version = main_token[1]
        version_major = major_version(version) if version else None
        compat_name = compat_token[0] if compat_token else None
        compat_version = compat_token[1] if compat_token else None

        csv_writer.writerow(
            [name, version_major, compat_name, compat_version, entry.user_agent]
        )
    else:
        print("Failed to parse user agent: ", entry.user_agent, file=sys.stderr)
