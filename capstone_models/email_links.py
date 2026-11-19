"""Extract explicit web destinations from mail text and HTML."""
import re
from urllib.parse import urlsplit

from email_intake_v1 import HTMLText
from train_email_baseline_v1 import EMAIL

PREFIX = re.compile(r'(?i)(?<![\w@/.])(?:https?://|//|www\.)[^\s<>"\x27]+')
MESSAGE_ID = re.compile(r'(?im)^\s*(?:>\s*)?(?:message-id|in-reply-to|references)\s*:[^\n]*(?:\n[ \t]+<[^\n]*)*')
WEB_PREFIXES = ("https://", "http://", "//", "www.")


class MailHTML(HTMLText):
    def handle_starttag(self, tag, attrs):
        if not self.hidden:
            super().handle_starttag(tag, attrs)
        elif tag in ("script", "style", "head"):
            self.hidden += 1


def text_url(token):
    token = token.rstrip(".,;:!?。！，；：？")
    for opening, closing in (("(", ")"), ("[", "]"), ("{", "}")):
        while token.endswith(closing) and token.count(closing) > token.count(opening):
            token = token[:-1]
    return token


def web_url(url):
    if not isinstance(url, str):
        raise TypeError("URL must be a string")
    url = url.strip()
    if not url.lower().startswith(WEB_PREFIXES) or any(c.isspace() for c in url):
        return None
    return url


def destinations(subject, body, *, visible="", hrefs=(), extracted_links=()):
    result = {}
    for origin, text in (("subject", subject), ("body", body), ("html_visible", visible)):
        text = MESSAGE_ID.sub("", text)
        email_spans = [m.span() for m in EMAIL.finditer(text)]
        for match in PREFIX.finditer(text):
            if any(start <= match.start() < end for start, end in email_spans):
                continue
            result.setdefault(text_url(match.group()), set()).add(origin)
    for origin, urls in (("html_href", hrefs), ("provided_destination", extracted_links)):
        for url in urls:
            url = web_url(url)
            if url is not None:
                result.setdefault(url, set()).add(origin)
    return result
