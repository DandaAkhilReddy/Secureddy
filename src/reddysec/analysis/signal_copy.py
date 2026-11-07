"""Plain-English copy for the lure signals (ClickFix, scam pages, phishing-kit
tells, device-code and consent lures, free hosting, hidden characters).

Written for the client, not for an analyst: short, calm, no jargon. Each entry
has a ``title`` (one line), an ``explanation`` (what it means, one or two
sentences) and ``what_to_do``. Placeholders in braces (``{filename}``,
``{host}``, ``{brand}``) are filled by the web presenters from the signal's
evidence, the same way ``web.presenters.SIGNAL_COPY`` works; they are only
used where the evidence always carries the value.

``CLICK_ADVICE_COPY`` holds the matching words for the per-link "is it safe
to click?" result (``UrlVerdict.click_advice``).
"""

from __future__ import annotations

_DONT = "Do not open this link. If you need to see it, use the Reading Room."

SIGNAL_COPY: dict[str, dict[str, str]] = {
    # ---- ClickFix family (sandbox)
    "dynamic.clickfix": {
        "title": "Fake 'I'm not a robot' check",
        "explanation": "The page asks you to press keys and paste something into Windows. Real websites never do this. "
                       "It would install spyware.",
        "what_to_do": "Do not follow the steps. If you already did, tell us right away and disconnect from the internet.",
    },
    "dynamic.clipboard_hijack": {
        "title": "The page copied a hidden command",
        "explanation": "When we opened the link, the page quietly put a dangerous command on the clipboard. "
                       "Pasting it into your computer would install malware.",
        "what_to_do": "Do not paste anything after visiting this page. If you already did, tell us right away.",
    },
    "dynamic.fake_captcha": {
        "title": "Fake 'I'm not a robot' check",
        "explanation": "The page pretends to be a security check. Real checks only ask you to tick a box or pick pictures, "
                       "never to press keys or paste anything.",
        "what_to_do": _DONT,
    },
    # ---- other scam pages (sandbox)
    "dynamic.tech_support_scam": {
        "title": "Fake virus warning",
        "explanation": "The page pretends your computer is infected and tells you to call a phone number. "
                       "The people on that number are scammers.",
        "what_to_do": "Do not call the number. Close the browser tab. If the page will not close, restart the computer.",
    },
    "dynamic.wallet_drainer": {
        "title": "Crypto wallet theft page",
        "explanation": "The page asks you to connect a crypto wallet or type your recovery phrase. "
                       "Anyone with that phrase can take all the money.",
        "what_to_do": "Never type a recovery phrase into a website. Do not connect your wallet.",
    },
    "dynamic.notification_spam": {
        "title": "The page asks to send you notifications",
        "explanation": "Scam sites ask you to press 'Allow' so they can fill your screen with fake virus alerts and ads.",
        "what_to_do": "Press 'Block' if you ever see this request. You can remove allowed sites in your browser settings.",
    },
    # ---- phishing-kit tells (sandbox)
    "dynamic.aitm_proxy": {
        "title": "Copy of a real sign-in page",
        "explanation": "The page shows the real {brand} sign-in screen, but from someone else's website. "
                       "It can steal your password and the security code you type after it.",
        "what_to_do": "Do not sign in there. Go to the company's website by typing it yourself.",
    },
    "dynamic.captcha_gated_login": {
        "title": "A security check hides a sign-in page",
        "explanation": "The page asks you to prove you are human, then shows a sign-in form. "
                       "Phishing sites do this so security scanners cannot see the fake sign-in page.",
        "what_to_do": "Do not sign in there. Use the company's own website or app.",
    },
    "dynamic.anti_analysis": {
        "title": "The page tries to hide from security tools",
        "explanation": "The page runs code that stops inspection. Ordinary websites do not need this.",
        "what_to_do": "Be careful with this link. Use the Reading Room if you need to see it.",
    },
    "dynamic.ua_cloaking": {
        "title": "The page shows scanners something different",
        "explanation": "The page checks whether a security scanner is looking and changes what it shows.",
        "what_to_do": "Be careful with this link. Use the Reading Room if you need to see it.",
    },
    "dynamic.free_hosting_login": {
        "title": "Sign-in page on a free website service",
        "explanation": "The page asks you to sign in, but it lives on a free website service anyone can use. "
                       "Real companies use their own websites.",
        "what_to_do": "Do not sign in there. Go to the company's website by typing it yourself.",
    },
    "dynamic.device_code_lure": {
        "title": "Asks you to type a code to 'join' or 'verify'",
        "explanation": "Typing this code on a Microsoft or Google page would sign someone else in to your account.",
        "what_to_do": "Do not enter the code. If you already did, tell us right away so we can sign them out.",
    },
    # ---- the email itself
    "bec.device_code_lure": {
        "title": "Asks you to type a code to 'join' or 'verify'",
        "explanation": "The email asks you to enter a code on a Microsoft or Google page. Doing that would sign "
                       "someone else in to your account. Real meetings and documents never need this.",
        "what_to_do": "Do not enter the code. If you already did, tell us right away so we can sign them out.",
    },
    "bec.callback_scam": {
        "title": "Fake bill that wants a phone call",
        "explanation": "The email says you were charged or renewed and gives a number to call to cancel. "
                       "The number goes to scammers who ask for card details or control of your computer.",
        "what_to_do": "Do not call the number. Check your bank or the company's own app instead.",
    },
    # ---- links (static)
    "url.free_hosting": {
        "title": "Link goes to a free website service",
        "explanation": "Anyone can make a page there in minutes. Real companies rarely send you to one.",
        "what_to_do": "Be careful with this link, especially if it asks you to sign in.",
    },
    "url.open_redirect": {
        "title": "Link starts on a trusted site but forwards you elsewhere",
        "explanation": "The link begins with a well-known name so it looks safe, then sends you to a different website.",
        "what_to_do": "Look at where it really goes (we show the full path below), or use the Reading Room.",
    },
    "url.oauth_consent_lure": {
        "title": "Link asks you to give an app access to your account",
        "explanation": "Clicking 'Accept' would let an unknown app read your email or files, even after you change your password.",
        "what_to_do": "Do not accept. If you already did, tell us so we can remove the app's access.",
    },
    "url.hidden_characters": {
        "title": "Link text hides invisible characters",
        "explanation": "Invisible characters break up words so filters cannot read them. Real companies do not need them.",
        "what_to_do": "Be careful with this link. Use the Reading Room if you need to see it.",
    },
    "sender.display_hidden_chars": {
        "title": "The sender's name hides invisible characters",
        "explanation": "Invisible characters break up a company name so spam filters cannot read it.",
        "what_to_do": "Treat this email with care. Real companies do not do this.",
    },
    # ---- attachments
    "attachment.svg_phish": {
        "title": "An 'image' that opens a fake page",
        "explanation": "{filename} looks like a picture, but opening it would run code, show a sign-in form or send "
                       "you to a phishing site.",
        "what_to_do": "Do not open the attachment.",
    },
    "attachment.html_clickfix": {
        "title": "Fake check that makes you paste a command",
        "explanation": "{filename} is a web page that copies a command and tells you to press keys to run it. "
                       "That would install malware.",
        "what_to_do": "Do not open the attachment or follow its steps. If you already did, tell us right away.",
    },
    "attachment.filename_trick": {
        "title": "The file hides its real type",
        "explanation": "The name of {filename} uses hidden characters or spaces so a program looks like a document.",
        "what_to_do": "Do not open the attachment.",
    },
}

CLICK_ADVICE_COPY: dict[str, dict[str, str]] = {
    "safe_to_open": {
        "label": "Safe to open",
        "explanation": "We checked this link and it goes to a normal page on a well-known website.",
    },
    "open_in_reading_room": {
        "label": "Open only in the Reading Room",
        "explanation": "We found nothing conclusive, but we cannot vouch for it. The Reading Room opens it on our "
                       "computers, so nothing reaches yours.",
    },
    "do_not_open": {
        "label": "Do not open",
        "explanation": "We saw this link do something harmful. Do not open it, even in the Reading Room, unless we ask you to.",
    },
}


def copy_for(code: str) -> dict[str, str] | None:
    """The copy for ``code``, or ``None`` when this module does not cover it."""
    return SIGNAL_COPY.get(code)
