"""
Email helper — Gmail SMTP with multiple fallback strategies.

Strategy order (fastest/most reliable first):
  1. Port 587, STARTTLS  — standard Gmail SMTP, works on Render
  2. Port 465, SMTP_SSL  — Gmail SSL, fallback if 587 is filtered
  3. Resend HTTP API     — last resort if RESEND_API_KEY is set

Required Render env vars:
  MAIL_USERNAME  — your full Gmail address (e.g. yourname@gmail.com)
  MAIL_PASSWORD  — 16-character Gmail App Password (NOT your regular password)
                   Generate at: Google Account → Security → 2-Step Verification → App passwords

Optional:
  RESEND_API_KEY — only needed if Gmail SMTP is also blocked
  RESEND_FROM    — sender address on verified Resend domain
"""
import os
import smtplib
import socket
import ssl
import logging
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

log = logging.getLogger(__name__)

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
RESEND_FROM = os.getenv("RESEND_FROM", "CYBERSHIELD <onboarding@resend.dev>")


def _resolve_ipv4(hostname: str, port: int) -> str:
    """Force IPv4 resolution — avoids IPv6 connectivity issues on Render."""
    results = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
    if not results:
        raise RuntimeError(f"Could not resolve {hostname} to an IPv4 address")
    return results[0][4][0]


def _build_message(subject: str, from_addr: str, to_email: str,
                   body_text: str, body_html: str) -> MIMEMultipart:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_email
    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))
    return msg


def _smtp_587(subject, to_email, body_text, body_html, username, password):
    """Gmail SMTP with STARTTLS on port 587 — primary method."""
    ipv4 = _resolve_ipv4("smtp.gmail.com", 587)
    log.info(f"[MAILER] STARTTLS: smtp.gmail.com → {ipv4}:587")
    ctx = ssl.create_default_context()
    smtp = smtplib.SMTP(timeout=15)
    smtp.connect(ipv4, 587)
    smtp._host = "smtp.gmail.com"   # fix SNI for cert validation
    smtp.ehlo("smtp.gmail.com")
    smtp.starttls(context=ctx)
    smtp.ehlo("smtp.gmail.com")
    smtp.login(username, password)
    msg = _build_message(subject, username, to_email, body_text, body_html)
    smtp.sendmail(username, to_email, msg.as_string())
    smtp.quit()
    log.info("[MAILER] STARTTLS (587) succeeded")


def _smtp_465(subject, to_email, body_text, body_html, username, password):
    """Gmail SMTP_SSL on port 465 — fallback if 587 STARTTLS fails."""
    ipv4 = _resolve_ipv4("smtp.gmail.com", 465)
    log.info(f"[MAILER] SSL: smtp.gmail.com → {ipv4}:465")
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ctx, timeout=15) as smtp:
        smtp.login(username, password)
        msg = _build_message(subject, username, to_email, body_text, body_html)
        smtp.sendmail(username, to_email, msg.as_string())
    log.info("[MAILER] SSL (465) succeeded")


def _send_via_resend(subject: str, to_email: str, body_html: str, body_text: str) -> None:
    """Last-resort Resend HTTP API — only used if RESEND_API_KEY is set."""
    if not RESEND_API_KEY:
        raise RuntimeError("RESEND_API_KEY not configured")

    payload = {
        "from": RESEND_FROM,
        "to": [to_email],
        "subject": subject,
        "html": body_html,
        "text": body_text,
    }
    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        # Custom User-Agent avoids Cloudflare WAF blocks (error 1010)
        "User-Agent": "Mozilla/5.0 (compatible; CybershieldMailer/1.0)",
    }

    if _HAS_REQUESTS:
        resp = _requests.post(
            "https://api.resend.com/emails",
            json=payload,
            headers=headers,
            timeout=15,
        )
        if resp.status_code in (200, 201):
            log.info(f"[MAILER] Resend success: {resp.json()}")
            return
        body = resp.text
        if resp.status_code == 403 and "1010" in body:
            raise RuntimeError(
                "Resend blocked by Cloudflare WAF (1010) on Render's IP. "
                "Gmail SMTP should be used instead."
            )
        raise RuntimeError(f"Resend API error ({resp.status_code}): {body}")
    else:
        raise RuntimeError("requests library not available for Resend fallback")


def send_email(
    subject: str,
    to_email: str,
    body_text: str,
    body_html: str,
    mail_username: str,
    mail_password: str,
    mail_server: str = "smtp.gmail.com",
    mail_port: int = 587,
):
    """
    Send an email via Gmail SMTP (port 587 → 465 → Resend fallback).

    Requires:
      mail_username = Gmail address      (MAIL_USERNAME env var)
      mail_password = Gmail App Password (MAIL_PASSWORD env var)
                      NOT your regular Gmail password — must be a 16-char App Password.
                      Enable at: Google Account → Security → 2-Step Verification → App passwords
    """
    errors = []

    # ── Strategy 1: STARTTLS port 587 ────────────────────────────────────────
    try:
        _smtp_587(subject, to_email, body_text, body_html, mail_username, mail_password)
        return
    except smtplib.SMTPAuthenticationError as e:
        msg = (
            f"Gmail authentication failed (535). Make sure MAIL_PASSWORD is a "
            f"16-character App Password, not your regular Gmail password. "
            f"Details: {e}"
        )
        log.error(f"[MAILER] {msg}")
        # Auth error means credentials are wrong — no point trying port 465
        raise RuntimeError(msg) from e
    except Exception as e:
        log.warning(f"[MAILER] STARTTLS (587) failed: {e}")
        errors.append(f"587/STARTTLS: {e}")

    # ── Strategy 2: SMTP_SSL port 465 ────────────────────────────────────────
    try:
        _smtp_465(subject, to_email, body_text, body_html, mail_username, mail_password)
        return
    except smtplib.SMTPAuthenticationError as e:
        msg = (
            f"Gmail authentication failed (535) on port 465. "
            f"Use a Gmail App Password, not your regular password. Details: {e}"
        )
        log.error(f"[MAILER] {msg}")
        raise RuntimeError(msg) from e
    except Exception as e:
        log.warning(f"[MAILER] SSL (465) failed: {e}")
        errors.append(f"465/SSL: {e}")

    # ── Strategy 3: Resend HTTP API (last resort) ─────────────────────────────
    if RESEND_API_KEY:
        try:
            log.info("[MAILER] Falling back to Resend HTTP API...")
            _send_via_resend(subject, to_email, body_html, body_text)
            return
        except Exception as e:
            log.error(f"[MAILER] Resend failed: {e}")
            errors.append(f"Resend: {e}")

    raise RuntimeError(
        f"All email methods failed. Errors: {' | '.join(errors)}\n"
        f"Fix: Set MAIL_USERNAME (Gmail address) and MAIL_PASSWORD (Gmail App Password) "
        f"in your Render environment variables."
    )
