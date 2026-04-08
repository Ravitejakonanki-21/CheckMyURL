"""
Email helper with two strategies:
  1. SMTP (direct, works locally and on paid hosting)
  2. Resend HTTP API (works on Render free tier where SMTP ports are blocked)

The function tries SMTP first (fast, no third-party dependency for local dev),
and falls back to Resend when SMTP fails.
"""
import os
import smtplib
import socket
import ssl
import logging
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

log = logging.getLogger(__name__)

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
# Use a verified domain sender if you have one, otherwise Resend's test sender
RESEND_FROM = os.getenv("RESEND_FROM", "CYBERSHIELD <onboarding@resend.dev>")


def _resolve_ipv4(hostname: str, port: int) -> str:
    """Resolve hostname to an IPv4 address."""
    results = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
    if not results:
        raise RuntimeError(f"Could not resolve {hostname} to IPv4")
    return results[0][4][0]


def _send_via_resend(subject: str, to_email: str, body_html: str, body_text: str) -> None:
    """Send email via Resend HTTP API (works over HTTPS port 443)."""
    api_key = RESEND_API_KEY
    if not api_key:
        raise RuntimeError("RESEND_API_KEY not set — cannot send via Resend")

    payload = json.dumps({
        "from": RESEND_FROM,
        "to": [to_email],
        "subject": subject,
        "html": body_html,
        "text": body_text,
    }).encode("utf-8")

    req = Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        resp = urlopen(req, timeout=15)
        result = json.loads(resp.read().decode())
        log.info(f"[MAILER] Resend success: {result}")
    except HTTPError as e:
        body = e.read().decode()
        log.error(f"[MAILER] Resend HTTP {e.code}: {body}")
        raise RuntimeError(f"Resend API error ({e.code}): {body}")
    except URLError as e:
        raise RuntimeError(f"Resend connection error: {e.reason}")


def _send_via_smtp(
    subject: str,
    to_email: str,
    body_text: str,
    body_html: str,
    mail_username: str,
    mail_password: str,
    mail_server: str = "smtp.gmail.com",
) -> None:
    """Send email via SMTP with forced IPv4 + proper hostname SNI."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = mail_username
    msg["To"] = to_email
    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))

    ipv4_addr = _resolve_ipv4(mail_server, 587)
    log.info(f"[MAILER] SMTP: resolved {mail_server} -> {ipv4_addr}")

    # STARTTLS on port 587, connect to IPv4, use hostname for cert verification
    ctx = ssl.create_default_context()
    smtp = smtplib.SMTP(timeout=10)
    smtp.connect(ipv4_addr, 587)
    smtp._host = mail_server  # Fix SNI hostname for cert verification
    smtp.ehlo(mail_server)
    smtp.starttls(context=ctx)
    smtp.ehlo(mail_server)
    smtp.login(mail_username, mail_password)
    smtp.sendmail(mail_username, to_email, msg.as_string())
    smtp.quit()


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
    Send an email. Tries SMTP first (works locally), falls back to
    Resend HTTP API (works on Render/cloud where SMTP ports are blocked).
    """
    # ── Attempt 1: SMTP (fast, works locally)
    try:
        log.info("[MAILER] Trying SMTP...")
        _send_via_smtp(
            subject, to_email, body_text, body_html,
            mail_username, mail_password, mail_server,
        )
        log.info("[MAILER] SMTP succeeded")
        return
    except Exception as e:
        log.warning(f"[MAILER] SMTP failed: {e}")

    # ── Attempt 2: Resend HTTP API (works on Render)
    try:
        log.info("[MAILER] Trying Resend HTTP API...")
        _send_via_resend(subject, to_email, body_html, body_text)
        log.info("[MAILER] Resend succeeded")
        return
    except Exception as e:
        log.error(f"[MAILER] Resend failed: {e}")
        raise RuntimeError(f"All email methods failed. SMTP blocked, Resend error: {e}")
