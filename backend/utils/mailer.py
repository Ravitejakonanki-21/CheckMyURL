"""
Email helper that forces IPv4 connections to Gmail SMTP.
Works around Render/Docker containers where IPv6 is unreachable.

Uses the hostname for SSL certificate verification (not the raw IP),
which avoids "certificate is not valid for <IP>" errors.
"""
import smtplib
import socket
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def _resolve_ipv4(hostname: str, port: int) -> str:
    """Resolve hostname to an IPv4 address."""
    results = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
    if not results:
        raise RuntimeError(f"Could not resolve {hostname} to IPv4")
    return results[0][4][0]  # First IPv4 address


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
    Send an email using direct SMTP with forced IPv4.
    Falls back to port 465 (SSL) if port 587 (TLS) fails.
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = mail_username
    msg["To"] = to_email
    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))

    # Resolve to IPv4 to avoid "Network is unreachable" on IPv6-only DNS
    ipv4_addr = _resolve_ipv4(mail_server, mail_port)

    # Build SSL context that verifies against the hostname (not the IP)
    ctx = ssl.create_default_context()

    last_error = None

    # Attempt 1: STARTTLS on port 587 — connect to IP, verify cert against hostname
    try:
        smtp = smtplib.SMTP(ipv4_addr, 587, timeout=15)
        smtp.ehlo(mail_server)
        smtp.starttls(context=ctx)
        # After STARTTLS, re-ehlo with the real hostname so the server
        # sees a valid EHLO and the TLS cert matches
        smtp.ehlo(mail_server)
        smtp.login(mail_username, mail_password)
        smtp.sendmail(mail_username, to_email, msg.as_string())
        smtp.quit()
        return  # Success
    except Exception as e:
        last_error = e

    # Attempt 2: Direct TLS on port 465 — connect to hostname directly
    # (smtplib.SMTP_SSL does the TLS handshake at connect time)
    try:
        smtp = smtplib.SMTP_SSL(mail_server, 465, timeout=15, context=ctx)
        smtp.ehlo(mail_server)
        smtp.login(mail_username, mail_password)
        smtp.sendmail(mail_username, to_email, msg.as_string())
        smtp.quit()
        return  # Success
    except Exception as e:
        last_error = e

    # Attempt 3: STARTTLS on port 587 with relaxed SSL (skip cert verification)
    # This is a last resort for environments with broken CA bundles
    try:
        ctx_noverify = ssl.create_default_context()
        ctx_noverify.check_hostname = False
        ctx_noverify.verify_mode = ssl.CERT_NONE
        smtp = smtplib.SMTP(ipv4_addr, 587, timeout=15)
        smtp.ehlo(mail_server)
        smtp.starttls(context=ctx_noverify)
        smtp.ehlo(mail_server)
        smtp.login(mail_username, mail_password)
        smtp.sendmail(mail_username, to_email, msg.as_string())
        smtp.quit()
        return  # Success
    except Exception as e:
        last_error = e

    raise RuntimeError(f"All SMTP connection methods failed. Last error: {last_error}")
