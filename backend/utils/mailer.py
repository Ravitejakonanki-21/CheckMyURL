"""
Email helper that forces IPv4 connections to Gmail SMTP.
Works around Render/Docker containers where IPv6 is unreachable.

Key fix: connects to the resolved IPv4 address but uses the real hostname
for SSL/TLS certificate verification (SNI), avoiding both IPv6 failures
and "certificate not valid for IP" errors.
"""
import smtplib
import socket
import ssl
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

log = logging.getLogger(__name__)


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
    Tries multiple connection strategies for maximum compatibility.
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = mail_username
    msg["To"] = to_email
    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))

    # Resolve to IPv4 to avoid "Network is unreachable" on IPv6-only DNS
    ipv4_addr = _resolve_ipv4(mail_server, mail_port)
    log.info(f"[MAILER] Resolved {mail_server} -> {ipv4_addr}")

    errors = []

    # ── Attempt 1: STARTTLS on port 587, connect to IPv4, verify cert
    #    against the real hostname (not the IP).
    try:
        log.info("[MAILER] Attempt 1: STARTTLS 587 via IPv4")
        ctx = ssl.create_default_context()
        smtp = smtplib.SMTP(timeout=15)
        smtp.connect(ipv4_addr, 587)
        # Override _host so starttls() uses the real hostname for SNI
        # and certificate verification instead of the IP address.
        smtp._host = mail_server
        smtp.ehlo(mail_server)
        smtp.starttls(context=ctx)
        smtp.ehlo(mail_server)
        smtp.login(mail_username, mail_password)
        smtp.sendmail(mail_username, to_email, msg.as_string())
        smtp.quit()
        log.info("[MAILER] Attempt 1 succeeded")
        return
    except Exception as e:
        log.warning(f"[MAILER] Attempt 1 failed: {e}")
        errors.append(f"STARTTLS-587-IPv4: {e}")

    # ── Attempt 2: SMTP_SSL on port 465, connect to IPv4 with proper SNI
    try:
        log.info("[MAILER] Attempt 2: SSL 465 via IPv4")
        ctx = ssl.create_default_context()
        # Manually create an IPv4 socket, then wrap with SSL using the
        # real hostname for certificate verification.
        raw_sock = socket.create_connection((ipv4_addr, 465), timeout=15)
        ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=mail_server)
        smtp = smtplib.SMTP_SSL(host=mail_server, context=ctx)
        smtp.sock = ssl_sock
        smtp.ehlo(mail_server)
        smtp.login(mail_username, mail_password)
        smtp.sendmail(mail_username, to_email, msg.as_string())
        smtp.quit()
        log.info("[MAILER] Attempt 2 succeeded")
        return
    except Exception as e:
        log.warning(f"[MAILER] Attempt 2 failed: {e}")
        errors.append(f"SSL-465-IPv4: {e}")

    # ── Attempt 3: STARTTLS on 587 with relaxed SSL (no cert verification)
    #    Last resort for environments with broken CA bundles or proxies.
    try:
        log.info("[MAILER] Attempt 3: STARTTLS 587 no-verify")
        ctx_nv = ssl.create_default_context()
        ctx_nv.check_hostname = False
        ctx_nv.verify_mode = ssl.CERT_NONE
        smtp = smtplib.SMTP(timeout=15)
        smtp.connect(ipv4_addr, 587)
        smtp._host = mail_server
        smtp.ehlo(mail_server)
        smtp.starttls(context=ctx_nv)
        smtp.ehlo(mail_server)
        smtp.login(mail_username, mail_password)
        smtp.sendmail(mail_username, to_email, msg.as_string())
        smtp.quit()
        log.info("[MAILER] Attempt 3 succeeded")
        return
    except Exception as e:
        log.warning(f"[MAILER] Attempt 3 failed: {e}")
        errors.append(f"STARTTLS-587-noverify: {e}")

    # ── Attempt 4: Direct hostname connection (port 465 SSL)
    #    Let Python resolve DNS naturally (works if IPv4 is preferred).
    try:
        log.info("[MAILER] Attempt 4: SSL 465 via hostname")
        ctx = ssl.create_default_context()
        smtp = smtplib.SMTP_SSL(mail_server, 465, timeout=15, context=ctx)
        smtp.ehlo(mail_server)
        smtp.login(mail_username, mail_password)
        smtp.sendmail(mail_username, to_email, msg.as_string())
        smtp.quit()
        log.info("[MAILER] Attempt 4 succeeded")
        return
    except Exception as e:
        log.warning(f"[MAILER] Attempt 4 failed: {e}")
        errors.append(f"SSL-465-hostname: {e}")

    error_detail = " | ".join(errors)
    raise RuntimeError(f"All SMTP methods failed: {error_detail}")
