"""
Email helper — SendGrid API.

Much simpler and more reliable than SMTP on cloud platforms like Render.
Requires:
  SENDGRID_API_KEY  — your SendGrid API key
  MAIL_USERNAME     — verified sender email on SendGrid (e.g. your Gmail)
"""
import os
import logging

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

log = logging.getLogger(__name__)


def send_email(
    subject: str,
    to_email: str,
    body_text: str,
    body_html: str,
    mail_username: str | None = None,
    mail_password: str | None = None,
    from_name: str = "CheckMyURL Security",
    **_kwargs,
):
    """
    Send an email via SendGrid.

    Parameters
    ----------
    subject      : Email subject line.
    to_email     : Recipient email address.
    body_text    : Plain-text body.
    body_html    : HTML body.
    mail_username: Sender email address (falls back to MAIL_USERNAME env var).
                   Must be a verified sender on your SendGrid account.
    mail_password: Ignored — kept for backward compatibility.
    from_name    : Friendly name shown to the recipient.
    """
    sender_email = mail_username or os.getenv("MAIL_USERNAME", "")
    api_key = os.getenv("SENDGRID_API_KEY", "")

    if not api_key:
        raise RuntimeError(
            "SENDGRID_API_KEY environment variable is not set. "
            "Add it to your Render environment variables."
        )

    if not sender_email:
        raise RuntimeError(
            "No sender email specified. Set MAIL_USERNAME env var "
            "to the email address you verified on SendGrid."
        )

    # Use a tuple (email, name) for from_email to set a friendly display name
    from_email = (sender_email, from_name)

    message = Mail(
        from_email=from_email,
        to_emails=to_email,
        subject=subject,
        html_content=body_html,
    )
    
    # Add a Reply-To header to improve trust signals
    message.reply_to = sender_email


    try:
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)
        log.info(
            f"[MAILER] SendGrid success: to={to_email}, "
            f"status={response.status_code}"
        )
        return True
    except Exception as e:
        log.error(f"[MAILER] SendGrid failed: {e}")
        raise RuntimeError(f"Failed to send email via SendGrid: {e}") from e
