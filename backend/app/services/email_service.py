import os
import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from dotenv import load_dotenv

load_dotenv()


class EmailService:
    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST")
        self.smtp_port = int(os.getenv("SMTP_PORT", 587))
        self.smtp_email = os.getenv("SMTP_EMAIL")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.smtp_from = os.getenv("SMTP_FROM", "ShadowScan")

    def send_email(
        self,
        to_email: str,
        subject: str,
        body: str,
    ) -> bool:
        """
        Send a plain text email.
        Returns True on success, False on failure.
        """

        try:
            message = MIMEMultipart()

            message["From"] = (
                f"{self.smtp_from} <{self.smtp_email}>"
            )
            message["To"] = to_email
            message["Subject"] = subject

            message.attach(
                MIMEText(body, "plain")
            )

            with smtplib.SMTP(
                self.smtp_host,
                self.smtp_port,
            ) as server:

                server.starttls()

                server.login(
                    self.smtp_email,
                    self.smtp_password,
                )

                server.send_message(message)

            return True

        except Exception as e:
            print(f"Email Error: {e}")
            return False

    def send_verification_email(
        self,
        to_email: str,
        otp: str,
    ) -> bool:
        """
        Send email verification OTP.
        """

        subject = "ShadowScan Email Verification"

        body = f"""
Hello,

Welcome to ShadowScan.

Your verification code is:

{otp}

This OTP will expire in 5 minutes.

If you didn't request this account, please ignore this email.

Regards,
ShadowScan Team
"""

        return self.send_email(
            to_email,
            subject,
            body,
        )

    def send_password_reset_email(
        self,
        to_email: str,
        otp: str,
    ) -> bool:
        """
        Send password reset OTP.
        """

        subject = "ShadowScan Password Reset"

        body = f"""
Hello,

We received a request to reset your ShadowScan password.

Your OTP is:

{otp}

This OTP will expire in 5 minutes.

If you didn't request this password reset, please ignore this email.

Regards,
ShadowScan Team
"""

        return self.send_email(
            to_email,
            subject,
            body,
        )