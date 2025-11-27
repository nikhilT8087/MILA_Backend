import smtplib
from email.mime.text import MIMEText
from config.basic_config import settings

#helper function for send_email
def send_email(to_email: str, subject: str, body: str):
    msg = MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"] = settings.EMAIL_FROM
    msg["To"] = to_email

    try:
        with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
            server.starttls()
            server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
            server.sendmail(settings.EMAIL_FROM, to_email, msg.as_string())
    except Exception as e:
        print(f"Error sending email: {e}")
        raise
