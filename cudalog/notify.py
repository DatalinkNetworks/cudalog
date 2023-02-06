from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List
import aiosmtplib
import os


async def send_email(
    host: str,
    port: int,
    username: str,
    password: str,
    to: str,
    subject: str,
    body: str,
    filenames: List[str],
    starttls: bool = False,
):
    msg = MIMEMultipart()
    msg["From"] = username
    msg["To"] = to
    msg["Subject"] = subject
    msg.attach(MIMEText(body))

    for i, filename in enumerate(filenames):
        with open(filename, "rb") as f:
            file_data = f.read()
            file_name = os.path.basename(filename)

        part = MIMEText(file_data, "plain", "utf-8")
        part.add_header("Content-Disposition", "attachment", filename=file_name)
        part.add_header("Content-ID", "<{}>".format(file_name))
        part.add_header("X-Attachment-Id", f"{i}")
        msg.attach(part)

    smtp = aiosmtplib.SMTP(hostname=host, port=port)
    await smtp.connect()
    await smtp.ehlo()
    if starttls:
        await smtp.starttls()
    await smtp.login(username, password)
    await smtp.send_message(msg)
    await smtp.quit()
