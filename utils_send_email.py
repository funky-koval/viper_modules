import os
import smtplib
import mimetypes
from email.message import EmailMessage
from email.utils import formatdate

def send_email(to_address, subject, msg_body, attachments=None, cfg=None):
    msg = EmailMessage()
    msg['From'] = cfg['address']
    msg['To'] = ', '.join(to_address)
    msg['Subject'] = subject
    msg['Date'] = formatdate(localtime=True)
    msg.set_content(msg_body)

    attachments = attachments or []
    for file_path in attachments:
        ctype, encoding = mimetypes.guess_type(file_path)
        if ctype is None or encoding is not None:
            ctype = 'application/octet-stream'
        maintype, subtype = ctype.split('/', 1)
        with open(file_path, 'rb') as f:
            file_data = f.read()
            msg.add_attachment(file_data, maintype=maintype, subtype=subtype, filename=os.path.basename(file_path))

    with smtplib.SMTP(cfg['smtp'], cfg.get('port', 587)) as server:
        if cfg.get('tls', True):
            server.starttls()
        if cfg.get('auth', True):
            server.login(cfg['username'], cfg['password'])
        server.send_message(msg)
