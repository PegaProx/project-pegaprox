# -*- coding: utf-8 -*-
"""
PegaProx Email Utilities - Layer 3
SMTP email sending.
"""

import os
import logging
import socket
import ssl
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

def send_email(to_addresses: list, subject: str, body: str, html_body: str = None,
               smtp_settings: dict = None) -> tuple:
    """send email via smtp"""
    # MK: spent way too long on this, every smtp server is different
    if smtp_settings:
        settings = smtp_settings
    else:
        from pegaprox.api.helpers import load_server_settings
        settings = load_server_settings()
    
    if not smtp_settings and not settings.get('smtp_enabled'):
        return False, "SMTP not enabled"
    
    smtp_host = settings.get('smtp_host', '')
    smtp_port = int(settings.get('smtp_port', 587) or 587)
    smtp_user = settings.get('smtp_user', '')
    # NS: Feb 2026 - SECURITY: decrypt stored password (encrypted since 0.7.0)
    # If smtp_settings dict was passed directly (e.g. SMTP test), password is already plaintext
    raw_smtp_password = settings.get('smtp_password', '')
    if smtp_settings:
        # Caller provided settings directly (e.g. SMTP test) - password is plaintext
        smtp_password = raw_smtp_password
    else:
        # Loaded from DB - needs decryption
        from pegaprox.core.db import get_db
        try:
            smtp_password = get_db()._decrypt(raw_smtp_password) if raw_smtp_password else ''
        except Exception:
            smtp_password = raw_smtp_password  # Fallback for unencrypted legacy values
    from_email = settings.get('smtp_from_email', '')
    from_name = settings.get('smtp_from_name', '') or 'PegaProx'
    use_tls = settings.get('smtp_tls', True)
    use_ssl = settings.get('smtp_ssl', False)
    
    if not smtp_host:
        return False, "SMTP host not configured"
    if not from_email:
        return False, "From email not configured"
    
    if isinstance(to_addresses, str):
        to_addresses = [to_addresses]
    
    # print(f"sending to {to_addresses}")  # DEBUG - NS
    logging.info(f"[SMTP] sending to {to_addresses} via {smtp_host}:{smtp_port}")
    
    try:
        from email.utils import formatdate, make_msgid
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{from_name} <{from_email}>" if from_name else from_email
        msg['To'] = ', '.join(to_addresses)
        msg['Date'] = formatdate(localtime=True)
        msg['Message-ID'] = make_msgid(domain=from_email.split('@')[-1] if '@' in from_email else 'pegaprox.local')
        
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        
        if html_body:
            msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        
        # Connect and send
        if use_ssl:
            logging.debug(f"[SMTP] Connecting with SSL to {smtp_host}:{smtp_port}")
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15)
        else:
            logging.debug(f"[SMTP] Connecting to {smtp_host}:{smtp_port}")
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        
        # Debug mode disabled for production (would log passwords!)
        # server.set_debuglevel(1)
        
        # Identify ourselves to the server
        server.ehlo()
        
        if not use_ssl and use_tls:
            logging.debug("[SMTP] Starting TLS")
            server.starttls()
            server.ehlo()  # Re-identify after TLS
        
        # Authenticate if credentials provided
        if smtp_user and smtp_password and smtp_password != '********':
            logging.info(f"[SMTP] Authenticating as {smtp_user}")
            server.login(smtp_user, smtp_password)
        else:
            logging.warning(f"[SMTP] No authentication! user={bool(smtp_user)}, password={bool(smtp_password and smtp_password != '********')}")
        
        # Send the email
        refused = server.sendmail(from_email, to_addresses, msg.as_string())
        server.quit()
        
        if refused:
            logging.warning(f"[SMTP] Some recipients refused: {refused}")
            return False, f"Some recipients refused: {list(refused.keys())}"
        
        logging.info(f"[SMTP] Email sent successfully to {to_addresses}: {subject}")
        return True, None
        
    except smtplib.SMTPAuthenticationError as e:
        error = f"Authentication failed: Check username/password"
        logging.error(f"[SMTP] {error}: {e}")
        return False, error
    except smtplib.SMTPRecipientsRefused as e:
        # Get detailed error
        details = []
        for addr, (code, msg) in e.recipients.items():
            details.append(f"{addr}: {code} {msg.decode() if isinstance(msg, bytes) else msg}")
        error = f"Recipients refused: {'; '.join(details)}"
        logging.error(f"[SMTP] {error}")
        return False, error
    except smtplib.SMTPSenderRefused as e:
        error = f"Sender refused ({from_email}): {e.smtp_error.decode() if isinstance(e.smtp_error, bytes) else e.smtp_error}"
        logging.error(f"[SMTP] {error}")
        return False, error
    except smtplib.SMTPDataError as e:
        error = f"Data error: {e.smtp_error.decode() if isinstance(e.smtp_error, bytes) else e.smtp_error}"
        logging.error(f"[SMTP] {error}")
        return False, error
    except smtplib.SMTPConnectError as e:
        error = f"Connection failed to {smtp_host}:{smtp_port}"
        logging.error(f"[SMTP] {error}: {e}")
        return False, error
    except socket.timeout:
        error = f"Connection timeout to {smtp_host}:{smtp_port}"
        logging.error(f"[SMTP] {error}")
        return False, error
    except socket.gaierror as e:
        error = f"DNS resolution failed for {smtp_host}"
        logging.error(f"[SMTP] {error}: {e}")
        return False, error
    except ConnectionRefusedError:
        error = f"Connection refused by {smtp_host}:{smtp_port}"
        logging.error(f"[SMTP] {error}")
        return False, error
    except Exception as e:
        error = f"Failed to send email: {str(e)}"
        logging.error(f"[SMTP] {error}")
        return False, error

