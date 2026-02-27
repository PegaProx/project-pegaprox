# -*- coding: utf-8 -*-
"""
PegaProx Password Expiry Check - Layer 7
Background password expiry monitoring.
"""

import time
import logging
import threading
from datetime import datetime, date

from pegaprox.globals import (
    _password_expiry_running, _password_expiry_thread,
    _password_expiry_last_check,
)
from pegaprox.core.db import get_db
from pegaprox.api.helpers import load_server_settings
from pegaprox.models.permissions import ROLE_ADMIN
from pegaprox.utils.auth import load_users
from pegaprox.utils.email import send_email

def check_password_expiry():
    """Check all users for expiring passwords and send email notifications
    
    MK: This runs periodically to warn users about expiring passwords
    We track last notification to avoid spamming users
    NS: Only sends once per day per user, even if check runs more often
    """
    global _password_expiry_last_check
    
    settings = load_server_settings()
    if not settings.get('password_expiry_enabled'):
        return  # feature disabled, nothing to do
    if not settings.get('password_expiry_email_enabled', True):
        return  # emails disabled but UI warning still works
    if not settings.get('smtp_enabled'):
        return  # can't send emails without SMTP config
    
    expiry_days = settings.get('password_expiry_days', 90)
    warning_days = settings.get('password_expiry_warning_days', 14)
    include_admins = settings.get('password_expiry_include_admins', False)
    
    users_db = load_users()
    today = datetime.now().date()
    
    for username, user in users_db.items():
        # skip admins unless include_admins is enabled
        # NS: this was a feature request from IT-Sec - they want admins to rotate too
        if user.get('role') == ROLE_ADMIN and not include_admins:
            continue
        if not user.get('enabled', True):
            continue
        
        email = user.get('email')
        if not email:
            continue  # no email to send to
        
        changed_at = user.get('password_changed_at')
        if not changed_at:
            # treat as expired, but dont spam about it
            continue
        
        try:
            changed_date = datetime.fromisoformat(changed_at.replace('Z', '+00:00'))
            if changed_date.tzinfo:
                changed_date = changed_date.replace(tzinfo=None)
            days_since = (datetime.now() - changed_date).days
            days_until_expiry = expiry_days - days_since
            
            # LW: Only send notifications at specific intervals, not every day
            # NS: Users complained about too many emails, so we limit it to:
            # - First warning (configured warning_days, e.g. 14 days before)
            # - 7 days before
            # - 3 days before  
            # - 1 day before
            # - When expired (then every 3 days as reminder)
            # MK: we use a set to avoid duplicates if warning_days happens to be 7, 3, or 1
            notification_days = {warning_days, 7, 3, 1}
            
            should_notify = False
            if days_until_expiry <= 0:
                # expired - check if we should remind (every 3 days)
                last_notified = _password_expiry_last_check.get(username)
                if last_notified is None:
                    should_notify = True  # first notification after expiry
                else:
                    # remind every 3 days after expiry
                    days_since_notification = (today - last_notified).days if isinstance(last_notified, date) else 999
                    if days_since_notification >= 3:
                        should_notify = True
            elif days_until_expiry in notification_days:
                # exact match on notification days (14, 7, 3, 1 before expiry)
                should_notify = True
            
            if not should_notify:
                continue
            
            # Check if we already notified today (safety check)
            last_notified = _password_expiry_last_check.get(username)
            if last_notified == today:
                continue
            
            # Send notification - bilingual DE/EN because we dont track user language
            # NS: some users might want english only but this works for everyone
            display_name = user.get('display_name', username)
            
            if days_until_expiry <= 0:
                subject = f"[PegaProx] Password expired / Passwort abgelaufen"
                body = f"""Hello {display_name},

Your PegaProx password has expired. Please change it as soon as possible.

You can still log in, but you will be prompted to change your password.

Username: {username}

Best regards,
Your PegaProx System

---

Hallo {display_name},

Ihr PegaProx-Passwort ist abgelaufen. Bitte ändern Sie es so bald wie möglich.

Sie können sich weiterhin anmelden, werden aber aufgefordert Ihr Passwort zu ändern.

Benutzername: {username}

Mit freundlichen Grüßen,
Ihr PegaProx System"""
            else:
                subject = f"[PegaProx] Password expires in {days_until_expiry} days / Passwort läuft ab"
                body = f"""Hello {display_name},

Your PegaProx password will expire in {days_until_expiry} days.

Please change your password in time to avoid any interruptions.

Username: {username}

Best regards,
Your PegaProx System

---

Hallo {display_name},

Ihr PegaProx-Passwort läuft in {days_until_expiry} Tagen ab.

Bitte ändern Sie Ihr Passwort rechtzeitig um Unterbrechungen zu vermeiden.

Benutzername: {username}

Mit freundlichen Grüßen,
Ihr PegaProx System"""
            
            success, error = send_email([email], subject, body)
            if success:
                _password_expiry_last_check[username] = today
                logging.info(f"Password expiry notification sent to {username} ({days_until_expiry} days)")
            elif error:
                logging.warning(f"Password expiry email failed for {username}: {error}")
                
        except Exception as e:
            logging.error(f"Error checking password expiry for {username}: {e}")

_password_expiry_thread = None
_password_expiry_running = False

def password_expiry_check_loop():
    """Background thread that checks password expiry daily"""
    global _password_expiry_running
    _password_expiry_running = True
    
    while _password_expiry_running:
        try:
            check_password_expiry()
        except Exception as e:
            logging.error(f"Password expiry check error: {e}")
        
        # Check once every 6 hours
        time.sleep(6 * 60 * 60)

def start_password_expiry_thread():
    global _password_expiry_thread
    if _password_expiry_thread is None or not _password_expiry_thread.is_alive():
        _password_expiry_thread = threading.Thread(target=password_expiry_check_loop, daemon=True)
        _password_expiry_thread.start()
        logging.info("Password expiry check thread started")

