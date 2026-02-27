# -*- coding: utf-8 -*-
"""settings, updates, backup/restore & security routes - split from monolith dec 2025, NS/MK"""

import subprocess
import shutil
import os
import sys
import json
import time
import logging
import threading
import re
from datetime import datetime
from flask import Blueprint, jsonify, request, Response, make_response, send_from_directory

from pegaprox.constants import *
from pegaprox.globals import *
from pegaprox.models.permissions import *
from pegaprox.core.db import get_db, ENCRYPTION_AVAILABLE

import requests
from pegaprox.utils.auth import require_auth, load_users, save_users, validate_session, TOTP_AVAILABLE, ARGON2_AVAILABLE, _check_default_password_in_use, verify_password, needs_password_rehash
from pegaprox.utils.ssh import get_ssh_connection_stats
from pegaprox.utils.concurrent import GEVENT_AVAILABLE
from pegaprox.utils.audit import log_audit, get_client_ip
from pegaprox.api.helpers import load_server_settings, save_server_settings, check_cluster_access, get_login_settings, get_session_timeout
from pegaprox.app import get_allowed_origins, add_allowed_origin
from pegaprox.globals import _cors_origins_env, _auto_allowed_origins

bp = Blueprint('settings', __name__)

@bp.route('/api/pegaprox/version', methods=['GET'])
@require_auth()
def get_pegaprox_version():
    """Get current PegaProx version"""
    return jsonify({
        'version': PEGAPROX_VERSION,
        'build': PEGAPROX_BUILD,
        'python_version': sys.version.split()[0],
        'gevent_available': GEVENT_AVAILABLE,
        'encryption_available': ENCRYPTION_AVAILABLE,
    })


# NS: Military Grade Encryption Status & Migration - Jan 2026
@bp.route('/api/pegaprox/security/status', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def get_security_status():
    """Get encryption and security status"""
    db = get_db()
    
    # Count items that need migration
    users_needing_migration = 0
    clusters_needing_migration = 0
    
    try:
        users_db = load_users()
        for user in users_db.values():
            if needs_password_rehash(user.get('password_salt', ''), user.get('password_hash', '')):
                users_needing_migration += 1
    except:
        pass
    
    try:
        cursor = db.conn.cursor()
        cursor.execute('SELECT pass_encrypted, ssh_key_encrypted FROM clusters')
        for row in cursor.fetchall():
            if db._needs_reencrypt(row[0]):
                clusters_needing_migration += 1
            elif row[1] and db._needs_reencrypt(row[1]):
                clusters_needing_migration += 1
    except:
        pass
    
    # Get login rate limit settings
    login_settings = get_login_settings()
    
    return jsonify({
        'encryption': {
            'available': ENCRYPTION_AVAILABLE,
            'algorithm': 'AES-256-GCM' if ENCRYPTION_AVAILABLE else 'None',
            'key_size': '256-bit',
            'mode': 'GCM (Authenticated Encryption)',
        },
        'password_hashing': {
            'available': ARGON2_AVAILABLE,
            'algorithm': 'Argon2id' if ARGON2_AVAILABLE else 'PBKDF2-SHA256',
            'memory_cost': '64 MB' if ARGON2_AVAILABLE else 'N/A',
            'iterations': 3 if ARGON2_AVAILABLE else 600000,
        },
        'rate_limiting': {
            'login': {
                'enabled': True,
                'max_attempts': login_settings['max_attempts'],
                'lockout_time': login_settings['lockout_time'],
                'window': login_settings['attempt_window'],
            },
            'api': {
                'enabled': API_RATE_LIMIT > 0,
                'requests_per_window': API_RATE_LIMIT,
                'window_seconds': API_RATE_WINDOW,
                'active_clients': len(api_request_counts),
            }
        },
        'session_management': {
            'timeout_minutes': get_session_timeout() // 60,
            'active_sessions': len(active_sessions),
            'encrypted_storage': True,
            'secure_cookies': True,
        },
        'migration': {
            'users_pending': users_needing_migration,
            'clusters_pending': clusters_needing_migration,
            'total_pending': users_needing_migration + clusters_needing_migration,
            'auto_migration': True,
        },
        'features': {
            'aes_256_gcm': ENCRYPTION_AVAILABLE,
            'argon2id': ARGON2_AVAILABLE,
            'login_rate_limiting': True,
            'api_rate_limiting': API_RATE_LIMIT > 0,
            'secure_sessions': True,
            'csp_headers': True,
            'hsts': True,
        }
    })


@bp.route('/api/pegaprox/security/migrate-all', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def migrate_all_encryption():
    """Force migration of all data to latest encryption
    
    NS: Migrates all passwords to Argon2id and all secrets to AES-256-GCM
    """
    if not ENCRYPTION_AVAILABLE:
        return jsonify({'error': 'Encryption not available'}), 400
    
    db = get_db()
    results = {
        'users_migrated': 0,
        'clusters_migrated': 0,
        'errors': []
    }
    
    # Migrate clusters
    try:
        cursor = db.conn.cursor()
        cursor.execute('SELECT id, pass_encrypted, ssh_key_encrypted FROM clusters')
        
        for row in cursor.fetchall():
            cluster_id = row[0]
            pass_encrypted = row[1]
            ssh_key_encrypted = row[2] or ''
            
            needs_update = False
            new_pass = pass_encrypted
            new_ssh_key = ssh_key_encrypted
            
            if db._needs_reencrypt(pass_encrypted):
                decrypted = db._decrypt(pass_encrypted)
                new_pass = db._encrypt(decrypted)
                needs_update = True
            
            if ssh_key_encrypted and db._needs_reencrypt(ssh_key_encrypted):
                decrypted = db._decrypt(ssh_key_encrypted)
                new_ssh_key = db._encrypt(decrypted)
                needs_update = True
            
            if needs_update:
                cursor.execute('''
                    UPDATE clusters SET pass_encrypted = ?, ssh_key_encrypted = ?, updated_at = ?
                    WHERE id = ?
                ''', (new_pass, new_ssh_key, datetime.now().isoformat(), cluster_id))
                results['clusters_migrated'] += 1
        
        db.conn.commit()
    except Exception as e:
        results['errors'].append(f"Cluster migration error: {e}")
    
    # Note: User password migration happens automatically on login
    # We can't migrate passwords without the original password
    results['users_note'] = 'User passwords will be migrated automatically on next login'
    
    user = request.session.get('user', 'unknown')
    log_audit(user, 'security.migration', f"Migrated {results['clusters_migrated']} clusters to AES-256-GCM")
    
    return jsonify({
        'success': True,
        'results': results,
        'message': f"Migrated {results['clusters_migrated']} clusters to Military Grade encryption"
    })


@bp.route('/api/pegaprox/check-update', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def check_pegaprox_update():
    """Check for PegaProx updates (mirror + GitHub fallback)"""
    try:
        # NS: Feb 2026 - GitHub first, mirror as fallback
        response = None
        for url in [GITHUB_VERSION_URL, MIRROR_VERSION_URL]:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    break
            except requests.RequestException:
                continue

        if not response or response.status_code != 200:
            status = response.status_code if response else 'unreachable'
            logging.warning(f"Update check failed: {status}")
            return jsonify({
                'error': f'Update server returned {status}',
                'current_version': PEGAPROX_VERSION,
                'current_build': PEGAPROX_BUILD,
                'update_available': False,
            }), 200  # Return 200 with error message so UI can still show current version
        
        try:
            remote_version = response.json()
        except Exception as json_err:
            logging.error(f"Failed to parse GitHub response: {json_err}")
            return jsonify({
                'error': 'Invalid response from GitHub',
                'current_version': PEGAPROX_VERSION,
                'current_build': PEGAPROX_BUILD,
                'update_available': False,
            }), 200
        
        current_version = PEGAPROX_VERSION.replace('Alpha ', '').replace('Beta ', '')
        latest_version = remote_version.get('version', '0.0')
        
        # Simple version comparison (works for semver-like versions)
        def parse_version(v):
            try:
                parts = str(v).replace('Alpha ', '').replace('Beta ', '').split('.')
                return tuple(int(p) for p in parts if p.isdigit())
            except:
                return (0, 0)
        
        current_tuple = parse_version(current_version)
        latest_tuple = parse_version(latest_version)
        
        update_available = latest_tuple > current_tuple
        
        return jsonify({
            'current_version': PEGAPROX_VERSION,
            'current_build': PEGAPROX_BUILD,
            'latest_version': remote_version.get('version'),
            'latest_build': remote_version.get('build'),
            'release_date': remote_version.get('release_date'),
            'changelog': remote_version.get('changelog', []),
            'download_url': remote_version.get('download_url', GITHUB_REPO_URL),
            'update_available': update_available,
            'min_python': remote_version.get('min_python', '3.8'),
            'breaking_changes': remote_version.get('breaking_changes', []),
        })
        
    except requests.exceptions.Timeout:
        logging.warning("Timeout checking for updates")
        return jsonify({
            'error': 'Timeout - GitHub not reachable',
            'current_version': PEGAPROX_VERSION,
            'current_build': PEGAPROX_BUILD,
            'update_available': False,
        }), 200
    except requests.exceptions.ConnectionError as e:
        logging.warning(f"Connection error checking updates: {e}")
        return jsonify({
            'error': 'Cannot connect to GitHub - check internet connection',
            'current_version': PEGAPROX_VERSION,
            'current_build': PEGAPROX_BUILD,
            'update_available': False,
        }), 200
    except requests.exceptions.RequestException as e:
        logging.warning(f"Request error checking updates: {e}")
        return jsonify({
            'error': f'Network error: {str(e)}',
            'current_version': PEGAPROX_VERSION,
            'current_build': PEGAPROX_BUILD,
            'update_available': False,
        }), 200
    except Exception as e:
        logging.error(f"Error checking updates: {e}")
        return jsonify({
            'error': str(e),
            'current_version': PEGAPROX_VERSION,
            'current_build': PEGAPROX_BUILD,
            'update_available': False,
        }), 200



@bp.route('/api/pegaprox/update', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def perform_pegaprox_update():
    """PegaProx auto-update from GitHub

    NS: Rewritten feb 2026 - archive-based (no manual releases needed)
    PRIMARY: downloads GitHub source archive, extracts, copies.
    FALLBACK: expands update_files globs via GitHub API, downloads individually.

    Protected paths (NEVER overwritten):
    - config/, ssl/, certs/   (settings, encrypted data)
    - *.db, *.enc             (databases, encrypted files)
    - *.pem, *.key, *.crt    (certificates, private keys)
    """
    try:
        data = request.json or {}
        force = data.get('force', False)

        # Protected paths - NEVER overwrite
        PROTECTED = [
            'config/', 'ssl/', 'certs/', 'logs/', 'backups/', 'venv/', '.git/',
            '.db', '.enc', '.pem', '.key', '.crt', '.p12'
        ]

        def is_protected(path):
            p = path.lower()
            for pat in PROTECTED:
                if pat.endswith('/'):
                    if p.startswith(pat) or f'/{pat}' in p:
                        return True
                else:
                    if p.endswith(pat):
                        return True
            return False

        # Check for updates (GitHub first, mirror fallback)
        response = None
        for version_url in [GITHUB_VERSION_URL, MIRROR_VERSION_URL]:
            try:
                response = requests.get(version_url, timeout=10)
                if response.status_code == 200:
                    break
            except requests.RequestException:
                continue

        if not response or response.status_code != 200:
            return jsonify({
                'error': 'Cannot reach update server (tried GitHub + mirror)',
                'hint': 'Check your internet connection or try again later'
            }), 503

        try:
            remote_version = response.json()
        except:
            return jsonify({'error': 'Invalid version data from server'}), 500

        new_version = remote_version.get('version', '0.0')

        # Version check
        if not force:
            current = PEGAPROX_VERSION.replace('Alpha ', '').replace('Beta ', '')
            def parse_ver(v):
                try:
                    parts = str(v).replace('Alpha ', '').replace('Beta ', '').split('.')
                    return tuple(int(p) for p in parts if p.isdigit())
                except:
                    return (0, 0)

            if parse_ver(current) >= parse_ver(new_version):
                return jsonify({
                    'success': False, 'message': 'Already up to date',
                    'current_version': PEGAPROX_VERSION, 'latest_version': new_version
                })

        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'pegaprox.update_started', f"Update to version {new_version} initiated")

        # NS: install dir = project root (3 levels up from pegaprox/api/settings.py)
        install_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        # Backup current state
        backup_base = os.path.join(CONFIG_DIR, 'backups')
        os.makedirs(backup_base, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = os.path.join(backup_base, f"pegaprox_{PEGAPROX_VERSION.replace(' ', '_')}_{timestamp}")
        os.makedirs(backup_path, exist_ok=True)

        # MK: backup the stuff that matters, not everything
        for item in ['pegaprox', 'web', 'static']:
            src = os.path.join(install_dir, item)
            if os.path.isdir(src):
                try:
                    shutil.copytree(src, os.path.join(backup_path, item),
                                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
                except Exception as e:
                    logging.warning(f"Backup {item}/: {e}")
        for f in ['pegaprox_multi_cluster.py', 'version.json', 'requirements.txt']:
            src = os.path.join(install_dir, f)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(backup_path, f))

        logging.info(f"Backup saved to {backup_path}")

        downloaded_files = []
        failed_files = []
        skipped_protected = []
        update_method = 'unknown'

        # ---- PRIMARY: Archive-based download ----
        # NS: Feb 2026 - GitHub first, mirror as fallback
        archive_urls = [
            remote_version.get('update_archive', GITHUB_ARCHIVE_URL),
            MIRROR_ARCHIVE_URL,
        ]

        try:
            import tarfile
            import tempfile

            resp = None
            for aurl in archive_urls:
                logging.info(f"Trying archive: {aurl}")
                try:
                    resp = requests.get(aurl, timeout=120, stream=True)
                    if resp.status_code == 200:
                        break
                except requests.RequestException:
                    continue

            if not resp or resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}")

            with tempfile.TemporaryDirectory() as tmpdir:
                archive_path = os.path.join(tmpdir, 'repo.tar.gz')
                with open(archive_path, 'wb') as f:
                    for chunk in resp.iter_content(8192):
                        f.write(chunk)

                # MK: extractall with filter='data' to block path traversal
                with tarfile.open(archive_path, 'r:gz') as tar:
                    tar.extractall(tmpdir, filter='data')

                # GitHub archives have a subdirectory (project-pegaprox-main/)
                content_dir = None
                for item in os.listdir(tmpdir):
                    check = os.path.join(tmpdir, item)
                    if os.path.isdir(check) and os.path.exists(os.path.join(check, 'pegaprox_multi_cluster.py')):
                        content_dir = check
                        break

                if not content_dir:
                    raise RuntimeError("Archive missing pegaprox_multi_cluster.py")

                # Walk archive and copy, skip protected paths + junk
                for root, dirs, files in os.walk(content_dir):
                    dirs[:] = [d for d in dirs if d not in ('__pycache__', '.git', 'venv', 'node_modules')]

                    rel_root = os.path.relpath(root, content_dir)
                    for fname in files:
                        if fname.endswith('.pyc'):
                            continue
                        rel_path = os.path.join(rel_root, fname) if rel_root != '.' else fname
                        rel_path = rel_path.replace('\\', '/')

                        if is_protected(rel_path):
                            skipped_protected.append(rel_path)
                            continue

                        dst = os.path.join(install_dir, rel_path)
                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                        shutil.copy2(os.path.join(root, fname), dst)
                        downloaded_files.append(rel_path)

            update_method = 'archive'
            logging.info(f"Archive update: {len(downloaded_files)} files installed")

        except Exception as archive_err:
            logging.warning(f"Archive download failed ({archive_err}), trying individual files...")

            # ---- FALLBACK: individual file download ----
            # NS: expand globs from update_files via GitHub Trees API
            REPO_BASE = GITHUB_RAW_URL
            file_list = []

            # try GitHub API to get full file tree
            try:
                api_url = f"{GITHUB_REPO_URL.replace('github.com', 'api.github.com/repos')}/git/trees/main?recursive=1"
                api_resp = requests.get(api_url, timeout=15)
                if api_resp.status_code == 200:
                    all_repo_files = [item['path'] for item in api_resp.json().get('tree', [])
                                      if item.get('type') == 'blob']
                else:
                    all_repo_files = None
            except:
                all_repo_files = None

            patterns = remote_version.get('update_files', [])

            if all_repo_files and patterns:
                # MK: expand glob patterns against actual repo file list
                import fnmatch
                for pat in patterns:
                    if '*' in pat or '?' in pat:
                        for f in all_repo_files:
                            if fnmatch.fnmatch(f, pat):
                                file_list.append(f)
                    else:
                        file_list.append(pat)
            elif all_repo_files:
                # no patterns? just grab everything
                file_list = all_repo_files
            elif patterns:
                # API failed, use patterns as literal filenames (old-style compat)
                file_list = [p for p in patterns if '*' not in p and '?' not in p]
            else:
                # absolute fallback - at least get the essentials
                file_list = [
                    'pegaprox_multi_cluster.py', 'version.json',
                    'requirements.txt', 'deploy.sh', 'update.sh',
                    'web/index.html', 'web/index.html.original',
                ]

            for remote_path in file_list:
                if is_protected(remote_path):
                    skipped_protected.append(remote_path)
                    continue
                if remote_path.endswith('.pyc') or '/__pycache__/' in remote_path:
                    continue

                dst = os.path.join(install_dir, remote_path)

                # try GitHub first, then mirror
                downloaded = False
                for base_url in [GITHUB_RAW_URL, MIRROR_RAW_URL]:
                    try:
                        resp = requests.get(f"{base_url}/{remote_path}", timeout=60)
                        if resp.status_code == 200:
                            os.makedirs(os.path.dirname(dst), exist_ok=True)
                            tmp = dst + '.new'
                            with open(tmp, 'wb') as f:
                                f.write(resp.content)
                            os.replace(tmp, dst)
                            downloaded_files.append(remote_path)
                            downloaded = True
                            break
                        elif resp.status_code == 404:
                            break  # file doesn't exist, skip
                    except:
                        continue

                if not downloaded and remote_path not in [f[0] for f in failed_files]:
                    # only log as failed if it wasn't a 404
                    pass

            update_method = 'individual'
            logging.info(f"Individual update: {len(downloaded_files)} files, {len(failed_files)} failed")

        # Make scripts executable
        for script in ['deploy.sh', 'update.sh', 'web/Dev/build.sh']:
            spath = os.path.join(install_dir, script)
            if os.path.exists(spath):
                try:
                    os.chmod(spath, 0o755)
                except:
                    pass

        # Install new Python packages
        pip_result = None
        requirements_path = os.path.join(install_dir, 'requirements.txt')
        if os.path.exists(requirements_path):
            try:
                logging.info("Installing Python packages...")

                # MK: try multiple pip methods - venv first, then system
                venv_pip = os.path.join(install_dir, 'venv', 'bin', 'pip')
                venv_pip_win = os.path.join(install_dir, 'venv', 'Scripts', 'pip.exe')

                is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
                has_sudo = shutil.which('sudo') is not None

                if os.path.exists(venv_pip):
                    result = subprocess.run(
                        [venv_pip, 'install', '-r', requirements_path, '--quiet'],
                        capture_output=True, text=True, timeout=120)
                    if result.returncode == 0:
                        pip_result = "success (venv)"

                elif os.path.exists(venv_pip_win):
                    result = subprocess.run(
                        [venv_pip_win, 'install', '-r', requirements_path, '--quiet'],
                        capture_output=True, text=True, timeout=120)
                    if result.returncode == 0:
                        pip_result = "success (venv)"

                if not pip_result:
                    system_pip = shutil.which('pip3') or shutil.which('pip')
                    if system_pip:
                        pip_args = [system_pip, 'install', '-r', requirements_path, '--quiet', '--break-system-packages']

                        if is_root:
                            result = subprocess.run(pip_args, capture_output=True, text=True, timeout=120)
                        elif has_sudo:
                            result = subprocess.run(
                                ['sudo', '-n'] + pip_args, capture_output=True, text=True, timeout=120)
                            if result.returncode != 0:
                                result = subprocess.run(
                                    [system_pip, 'install', '-r', requirements_path, '--user', '--quiet'],
                                    capture_output=True, text=True, timeout=120)
                        else:
                            result = subprocess.run(
                                [system_pip, 'install', '-r', requirements_path, '--user', '--quiet'],
                                capture_output=True, text=True, timeout=120)

                        pip_result = "success" if result.returncode == 0 else f"failed: {result.stderr[:100]}"
                    else:
                        pip_result = "skipped (pip not found)"

            except subprocess.TimeoutExpired:
                pip_result = "timeout"
            except Exception as e:
                pip_result = f"error: {str(e)}"

        log_audit(user, 'pegaprox.update_completed',
                  f"Updated to {new_version} via {update_method}, {len(downloaded_files)} files")

        # Schedule restart
        restart_delay = 3

        def restart_server():
            time.sleep(restart_delay)
            logging.info("Restarting PegaProx server...")

            is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
            has_sudo = shutil.which('sudo') is not None

            try:
                result = subprocess.run(['systemctl', 'is-active', 'pegaprox'],
                                       capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    if is_root:
                        subprocess.run(['systemctl', 'restart', 'pegaprox'], timeout=30)
                        return
                    elif has_sudo:
                        result = subprocess.run(
                            ['sudo', '-n', 'systemctl', 'restart', 'pegaprox'],
                            capture_output=True, text=True, timeout=30)
                        if result.returncode == 0:
                            return

                    # let systemd restart us
                    logging.info("Exiting for systemd restart (Restart=always)...")
                    os._exit(0)
            except:
                pass

            # Fallback: restart via Python
            try:
                os.execv(sys.executable, [sys.executable] + sys.argv)
            except:
                os._exit(0)

        threading.Thread(target=restart_server, daemon=True).start()

        return jsonify({
            'success': True,
            'message': f'Update to {new_version} complete! Restarting in {restart_delay}s...',
            'updated_version': new_version,
            'update_method': update_method,
            'backup_path': backup_path,
            'files_updated': downloaded_files,
            'files_failed': failed_files,
            'files_protected': skipped_protected,
            'pip_install': pip_result,
            'restarting': True,
            'restart_delay': restart_delay
        })

    except Exception as e:
        logging.error(f"Update error: {e}")
        return jsonify({'error': str(e)}), 500

@bp.route('/api/pegaprox/update/rollback', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def rollback_pegaprox_update():
    """Rollback to a previous PegaProx version from backup
    
    NS: Rollback functionality - Jan 2026
    """
    try:
        data = request.json or {}
        backup_name = data.get('backup')
        
        backup_dir = os.path.join(CONFIG_DIR, 'backups')
        
        if not backup_name:
            # List available backups
            backups = []
            if os.path.exists(backup_dir):
                for name in sorted(os.listdir(backup_dir), reverse=True):
                    backup_path = os.path.join(backup_dir, name)
                    if os.path.isdir(backup_path):
                        # Get backup info
                        files = os.listdir(backup_path)
                        backups.append({
                            'name': name,
                            'path': backup_path,
                            'files': files,
                            'created': datetime.fromtimestamp(os.path.getctime(backup_path)).isoformat()
                        })
            
            return jsonify({
                'backups': backups[:10],  # Last 10 backups
                'message': 'Select a backup to restore'
            })
        
        # Restore specific backup
        backup_path = os.path.join(backup_dir, backup_name)
        if not os.path.exists(backup_path):
            return jsonify({'error': 'Backup not found'}), 404
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        current_backend = os.path.abspath(__file__)
        current_frontend = os.path.join(current_dir, 'index.html')
        
        restored = []
        
        # Restore backend
        backup_backend = None
        for f in os.listdir(backup_path):
            if f.endswith('.py'):
                backup_backend = os.path.join(backup_path, f)
                break
        
        if backup_backend and os.path.exists(backup_backend):
            shutil.copy2(backup_backend, current_backend)
            restored.append('backend')
            logging.info(f"Restored backend from {backup_backend}")
        
        # Restore frontend
        backup_frontend = os.path.join(backup_path, 'index.html')
        if os.path.exists(backup_frontend):
            shutil.copy2(backup_frontend, current_frontend)
            restored.append('frontend')
            logging.info(f"Restored frontend from {backup_frontend}")
        
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'pegaprox.rollback', f"Rolled back to backup: {backup_name}")
        
        # Schedule restart
        def restart_server():
            time.sleep(3)
            is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
            has_sudo = shutil.which('sudo') is not None
            
            try:
                result = subprocess.run(['systemctl', 'is-active', 'pegaprox'], 
                                       capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    if is_root:
                        subprocess.run(['systemctl', 'restart', 'pegaprox'], timeout=30)
                        return
                    elif has_sudo:
                        result = subprocess.run(
                            ['sudo', '-n', 'systemctl', 'restart', 'pegaprox'],
                            capture_output=True, text=True, timeout=30
                        )
                        if result.returncode == 0:
                            return
                    # Fallback: exit for systemd restart
                    logging.info("Exiting for systemd restart...")
                    os._exit(0)
            except:
                pass
            try:
                os.execv(sys.executable, [sys.executable] + sys.argv)
            except:
                os._exit(0)
        
        import threading
        threading.Thread(target=restart_server, daemon=True).start()
        
        return jsonify({
            'success': True,
            'message': f'Rolled back to {backup_name}. Server restarting...',
            'restored': restored,
            'restarting': True
        })
        
    except Exception as e:
        logging.error(f"Rollback error: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/pegaprox/changelog', methods=['GET'])
@require_auth()
def get_pegaprox_changelog():
    """Get PegaProx changelog (GitHub + mirror fallback)"""
    try:
        for url in [GITHUB_VERSION_URL, MIRROR_VERSION_URL]:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    return jsonify({
                        'changelog': data.get('changelog', []),
                        'version': data.get('version'),
                        'release_date': data.get('release_date'),
                    })
            except:
                continue
        return jsonify({'error': 'Failed to fetch changelog'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Serve static files (JS, CSS, fonts for offline mode)
STATIC_DIR = 'static'
Path(STATIC_DIR).mkdir(exist_ok=True)
Path(os.path.join(STATIC_DIR, 'js')).mkdir(exist_ok=True)
Path(os.path.join(STATIC_DIR, 'css')).mkdir(exist_ok=True)

@bp.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files (JS, CSS, logo, etc.) for offline operation
    NS: Returns 404 with matching content-type to avoid MIME errors in browser
    """
    # Determine MIME type based on extension
    mime_types = {
        '.js': 'application/javascript',
        '.mjs': 'application/javascript',
        '.css': 'text/css',
        '.woff2': 'font/woff2',
        '.woff': 'font/woff',
        '.ttf': 'font/ttf',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.svg': 'image/svg+xml',
        '.ico': 'image/x-icon',
        '.json': 'application/json',
        '.map': 'application/json'
    }
    ext = os.path.splitext(filename)[1].lower()
    mimetype = mime_types.get(ext, 'application/octet-stream')
    
    # Check if file exists
    filepath = os.path.join(STATIC_DIR, filename)
    if not os.path.isfile(filepath):
        # Return 404 with correct MIME type - prevents "not executable" errors
        return Response('', status=404, mimetype=mimetype)
    
    return send_from_directory(STATIC_DIR, filename, mimetype=mimetype)

# SECURITY: Block access to config directory
@bp.route('/config/<path:filename>')
def block_config_access(filename):
    """Block any attempt to access config files via HTTP"""
    logging.warning(f"Blocked attempt to access config file: {filename} from {request.remote_addr}")
    return jsonify({'error': 'Access denied'}), 403

@bp.route('/config')
def block_config_dir():
    """Block any attempt to access config directory"""
    logging.warning(f"Blocked attempt to list config directory from {request.remote_addr}")
    return jsonify({'error': 'Access denied'}), 403

# Serve images (logos, sponsors, etc.)
IMAGES_DIR = 'images'
Path(IMAGES_DIR).mkdir(exist_ok=True)

@bp.route('/favicon.ico')
def serve_favicon():
    """serve favicon from images or static folder"""
    # try images first, then static
    for folder in [IMAGES_DIR, STATIC_DIR]:
        favicon_path = os.path.join(folder, 'favicon.ico')
        if os.path.exists(favicon_path):
            return send_from_directory(folder, 'favicon.ico', mimetype='image/x-icon')
    # return empty response if no favicon (prevents 404 spam in logs)
    return '', 204

@bp.route('/images/<path:filename>')
def serve_images(filename):
    """Serve image files (pegaprox logo, sponsor logos, etc.)"""
    return send_from_directory(IMAGES_DIR, filename)

@bp.route('/api/settings/server', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def get_server_settings():
    """Get server settings (admin only)"""
    settings = load_server_settings()
    # Add info about existing cert/key files
    settings['ssl_cert_exists'] = os.path.exists(SSL_CERT_FILE)
    settings['ssl_key_exists'] = os.path.exists(SSL_KEY_FILE)
    # Don't return actual cert/key content or sensitive passwords
    # Mask SMTP password if set
    if settings.get('smtp_password'):
        settings['smtp_password'] = '********'
    # MK: Mask LDAP bind password - frontend doesn't need the encrypted value
    if settings.get('ldap_bind_password'):
        settings['ldap_bind_password'] = '********'
    # NS: Mask OIDC client secret
    if settings.get('oidc_client_secret'):
        settings['oidc_client_secret'] = '********'
    return jsonify(settings)


@bp.route('/api/password-policy', methods=['GET'])
def get_password_policy():
    """Get password policy settings (public - needed for password change forms)
    
    NS: Jan 2026 - Returns only password-related settings, no auth required
    """
    settings = load_server_settings()
    return jsonify({
        'min_length': settings.get('password_min_length', 8),
        'require_uppercase': settings.get('password_require_uppercase', True),
        'require_lowercase': settings.get('password_require_lowercase', True),
        'require_numbers': settings.get('password_require_numbers', True),
        'require_special': settings.get('password_require_special', False),
        'expiry_days': settings.get('password_expiry_days', 0)
    })

@bp.route('/api/settings/server', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def update_server_settings():
    """Update server settings (admin only)
    
    NS: Fixed Dec 2025 - now accepts both JSON and form-data
    """
    try:
        settings = load_server_settings()
        restart_required = False
        
        # check if JSON or form-data
        if request.is_json:
            data = request.get_json() or {}
            
            # server config
            if 'domain' in data:
                # MK: Auto-strip port from domain if present (user might accidentally include it)
                domain_value = data['domain'].strip()
                if domain_value and ':' in domain_value and not domain_value.startswith('['):
                    domain_value = domain_value.rsplit(':', 1)[0]
                settings['domain'] = domain_value
            if 'port' in data:
                new_port = int(data['port'])
                if settings.get('port') != new_port:
                    restart_required = True
                settings['port'] = new_port
            if 'http_redirect_port' in data:
                new_http_port = int(data['http_redirect_port'])
                if settings.get('http_redirect_port') != new_http_port:
                    restart_required = True
                settings['http_redirect_port'] = new_http_port
            if 'ssl_enabled' in data:
                new_ssl = bool(data['ssl_enabled'])
                if settings.get('ssl_enabled') != new_ssl:
                    restart_required = True
                settings['ssl_enabled'] = new_ssl
            
            # security/bruteforce settings
            if 'login_max_attempts' in data:
                settings['login_max_attempts'] = max(1, min(50, int(data['login_max_attempts'])))
            if 'login_lockout_time' in data:
                settings['login_lockout_time'] = max(30, min(86400, int(data['login_lockout_time'])))
            if 'login_attempt_window' in data:
                settings['login_attempt_window'] = max(60, min(3600, int(data['login_attempt_window'])))
            
            # password policy
            if 'password_min_length' in data:
                settings['password_min_length'] = max(4, min(64, int(data['password_min_length'])))
            if 'password_require_uppercase' in data:
                settings['password_require_uppercase'] = bool(data['password_require_uppercase'])
            if 'password_require_lowercase' in data:
                settings['password_require_lowercase'] = bool(data['password_require_lowercase'])
            if 'password_require_numbers' in data:
                settings['password_require_numbers'] = bool(data['password_require_numbers'])
            if 'password_require_special' in data:
                settings['password_require_special'] = bool(data['password_require_special'])
            
            # LW: password expiry settings - Dec 2025
            if 'password_expiry_enabled' in data:
                old_val = settings.get('password_expiry_enabled')
                settings['password_expiry_enabled'] = bool(data['password_expiry_enabled'])
                if old_val != settings['password_expiry_enabled']:
                    log_audit(request.session.get('user', 'admin'), 'settings.password_expiry', 
                              f"Password expiry {'enabled' if settings['password_expiry_enabled'] else 'disabled'}")
            if 'password_expiry_days' in data:
                settings['password_expiry_days'] = max(7, min(365, int(data['password_expiry_days'])))
            if 'password_expiry_warning_days' in data:
                settings['password_expiry_warning_days'] = max(1, min(30, int(data['password_expiry_warning_days'])))
            if 'password_expiry_email_enabled' in data:
                settings['password_expiry_email_enabled'] = bool(data['password_expiry_email_enabled'])
            if 'password_expiry_include_admins' in data:
                old_val = settings.get('password_expiry_include_admins')
                settings['password_expiry_include_admins'] = bool(data['password_expiry_include_admins'])
                if old_val != settings['password_expiry_include_admins']:
                    log_audit(request.session.get('user', 'admin'), 'settings.password_expiry', 
                              f"Admin password expiry {'enabled' if settings['password_expiry_include_admins'] else 'disabled'}")
            
            # NS: Feb 2026 - Force 2FA for all users
            if 'force_2fa' in data:
                old_val = settings.get('force_2fa')
                settings['force_2fa'] = bool(data['force_2fa'])
                if old_val != settings['force_2fa']:
                    log_audit(request.session.get('user', 'admin'), 'settings.force_2fa',
                              f"Force 2FA {'enabled' if settings['force_2fa'] else 'disabled'}")
            if 'force_2fa_exclude_admins' in data:
                settings['force_2fa_exclude_admins'] = bool(data['force_2fa_exclude_admins'])
            
            # session settings
            if 'session_timeout' in data:
                settings['session_timeout'] = max(300, min(604800, int(data['session_timeout'])))
            
            # NS: SMTP Settings - Jan 2026
            if 'smtp_enabled' in data:
                settings['smtp_enabled'] = bool(data['smtp_enabled'])
                logging.info(f"[Settings] Setting smtp_enabled = {settings['smtp_enabled']}")
            if 'smtp_host' in data:
                settings['smtp_host'] = str(data['smtp_host']).strip()
                logging.info(f"[Settings] Setting smtp_host = {settings['smtp_host']}")
            if 'smtp_port' in data:
                settings['smtp_port'] = max(1, min(65535, int(data['smtp_port'] or 587)))
                logging.info(f"[Settings] Setting smtp_port = {settings['smtp_port']}")
            if 'smtp_user' in data:
                settings['smtp_user'] = str(data['smtp_user'] or '').strip()
            if 'smtp_password' in data:
                # Only update if not empty (don't overwrite with empty string)
                pwd = str(data['smtp_password'] or '')
                if pwd and pwd != '********':  # Don't save masked password
                    settings['smtp_password'] = get_db()._encrypt(pwd)  # NS: Feb 2026 - SECURITY: encrypt like LDAP/OIDC
                    logging.info("[Settings] SMTP password updated (encrypted)")
            if 'smtp_from_email' in data:
                settings['smtp_from_email'] = str(data['smtp_from_email'] or '').strip()
                logging.info(f"[Settings] Setting smtp_from_email = {settings['smtp_from_email']}")
            if 'smtp_from_name' in data:
                settings['smtp_from_name'] = str(data['smtp_from_name'] or '').strip()
            if 'smtp_tls' in data:
                settings['smtp_tls'] = bool(data['smtp_tls'])
            if 'smtp_ssl' in data:
                settings['smtp_ssl'] = bool(data['smtp_ssl'])
            
            # NS: Alert settings
            if 'alert_email_recipients' in data:
                recipients = data['alert_email_recipients']
                if isinstance(recipients, str):
                    # Parse comma-separated string
                    recipients = [r.strip() for r in recipients.split(',') if r.strip()]
                settings['alert_email_recipients'] = recipients
            if 'alert_cooldown' in data:
                settings['alert_cooldown'] = max(60, min(86400, int(data['alert_cooldown'])))
            
            # NS: Default theme for new users - Jan 2026
            if 'default_theme' in data:
                allowed_themes = [
                    'proxmoxDark', 'proxmoxLight', 'midnight', 'forest', 'rose', 'ocean',
                    'highContrast', 'dracula', 'nord', 'monokai', 'matrix', 'sunset',
                    'cyberpunk', 'github', 'solarizedDark', 'gruvbox',
                    'corporateDark', 'corporateLight', 'enterpriseBlue'  # NS: Corporate themes
                ]
                if data['default_theme'] in allowed_themes:
                    settings['default_theme'] = data['default_theme']
            
            # LW: Feb 2026 - LDAP/Active Directory settings
            ldap_keys = {
                'ldap_enabled': lambda v: bool(v),
                'ldap_server': lambda v: str(v or '').strip(),
                'ldap_port': lambda v: max(1, min(65535, int(v or 389))),
                'ldap_use_ssl': lambda v: bool(v),
                'ldap_use_starttls': lambda v: bool(v),
                'ldap_bind_dn': lambda v: str(v or '').strip(),
                'ldap_base_dn': lambda v: str(v or '').strip(),
                'ldap_user_filter': lambda v: str(v or '(&(objectClass=person)(sAMAccountName={username}))').strip(),
                'ldap_username_attribute': lambda v: str(v or 'sAMAccountName').strip(),
                'ldap_email_attribute': lambda v: str(v or 'mail').strip(),
                'ldap_display_name_attribute': lambda v: str(v or 'displayName').strip(),
                'ldap_group_base_dn': lambda v: str(v or '').strip(),
                'ldap_group_filter': lambda v: str(v or '(&(objectClass=group)(member={user_dn}))').strip(),
                'ldap_admin_group': lambda v: str(v or '').strip(),
                'ldap_user_group': lambda v: str(v or '').strip(),
                'ldap_viewer_group': lambda v: str(v or '').strip(),
                'ldap_default_role': lambda v: str(v).strip() if v else 'viewer',  # NS: Accept custom roles too
                'ldap_auto_create_users': lambda v: bool(v),
            }
            
            # NS: Feb 2026 - Log incoming LDAP data for debugging save issues
            if any(k in data for k in ldap_keys):
                logging.info(f"[LDAP] Incoming save data: server='{data.get('ldap_server', '<missing>')}', "
                           f"base_dn='{data.get('ldap_base_dn', '<missing>')}', "
                           f"enabled={data.get('ldap_enabled', '<missing>')}, "
                           f"bind_dn='{data.get('ldap_bind_dn', '<missing>')}'")
            
            for key, transform in ldap_keys.items():
                if key in data:
                    settings[key] = transform(data[key])
            
            # Handle ldap_bind_password separately (not in the loop to avoid lambda issues)
            if 'ldap_bind_password' in data:
                pwd = str(data['ldap_bind_password'] or '')
                if pwd and pwd != '********':
                    settings['ldap_bind_password'] = get_db()._encrypt(pwd)  # NS: Encrypt bind credential
            
            # LW: Custom group→role mappings (JSON array)
            # NS: Feb 2026 - Simplified: just group_dn + role (including custom roles)
            # tenant/tenant_role kept for backwards compat but no longer in UI
            if 'ldap_group_mappings' in data:
                mappings = data['ldap_group_mappings']
                if isinstance(mappings, list):
                    # Validate each mapping
                    clean_mappings = []
                    for m in mappings:
                        if isinstance(m, dict) and m.get('group_dn'):
                            clean_mappings.append({
                                'group_dn': str(m.get('group_dn', '')).strip(),
                                'role': str(m.get('role', 'viewer')).strip(),
                            })
                    settings['ldap_group_mappings'] = clean_mappings
                    # NS: Feb 2026 - Clear old built-in group fields when unified mappings are saved
                    # Prevents priority conflicts (built-in checked before custom in auth)
                    if clean_mappings:
                        settings['ldap_admin_group'] = ''
                        settings['ldap_user_group'] = ''
                        settings['ldap_viewer_group'] = ''
            
            if any(k in data for k in ldap_keys):
                log_audit(request.session.get('user', 'admin'), 'settings.ldap', 
                         f"LDAP settings updated (enabled={settings.get('ldap_enabled', False)})")
                # NS: Feb 2026 - Debug: confirm what was actually saved
                logging.info(f"[LDAP] Settings saved: enabled={settings.get('ldap_enabled')}, "
                           f"server='{settings.get('ldap_server', '')}', "
                           f"base_dn='{settings.get('ldap_base_dn', '')}', "
                           f"bind_dn='{settings.get('ldap_bind_dn', '')}', "
                           f"password_set={bool(settings.get('ldap_bind_password'))}")
                
                # NS: Feb 2026 - Verify DB actually persisted the value (catches write failures)
                try:
                    verify = load_server_settings()
                    v_server = verify.get('ldap_server', '')
                    v_base = verify.get('ldap_base_dn', '')
                    if settings.get('ldap_base_dn') and not v_base:
                        logging.error(f"[LDAP] DB WRITE VERIFICATION FAILED! Saved base_dn='{settings.get('ldap_base_dn')}' but read back '{v_base}'")
                    elif settings.get('ldap_server') and not v_server:
                        logging.error(f"[LDAP] DB WRITE VERIFICATION FAILED! Saved server='{settings.get('ldap_server')}' but read back '{v_server}'")
                except Exception as ve:
                    logging.warning(f"[LDAP] DB verification failed: {ve}")
            
            # NS: Feb 2026 - OIDC / Entra ID settings
            oidc_keys = {
                'oidc_enabled': lambda v: bool(v),
                'oidc_provider': lambda v: str(v) if v in ('entra', 'okta', 'generic') else 'entra',
                'oidc_cloud_environment': lambda v: str(v) if v in ('commercial', 'gcc', 'gcc_high', 'dod') else 'commercial',  # NS: GCC High/DoD
                'oidc_client_id': lambda v: str(v).strip(),
                'oidc_tenant_id': lambda v: str(v).strip(),
                'oidc_authority': lambda v: str(v).strip(),
                'oidc_scopes': lambda v: str(v).strip() or ('openid profile email User.Read GroupMember.Read.All' if settings.get('oidc_provider') == 'entra' else 'openid profile email'),
                'oidc_redirect_uri': lambda v: str(v).strip(),
                'oidc_admin_group_id': lambda v: str(v).strip(),
                'oidc_user_group_id': lambda v: str(v).strip(),
                'oidc_viewer_group_id': lambda v: str(v).strip(),
                'oidc_default_role': lambda v: str(v).strip() if v else ROLE_VIEWER,  # NS: Accept custom roles too
                'oidc_auto_create_users': lambda v: bool(v),
                'oidc_button_text': lambda v: str(v).strip() or 'Sign in with Microsoft',
            }
            
            for key, transform in oidc_keys.items():
                if key in data:
                    settings[key] = transform(data[key])
            
            # MK: Encrypt OIDC client secret
            if 'oidc_client_secret' in data:
                secret = str(data['oidc_client_secret'] or '')
                if secret and secret != '********':
                    settings['oidc_client_secret'] = get_db()._encrypt(secret)
            
            # LW: OIDC custom group mappings
            # NS: Feb 2026 - Simplified: just group_id + role (including custom roles)
            if 'oidc_group_mappings' in data:
                mappings = data['oidc_group_mappings']
                if isinstance(mappings, list):
                    clean = []
                    for m in mappings:
                        if isinstance(m, dict) and (m.get('group_id') or m.get('group_dn')):
                            clean.append({
                                'group_id': str(m.get('group_id') or m.get('group_dn', '')).strip(),
                                'role': str(m.get('role', 'viewer')).strip(),
                            })
                    settings['oidc_group_mappings'] = clean
                    # NS: Feb 2026 - Clear old built-in group fields when unified mappings are saved
                    if clean:
                        settings['oidc_admin_group_id'] = ''
                        settings['oidc_user_group_id'] = ''
                        settings['oidc_viewer_group_id'] = ''
            
            if any(k in data for k in oidc_keys):
                log_audit(request.session.get('user', 'admin'), 'settings.oidc', 
                         f"OIDC settings updated (enabled={settings.get('oidc_enabled', False)}, provider={settings.get('oidc_provider', 'entra')})")
            
        else:
            # form-data (for file uploads)
            domain = request.form.get('domain', '')
            port = request.form.get('port', '5000')
            http_redirect_port = request.form.get('http_redirect_port', '0')
            ssl_enabled = request.form.get('ssl_enabled', 'false').lower() == 'true'
            default_theme = request.form.get('default_theme', 'proxmoxDark')
            
            if settings.get('port') != int(port):
                restart_required = True
            if settings.get('http_redirect_port') != int(http_redirect_port):
                restart_required = True
            if settings.get('ssl_enabled') != ssl_enabled:
                restart_required = True
            
            settings['domain'] = domain
            settings['port'] = int(port)
            settings['http_redirect_port'] = int(http_redirect_port)
            settings['ssl_enabled'] = ssl_enabled
            
            # NS: Default theme for new users - Jan 2026
            allowed_themes = [
                'proxmoxDark', 'proxmoxLight', 'midnight', 'forest', 'rose', 'ocean',
                'highContrast', 'dracula', 'nord', 'monokai', 'matrix', 'sunset',
                'cyberpunk', 'github', 'solarizedDark', 'gruvbox',
                'corporateDark', 'corporateLight', 'enterpriseBlue'  # NS: Corporate themes
            ]
            if default_theme in allowed_themes:
                settings['default_theme'] = default_theme
            
            # Handle certificate upload
            if 'ssl_cert' in request.files:
                cert_file = request.files['ssl_cert']
                if cert_file.filename:
                    cert_content = cert_file.read()
                    if b'-----BEGIN CERTIFICATE-----' in cert_content or b'-----BEGIN' in cert_content:
                        with open(SSL_CERT_FILE, 'wb') as f:
                            f.write(cert_content)
                        os.chmod(SSL_CERT_FILE, 0o600)
                        restart_required = True
                    else:
                        return jsonify({'error': 'Invalid certificate format'}), 400
            
            # Handle key upload
            if 'ssl_key' in request.files:
                key_file = request.files['ssl_key']
                if key_file.filename:
                    key_content = key_file.read()
                    if b'-----BEGIN' in key_content and b'KEY-----' in key_content:
                        with open(SSL_KEY_FILE, 'wb') as f:
                            f.write(key_content)
                        os.chmod(SSL_KEY_FILE, 0o600)
                        restart_required = True
                    else:
                        return jsonify({'error': 'Invalid key format'}), 400
        
        # save
        logging.info(f"[Settings] Saving settings. SMTP enabled={settings.get('smtp_enabled')}, host={settings.get('smtp_host')}")
        if save_server_settings(settings):
            logging.info("[Settings] Settings saved successfully")
            usr = getattr(request, 'session', {}).get('user', 'system')
            log_audit(usr, 'settings.server_updated', f"Settings updated (restart_required={restart_required})")
            
            # NS: Feb 2026 - Warn if LDAP enabled but critical fields missing
            warnings = []
            if settings.get('ldap_enabled'):
                if not settings.get('ldap_server'):
                    warnings.append('LDAP server is empty')
                if not settings.get('ldap_base_dn'):
                    warnings.append('LDAP base DN is empty - LDAP login will not work')
                if not settings.get('ldap_bind_dn'):
                    warnings.append('LDAP bind DN is empty - user search may fail')
            
            return jsonify({
                'success': True,
                'restart_required': restart_required,
                'message': 'Settings saved',
                'warnings': warnings if warnings else None
            })
        else:
            logging.error("[Settings] Failed to save settings")
            return jsonify({'error': 'Failed to save settings'}), 500
            
    except Exception as e:
        logging.error(f"Error updating server settings: {e}")
        return jsonify({'error': str(e)}), 500

@bp.route('/api/settings/server/restart', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def restart_server():
    """Restart the PegaProx server (admin only)"""
    try:
        # Audit log
        user = getattr(request, 'session', {}).get('user', 'system')
        log_audit(user, 'settings.server_restart', 'Server restart initiated')
        
        # Send response before restarting
        response = jsonify({'success': True, 'message': 'Server restart initiated'})
        
        # Schedule restart in a separate thread
        def do_restart():
            time.sleep(1)  # Give time for response to be sent
            logging.info("Server restart initiated by admin")
            
            is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
            has_sudo = shutil.which('sudo') is not None
            
            try:
                result = subprocess.run(['systemctl', 'is-active', 'pegaprox'],
                                       capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    if is_root:
                        subprocess.run(['systemctl', 'restart', 'pegaprox'], 
                                      capture_output=True, timeout=30)
                        return
                    elif has_sudo:
                        result = subprocess.run(
                            ['sudo', '-n', 'systemctl', 'restart', 'pegaprox'],
                            capture_output=True, text=True, timeout=30
                        )
                        if result.returncode == 0:
                            return
            except Exception:
                pass
            
            # Fallback: exit and let systemd restart
            logging.info("Exiting for systemd restart...")
            os._exit(0)
        
        restart_thread = threading.Thread(target=do_restart)
        restart_thread.daemon = True
        restart_thread.start()
        
        return response
        
    except Exception as e:
        logging.error(f"Error restarting server: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================
# Config Backup/Restore API Routes
# NS: Jan 2026 - encrypted backups finally
# MK: AES-256-GCM with PBKDF2 key derivation
# ============================================

@bp.route('/api/config/backup', methods=['POST'])

@require_auth(roles=[ROLE_ADMIN])
def backup_config():
    """Export full PegaProx configuration as encrypted backup (admin only)
    
    SECURITY: Requires user password confirmation and backup encryption password.
    MK: Double password = prevents stolen sessions from exporting data
    
    Body:
    - user_password: Current user's password for confirmation
    - backup_password: Password to encrypt the backup file (min 8 chars)
    - include_secrets: Include encrypted passwords/keys (default: false)
    - include_users: Include user accounts (default: true)
    - include_audit: Include audit log (default: false)
    """
    try:
        logging.info("[Backup] Starting config backup...")
        data = request.json or {}
        
        # 1. Verify user password first
        # NS: prevents session hijacking from exporting everything
        user_password = data.get('user_password', '')
        if not user_password:
            logging.warning("[Backup] No user password provided")
            return jsonify({'error': 'User password required for security verification'}), 400
        
        username = getattr(request, 'session', {}).get('user')
        logging.info(f"[Backup] User from session: {username}")
        if not username:
            logging.warning("[Backup] No user in session")
            return jsonify({'error': 'Not authenticated'}), 401
        
        users = load_users()
        
        # LW: these type checks saved us hours of debugging
        logging.debug(f"[Backup] Users type: {type(users)}, count: {len(users) if isinstance(users, dict) else 'N/A'}")
        
        if not isinstance(users, dict):
            logging.error(f"[Backup] Users is not a dict: {type(users)}")
            return jsonify({'error': 'User database error'}), 500
        
        user = users.get(username)
        
        logging.debug(f"[Backup] User data type: {type(user)}")
        
        if not user:
            logging.warning(f"[Backup] User {username} not found in database")
            return jsonify({'error': 'User not found'}), 404
        
        # MK: happened once after a botched migration, better safe than sorry
        if isinstance(user, str):
            logging.error(f"[Backup] User data is string, not dict")
            return jsonify({'error': 'User data format error - please re-login'}), 500
        
        # Verify password
        password_salt = user.get('password_salt', '') if isinstance(user, dict) else ''
        password_hash = user.get('password_hash', '') if isinstance(user, dict) else ''
        
        if not verify_password(user_password, password_salt, password_hash):
            log_audit(username, 'config.backup_failed', 'Password verification failed')
            logging.warning(f"[Backup] Password verification failed for {username}")
            return jsonify({'error': 'Incorrect password'}), 401
        
        logging.debug(f"[Backup] Password verified for {username}")
        
        # 2. Validate backup password
        backup_password = data.get('backup_password', '')
        if not backup_password or len(backup_password) < 8:
            logging.warning("[Backup] Backup password too short")
            return jsonify({'error': 'Backup password must be at least 8 characters'}), 400
        
        include_secrets = data.get('include_secrets', False)
        include_users = data.get('include_users', True)
        include_audit = data.get('include_audit', False)
        
        database = get_db()
        
        backup_data = {
            'version': PEGAPROX_VERSION,
            'build': PEGAPROX_BUILD,
            'export_date': datetime.now().isoformat(),
            'exported_by': username,
            'encrypted': True,  # Mark as encrypted backup
        }
        
        # Server settings
        backup_data['server_settings'] = load_server_settings()
        # Remove sensitive data if not requested
        if not include_secrets:
            if 'smtp_password' in backup_data['server_settings']:
                backup_data['server_settings']['smtp_password'] = ''
        
        # Clusters
        clusters = database.get_all_clusters()
        if not include_secrets:
            # Remove passwords and keys - clusters is a dict: {'id': {data}}
            for cluster_id, cluster_data in clusters.items():
                if isinstance(cluster_data, dict):
                    cluster_data.pop('password_encrypted', None)
                    cluster_data.pop('password', None)
                    cluster_data.pop('pass', None)
                    cluster_data.pop('ssh_key_encrypted', None)
                    cluster_data.pop('ssh_key', None)
                    cluster_data.pop('api_token_encrypted', None)
                    cluster_data.pop('api_token', None)
        backup_data['clusters'] = clusters
        
        # Users (optional)
        if include_users:
            users_data = database.get_all_users()
            if not include_secrets:
                # users_data is a dict: {'username': {data}}
                for username, user_data in users_data.items():
                    if isinstance(user_data, dict):
                        user_data.pop('password_hash', None)
                        user_data.pop('password_salt', None)
                        user_data.pop('totp_secret', None)
                        user_data.pop('totp_secret_encrypted', None)
            backup_data['users'] = users_data
        
        # Tenants
        backup_data['tenants'] = database.get_all_tenants()
        
        # VM ACLs
        backup_data['vm_acls'] = database.get_all_vm_acls()
        
        # Affinity Rules
        backup_data['affinity_rules'] = database.get_affinity_rules()
        
        # Cluster Groups
        try:
            cursor = database.conn.cursor()
            cursor.execute('SELECT * FROM cluster_groups')
            backup_data['cluster_groups'] = [dict(row) for row in cursor.fetchall()]
        except:
            backup_data['cluster_groups'] = []
        
        # Custom Scripts
        try:
            cursor = database.conn.cursor()
            cursor.execute('SELECT * FROM custom_scripts WHERE deleted_at IS NULL')
            scripts = [dict(row) for row in cursor.fetchall()]
            # Don't include output in backup
            for script in scripts:
                script.pop('last_output', None)
            backup_data['custom_scripts'] = scripts
        except:
            backup_data['custom_scripts'] = []
        
        # Audit Log (optional, can be large)
        if include_audit:
            backup_data['audit_log'] = database.get_audit_log(limit=10000)
        
        logging.debug(f"[Backup] Encrypting backup data...")
        # 3. Encrypt the backup with AES-256-GCM
        encrypted_backup = _encrypt_backup(json.dumps(backup_data, default=str), backup_password)
        logging.debug(f"[Backup] Encryption complete, size: {len(encrypted_backup)} bytes")
        
        # Log the backup action
        log_audit(username, 'config.backup', f"Configuration exported (secrets={'included' if include_secrets else 'excluded'}, encrypted=True)")
        
        # Return as downloadable encrypted file
        response = make_response(encrypted_backup)
        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers['Content-Disposition'] = f'attachment; filename=pegaprox-backup-{datetime.now().strftime("%Y%m%d-%H%M%S")}.pegabackup'
        
        logging.debug(f"[Backup] Sending response with {len(encrypted_backup)} bytes")
        return response
        
    except Exception as e:
        logging.error(f"Config backup failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

def _encrypt_backup(data: str, password: str) -> bytes:
    """Encrypt backup data with password using AES-256-GCM
    
    Uses PBKDF2 to derive key from password.
    Format: salt (16 bytes) + nonce (12 bytes) + ciphertext
    
    MK: Same format as our cluster password encryption
    """
    import hashlib
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    # Generate random salt
    salt = os.urandom(16)
    
    # Derive key from password using PBKDF2
    # MK: 100k iterations is OWASP minimum, good enough for backups
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000,  # OWASP recommended minimum
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    
    # Encrypt with AES-256-GCM
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # NS: 12 bytes is standard for GCM
    ciphertext = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
    
    # Combine: salt + nonce + ciphertext
    return salt + nonce + ciphertext

def _decrypt_backup(encrypted_data: bytes, password: str) -> str:
    """Decrypt backup data with password
    
    Returns decrypted JSON string or raises exception on failure.
    NS: Wrong password will throw InvalidTag exception
    """
    import hashlib
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    logging.debug(f"[Decrypt] Input data size: {len(encrypted_data)} bytes")
    
    if len(encrypted_data) < 28:  # salt (16) + nonce (12)
        logging.error(f"[Decrypt] Data too short: {len(encrypted_data)} bytes (need at least 28)")
        raise ValueError("Invalid backup file format - file too short")
    
    # Extract components - format is: salt + nonce + ciphertext
    # MK: same format as our cluster password encryption
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:]
    
    logging.debug(f"[Decrypt] Salt: {len(salt)} bytes, Nonce: {len(nonce)} bytes, Ciphertext: {len(ciphertext)} bytes")
    
    # Derive key from password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    
    # Decrypt with AES-256-GCM
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        logging.debug(f"[Decrypt] Decryption successful, plaintext size: {len(plaintext)} bytes")
        return plaintext.decode('utf-8')
    except Exception as e:
        # NS: InvalidTag means wrong password, dont log the actual error (security)
        logging.error(f"[Decrypt] Decryption failed")
        raise ValueError("Incorrect backup password or corrupted file")

@bp.route('/api/config/restore', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def restore_config():
    """Import PegaProx configuration from encrypted backup (admin only)
    
    SECURITY: Requires user password confirmation and backup decryption password.
    NS: merge mode is default because overwrite is scary
    
    Accepts multipart form with:
    - user_password: Current user's password for confirmation
    - backup_password: Password to decrypt the backup file
    - backup_file: The encrypted .pegabackup file
    - mode: 'merge' (default) or 'overwrite'
    - restore_users: Restore user accounts (default: false for safety)
    - dry_run: Validate only, don't apply (default: false)
    """
    try:
        logging.info("[Restore] Starting config restore...")
        # NS: these help when debugging upload issues
        logging.debug(f"[Restore] Content-Type: {request.content_type}")
        logging.debug(f"[Restore] Form keys: {list(request.form.keys())}")
        logging.debug(f"[Restore] Files keys: {list(request.files.keys())}")
        
        # Get form data
        user_password = request.form.get('user_password', '')
        backup_password = request.form.get('backup_password', '')
        mode = request.form.get('mode', 'merge')
        restore_users_str = request.form.get('restore_users', 'false')
        dry_run_str = request.form.get('dry_run', 'false')
        
        # LW: form data comes as strings, need to convert
        restore_users = str(restore_users_str).lower() in ('true', '1', 'yes')
        dry_run = str(dry_run_str).lower() in ('true', '1', 'yes')
        
        logging.info(f"[Restore] Mode: {mode}, dry_run: {dry_run}, restore_users: {restore_users}")
        
        # 1. Verify user password first
        if not user_password:
            logging.warning("[Restore] No user password provided")
            return jsonify({'error': 'User password required for security verification'}), 400
        
        username = getattr(request, 'session', {}).get('user')
        logging.debug(f"[Restore] User from session: {username}")
        if not username:
            return jsonify({'error': 'Not authenticated'}), 401
        
        users = load_users()
        
        # NS: copy-paste from backup_config, same validation
        logging.debug(f"[Restore] Users type: {type(users)}, count: {len(users) if isinstance(users, dict) else 'N/A'}")
        
        if not isinstance(users, dict):
            logging.error(f"[Restore] Users is not a dict: {type(users)}")
            return jsonify({'error': 'User database error'}), 500
        
        user = users.get(username)
        
        logging.debug(f"[Restore] User data type: {type(user)}")
        if user:
            logging.debug(f"[Restore] User keys: {user.keys() if isinstance(user, dict) else 'NOT A DICT'}")
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # same legacy check as backup
        if isinstance(user, str):
            logging.error(f"[Restore] User data is string, not dict: {user[:50]}...")
            return jsonify({'error': 'User data format error - please re-login'}), 500
        
        # Verify password
        password_salt = user.get('password_salt', '') if isinstance(user, dict) else ''
        password_hash = user.get('password_hash', '') if isinstance(user, dict) else ''
        
        if not verify_password(user_password, password_salt, password_hash):
            log_audit(username, 'config.restore_failed', 'Password verification failed')
            logging.warning(f"[Restore] Password verification failed for {username}")
            return jsonify({'error': 'Incorrect password'}), 401
        
        logging.debug(f"[Restore] Password verified for {username}")
        
        # 2. Validate backup password
        if not backup_password:
            return jsonify({'error': 'Backup password required to decrypt file'}), 400
        
        # 3. Get backup file
        if 'backup_file' not in request.files:
            logging.warning("[Restore] No backup_file in request.files")
            return jsonify({'error': 'No backup file provided'}), 400
        
        backup_file = request.files['backup_file']
        if not backup_file.filename:
            return jsonify({'error': 'No backup file selected'}), 400
        
        logging.debug(f"[Restore] Processing file: {backup_file.filename}")
        
        # Read and decrypt
        encrypted_data = backup_file.read()
        logging.debug(f"[Restore] Read {len(encrypted_data)} bytes from file")
        
        try:
            decrypted_json = _decrypt_backup(encrypted_data, backup_password)
            data = json.loads(decrypted_json)
        except ValueError as e:
            log_audit(username, 'config.restore_failed', f'Decryption failed: {str(e)}')
            return jsonify({'error': str(e)}), 400
        except json.JSONDecodeError:
            return jsonify({'error': 'Invalid backup file format'}), 400
        
        # Validate backup format
        if 'version' not in data or 'export_date' not in data:
            return jsonify({'error': 'Invalid backup format - missing required fields'}), 400
        
        database = get_db()
        results = {
            'mode': mode,
            'dry_run': dry_run,
            'backup_version': data.get('version'),
            'backup_date': data.get('export_date'),
            'backup_by': data.get('exported_by'),
            'restored': {},
            'skipped': {},
            'errors': []
        }
        
        # Server Settings
        if 'server_settings' in data:
            try:
                if not dry_run:
                    current = load_server_settings()
                    if mode == 'merge':
                        # Only update non-empty values
                        for key, value in data['server_settings'].items():
                            if value not in [None, '', []]:
                                current[key] = value
                        save_server_settings(current)
                    else:
                        save_server_settings(data['server_settings'])
                results['restored']['server_settings'] = True
            except Exception as e:
                results['errors'].append(f"Server settings: {str(e)}")
        
        # Clusters
        if 'clusters' in data:
            cluster_count = 0
            clusters_data = data['clusters']
            
            # NS: log types because old backups might have different formats
            logging.debug(f"[Restore] Clusters type: {type(clusters_data)}")
            if isinstance(clusters_data, list) and len(clusters_data) > 0:
                logging.debug(f"[Restore] First cluster type: {type(clusters_data[0])}")
            
            # Handle both list of dicts and dict of dicts formats
            # MK: we changed the export format once, need to support both
            if isinstance(clusters_data, dict):
                # Format: {'cluster_id': {cluster_data}, ...}
                clusters_list = [{'id': k, **v} if isinstance(v, dict) else {'id': k} for k, v in clusters_data.items()]
            elif isinstance(clusters_data, list):
                clusters_list = clusters_data
            else:
                clusters_list = []
                results['errors'].append(f"Clusters: Invalid format (expected list or dict, got {type(clusters_data).__name__})")
            
            for cluster in clusters_list:
                try:
                    # Skip if not a dict
                    if not isinstance(cluster, dict):
                        logging.warning(f"[Restore] Skipping non-dict cluster: {type(cluster)}")
                        continue
                    
                    cluster_id = cluster.get('id')
                    if not cluster_id:
                        logging.warning(f"[Restore] Skipping cluster without id")
                        continue
                    
                    existing = database.get_cluster(cluster_id)
                    
                    if existing and mode == 'merge':
                        # Keep existing passwords if not in backup
                        if not cluster.get('password_encrypted') and existing.get('password_encrypted'):
                            cluster['password_encrypted'] = existing['password_encrypted']
                        if not cluster.get('ssh_key_encrypted') and existing.get('ssh_key_encrypted'):
                            cluster['ssh_key_encrypted'] = existing['ssh_key_encrypted']
                    
                    if not dry_run:
                        database.save_cluster(cluster_id, cluster)
                    cluster_count += 1
                except Exception as e:
                    cluster_id_str = cluster.get('id', 'unknown') if isinstance(cluster, dict) else str(cluster)[:20]
                    results['errors'].append(f"Cluster {cluster_id_str}: {str(e)}")
            results['restored']['clusters'] = cluster_count
        
        # Users (only if explicitly requested)
        if restore_users and 'users' in data:
            user_count = 0
            users_data = data['users']
            
            # Handle both list and dict formats
            if isinstance(users_data, dict):
                # Format: {'username': {user_data}, ...}
                users_list = [{'username': k, **v} if isinstance(v, dict) else {'username': k} for k, v in users_data.items()]
            elif isinstance(users_data, list):
                users_list = users_data
            else:
                users_list = []
                results['errors'].append(f"Users: Invalid format")
            
            for u in users_list:
                try:
                    if not isinstance(u, dict):
                        continue
                    uname = u.get('username')
                    if not uname or uname == 'admin' or uname == 'pegaprox':  # Never overwrite admin
                        continue
                    
                    if not dry_run:
                        database.save_user(uname, u)
                    user_count += 1
                except Exception as e:
                    uname_str = u.get('username', 'unknown') if isinstance(u, dict) else str(u)[:20]
                    results['errors'].append(f"User {uname_str}: {str(e)}")
            results['restored']['users'] = user_count
        else:
            results['skipped']['users'] = 'Not requested (safety)'
        
        # Tenants
        if 'tenants' in data:
            tenant_count = 0
            tenants_data = data['tenants']
            
            # Handle both list and dict formats
            if isinstance(tenants_data, dict):
                tenants_list = [{'id': k, **v} if isinstance(v, dict) else {'id': k} for k, v in tenants_data.items()]
            elif isinstance(tenants_data, list):
                tenants_list = tenants_data
            else:
                tenants_list = []
            
            for tenant in tenants_list:
                try:
                    if not isinstance(tenant, dict):
                        continue
                    if not dry_run:
                        database.save_tenant(tenant.get('id'), tenant)
                    tenant_count += 1
                except Exception as e:
                    results['errors'].append(f"Tenant: {str(e)}")
            results['restored']['tenants'] = tenant_count
        
        # VM ACLs
        if 'vm_acls' in data:
            try:
                if not dry_run:
                    if mode == 'overwrite':
                        # Clear existing
                        database.conn.cursor().execute('DELETE FROM vm_acls')
                    database.save_all_vm_acls(data['vm_acls'])
                results['restored']['vm_acls'] = len(data['vm_acls'])
            except Exception as e:
                results['errors'].append(f"VM ACLs: {str(e)}")
        
        # Affinity Rules
        if 'affinity_rules' in data:
            rule_count = 0
            for cluster_id, rules in data['affinity_rules'].items():
                for rule in rules:
                    try:
                        if not dry_run:
                            database.save_affinity_rule(cluster_id, rule)
                        rule_count += 1
                    except Exception as e:
                        results['errors'].append(f"Affinity rule: {str(e)}")
            results['restored']['affinity_rules'] = rule_count
        
        # Cluster Groups
        if 'cluster_groups' in data:
            group_count = 0
            cursor = database.conn.cursor()
            for group in data['cluster_groups']:
                try:
                    if not dry_run:
                        cursor.execute('''
                            INSERT OR REPLACE INTO cluster_groups (id, name, tenant_id, description, created_at)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (group.get('id'), group.get('name'), group.get('tenant_id'), 
                              group.get('description'), group.get('created_at', datetime.now().isoformat())))
                    group_count += 1
                except Exception as e:
                    results['errors'].append(f"Cluster group: {str(e)}")
            if not dry_run:
                database.conn.commit()
            results['restored']['cluster_groups'] = group_count
        
        # Log the restore action
        if not dry_run:
            log_audit(username, 'config.restore', f"Configuration restored from backup ({mode} mode)")
        else:
            log_audit(username, 'config.restore_dryrun', f"Configuration restore dry-run ({mode} mode)")
        
        return jsonify(results)
        
    except Exception as e:
        logging.error(f"Config restore failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ============================================
# IP Whitelisting API Routes
# LW: Jan 2026 - enterprise feature request
# ============================================

# IP Whitelist storage (loaded from settings)
_ip_whitelist_enabled = False
_ip_whitelist = set()
_ip_blacklist = set()  # MK: blacklist always wins over whitelist

def load_ip_whitelist():
    """Load IP whitelist from server settings"""
    global _ip_whitelist_enabled, _ip_whitelist, _ip_blacklist
    
    try:
        settings = load_server_settings()
        _ip_whitelist_enabled = settings.get('ip_whitelist_enabled', False)
        
        # MK: 'or' handles None values from old configs
        whitelist_str = settings.get('ip_whitelist') or ''
        _ip_whitelist = set(ip.strip() for ip in whitelist_str.split(',') if ip.strip())
        
        blacklist_str = settings.get('ip_blacklist') or ''
        _ip_blacklist = set(ip.strip() for ip in blacklist_str.split(',') if ip.strip())
    except Exception as e:
        logging.warning(f"Could not load IP whitelist: {e}")
        _ip_whitelist_enabled = False
        _ip_whitelist = set()
        _ip_blacklist = set()

def check_ip_allowed(client_ip: str) -> tuple:
    """check if client IP is allowed, returns (allowed, reason)"""
    if not _ip_whitelist_enabled:
        return True, 'Whitelist disabled'

    if not client_ip:
        return False, 'No IP detected'

    # LW Feb 2026 - normalize here too so log messages show clean IPv4
    client_ip = _normalize_ip(client_ip)
    
    # Check blacklist first (always blocks)
    # NS: blacklist is checked before whitelist, security first
    if _ip_blacklist:
        for blocked in _ip_blacklist:
            if _ip_matches(client_ip, blocked):
                return False, f'IP blacklisted: {blocked}'
    
    # If whitelist is empty, allow all (only blacklist applies)
    if not _ip_whitelist:
        return True, 'No whitelist configured'
    
    # Check whitelist
    for allowed in _ip_whitelist:
        if _ip_matches(client_ip, allowed):
            return True, f'IP allowed: {allowed}'
    
    return False, 'IP not in whitelist'

def _normalize_ip(ip_str: str) -> str:
    """Strip IPv6-mapped prefix so ::ffff:192.168.1.1 becomes 192.168.1.1

    MK Feb 2026 - dual-stack sockets report IPv4 clients as ::ffff:x.x.x.x
    Fixes #95: IP whitelist didn't match after IPv6 bind change
    """
    if ip_str and ip_str.startswith('::ffff:'):
        return ip_str[7:]
    return ip_str

def _ip_matches(client_ip: str, pattern: str) -> bool:
    """Check if IP matches pattern (supports CIDR and wildcards)

    NS: supports 192.168.1.100, 192.168.1.0/24, 192.168.1.*
    MK: chatgpt helped with the ipaddress module stuff
    """
    try:
        # NS Feb 2026 - normalize IPv6-mapped addresses for comparison
        client_ip = _normalize_ip(client_ip)

        # Exact match
        if client_ip == pattern:
            return True

        # Wildcard match (e.g., 192.168.1.*)
        if '*' in pattern:
            import fnmatch
            return fnmatch.fnmatch(client_ip, pattern)

        # CIDR match (e.g., 192.168.1.0/24)
        if '/' in pattern:
            import ipaddress
            network = ipaddress.ip_network(pattern, strict=False)
            return ipaddress.ip_address(client_ip) in network

        return False
    except Exception:
        return False

# Load whitelist on startup
try:
    load_ip_whitelist()
except:
    pass  # Settings might not exist yet

@bp.before_app_request
def check_ip_whitelist():
    """Check IP whitelist before processing request"""
    # Skip for static files
    if request.path.startswith('/static'):
        return None
    
    # Skip if whitelist not enabled
    if not _ip_whitelist_enabled:
        return None
    
    client_ip = get_client_ip()
    allowed, reason = check_ip_allowed(client_ip)
    
    if not allowed:
        logging.warning(f"IP blocked: {client_ip} - {reason}")
        return jsonify({
            'error': 'Access denied',
            'message': 'Your IP address is not allowed to access this service',
            'ip': client_ip
        }), 403

@bp.route('/api/security/ip-whitelist', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def get_ip_whitelist():
    """Get IP whitelist configuration (admin only)"""
    try:
        settings = load_server_settings()
        
        whitelist_str = settings.get('ip_whitelist') or ''
        blacklist_str = settings.get('ip_blacklist') or ''
        
        return jsonify({
            'enabled': settings.get('ip_whitelist_enabled', False),
            'whitelist': [ip.strip() for ip in whitelist_str.split(',') if ip.strip()],
            'blacklist': [ip.strip() for ip in blacklist_str.split(',') if ip.strip()],
            'your_ip': get_client_ip(),
            'formats_supported': ['Single IP (192.168.1.100)', 'CIDR (192.168.1.0/24)', 'Wildcard (192.168.1.*)']
        })
    except Exception as e:
        logging.error(f"Error getting IP whitelist: {e}")
        return jsonify({'error': str(e)}), 500

@bp.route('/api/security/ip-whitelist', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def update_ip_whitelist():
    """Update IP whitelist configuration (admin only)
    
    Body:
    - enabled: bool
    - whitelist: list of IPs/CIDRs
    - blacklist: list of IPs/CIDRs
    """
    try:
        data = request.json or {}
        settings = load_server_settings()
        current_ip = get_client_ip()
        
        # Validate that admin's current IP would still be allowed
        if data.get('enabled', False):
            new_whitelist = set(data.get('whitelist', []))
            new_blacklist = set(data.get('blacklist', []))
            
            # Check if current IP would be blocked
            if new_whitelist:
                allowed = False
                for pattern in new_whitelist:
                    if _ip_matches(current_ip, pattern):
                        allowed = True
                        break
                
                if not allowed:
                    return jsonify({
                        'error': 'Your current IP would be blocked',
                        'message': f'Add {current_ip} to the whitelist before enabling',
                        'your_ip': current_ip
                    }), 400
            
            # Check blacklist doesn't include current IP
            for pattern in new_blacklist:
                if _ip_matches(current_ip, pattern):
                    return jsonify({
                        'error': 'Your current IP is in the blacklist',
                        'message': f'Remove {current_ip} from the blacklist',
                        'your_ip': current_ip
                    }), 400
        
        # Update settings
        if 'enabled' in data:
            settings['ip_whitelist_enabled'] = bool(data['enabled'])
        
        if 'whitelist' in data:
            settings['ip_whitelist'] = ','.join(data['whitelist'])
        
        if 'blacklist' in data:
            settings['ip_blacklist'] = ','.join(data['blacklist'])
        
        save_server_settings(settings)
        
        # Reload whitelist
        load_ip_whitelist()
        
        # Audit log
        usr = getattr(request, 'session', {}).get('user', 'system')
        log_audit(usr, 'security.ip_whitelist_updated', 
                 f"IP whitelist {'enabled' if settings.get('ip_whitelist_enabled') else 'disabled'}, "
                 f"{len(_ip_whitelist)} IPs whitelisted, {len(_ip_blacklist)} IPs blacklisted")
        
        return jsonify({
            'success': True,
            'enabled': settings.get('ip_whitelist_enabled', False),
            'whitelist_count': len(_ip_whitelist),
            'blacklist_count': len(_ip_blacklist)
        })
        
    except Exception as e:
        logging.error(f"IP whitelist update failed: {e}")
        return jsonify({'error': str(e)}), 500

@bp.route('/api/security/ip-whitelist/test', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def test_ip_whitelist():
    """Test if an IP would be allowed (admin only)
    
    Body:
    - ip: IP address to test
    """
    try:
        data = request.json or {}
        test_ip = data.get('ip', get_client_ip())
        
        allowed, reason = check_ip_allowed(test_ip)
        
        return jsonify({
            'ip': test_ip,
            'allowed': allowed,
            'reason': reason,
            'whitelist_enabled': _ip_whitelist_enabled
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# Audit Log API Route
# ============================================

@bp.route('/api/audit', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def get_audit_log_api():
    """Get audit log entries (admin only)"""
    # Optional filters
    user_filter = request.args.get('user')
    action_filter = request.args.get('action')
    limit = int(request.args.get('limit', 500))
    verify = request.args.get('verify', '').lower() == 'true'
    
    # Get from database with optional integrity verification
    database = get_db()
    entries = database.get_audit_log(
        limit=limit,
        user=user_filter,
        action=action_filter,
        verify_integrity=verify
    )
    
    return jsonify(entries)


# MK: Cluster-specific audit endpoint with vmid filter
@bp.route('/api/clusters/<cluster_id>/audit', methods=['GET'])
@require_auth(perms=['cluster.view'])
def get_cluster_audit_log_api(cluster_id):
    """Get audit log entries for a specific cluster, optionally filtered by vmid"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    # Get cluster name for filtering
    cluster_name = None
    if cluster_id in cluster_managers:
        cluster_name = cluster_managers[cluster_id].config.name
    
    # Check if we're in multi-cluster mode
    multi_cluster = len(cluster_managers) > 1
    
    # Optional filters
    vmid = request.args.get('vmid')
    limit = int(request.args.get('limit', 100))
    
    # Get from database
    database = get_db()
    entries = database.get_audit_log(limit=limit * 10)  # Get more to filter
    
    # Filter by cluster and vmid
    filtered = []
    for entry in entries:
        entry_cluster = entry.get('cluster', '')
        details = entry.get('details', '')
        
        # Cluster filter
        if cluster_name:
            detected_cluster = None
            
            # First check the cluster field
            if entry_cluster:
                detected_cluster = entry_cluster
            else:
                # Try to detect cluster from details text
                import re
                # Look for [SomeCluster] pattern at end
                bracket_match = re.search(r'\[([^\]]+)\]\s*$', details)
                if bracket_match:
                    detected_cluster = bracket_match.group(1)
                else:
                    # Look for "for cluster X" or "cluster X" pattern
                    cluster_match = re.search(r'(?:for )?cluster\s+(\S+)', details, re.IGNORECASE)
                    if cluster_match:
                        detected_cluster = cluster_match.group(1)
            
            # If we detected a cluster, it must match
            if detected_cluster:
                if detected_cluster != cluster_name:
                    continue
            else:
                # No cluster info at all - skip in multi-cluster mode
                if multi_cluster:
                    continue
        
        # Check vmid filter
        if vmid:
            vmid_str = str(vmid)
            vmid_found = False
            
            # Check for patterns in details
            patterns = [
                f"VM {vmid_str} ", f"VM {vmid_str}-", f"VM {vmid_str})",
                f"CT {vmid_str} ", f"CT {vmid_str}-", f"CT {vmid_str})",
                f"QEMU {vmid_str} ", f"QEMU {vmid_str}-", f"QEMU {vmid_str})",
                f"LXC {vmid_str} ", f"LXC {vmid_str}-",
                f"/{vmid_str} ", f"/{vmid_str})",
                f"qemu/{vmid_str}", f"lxc/{vmid_str}",
            ]
            
            for pattern in patterns:
                if pattern in details:
                    vmid_found = True
                    break
            
            # Also check if details ends with the vmid pattern
            if not vmid_found:
                for ending in [f"VM {vmid_str}", f"CT {vmid_str}", f"QEMU {vmid_str}", f"LXC {vmid_str}"]:
                    if details.endswith(ending):
                        vmid_found = True
                        break
            
            if not vmid_found:
                continue
        
        filtered.append(entry)
        if len(filtered) >= limit:
            break
    
    return jsonify(filtered)


@bp.route('/api/audit/integrity', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def verify_audit_integrity():
    """Verify integrity of audit log using HMAC signatures (admin only)
    
    Returns statistics about log integrity:
    - total_entries: Total number of entries
    - verified: Entries with valid HMAC signature
    - unsigned: Old entries without signature (pre-upgrade)
    - potentially_tampered: Entries with invalid signature (WARNING!)
    - integrity_percentage: Percentage of verified entries
    """
    database = get_db()
    result = database.verify_audit_log_integrity()
    
    # Log this check itself
    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'audit.integrity_check', f"Audit integrity check: {result['verified']}/{result['total_entries']} verified, {result['potentially_tampered']} potentially tampered")
    
    return jsonify(result)

@bp.route('/api/security/key-info', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def get_encryption_key_info():
    """get info about current encryption key (exists, created, algorithm, backups)"""
    database = get_db()
    return jsonify(database.get_key_info())

@bp.route('/api/security/key-rotate', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def rotate_encryption_key():
    """Rotate the encryption key (admin only)
    
    IMPORTANT: This re-encrypts all sensitive data with a new key.
    Required for HIPAA/ISO 27001 compliance (periodic key rotation).
    
    The old key is backed up before rotation.
    """
    usr = getattr(request, 'session', {}).get('user', 'system')
    
    # Confirm action
    data = request.json or {}
    if not data.get('confirm'):
        return jsonify({
            'error': 'Key rotation requires confirmation',
            'message': 'Send {"confirm": true} to proceed. This will re-encrypt all data.'
        }), 400
    
    log_audit(usr, 'security.key_rotation_started', 'Encryption key rotation initiated')
    
    database = get_db()
    result = database.rotate_encryption_key()
    
    if result.get('success'):
        log_audit(usr, 'security.key_rotation_completed', 
                 f"Key rotation completed: {result.get('users_rotated', 0)} users, "
                 f"{result.get('clusters_rotated', 0)} clusters rotated")
        return jsonify(result)
    else:
        log_audit(usr, 'security.key_rotation_failed', f"Key rotation failed: {result.get('error', 'Unknown error')}")
        return jsonify(result), 500

@bp.route('/api/security/compliance', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def get_compliance_status():
    """Get security compliance status (admin only)
    
    Returns overview of security features for HIPAA/ISO 27001 compliance.
    """
    try:
        settings = load_server_settings()
        database = get_db()
        key_info = database.get_key_info()
        
        # Calculate compliance score
        # MK: each check is worth the same, simple but effective
        checks = {
            'encryption_enabled': ENCRYPTION_AVAILABLE and key_info.get('exists', False),
            'https_enabled': os.path.exists(SSL_CERT_FILE) and os.path.exists(SSL_KEY_FILE),
            'password_policy_enabled': settings.get('password_min_length', 8) >= 8,
            'session_timeout_compliant': settings.get('session_timeout', SESSION_TIMEOUT) <= 28800,  # 8h max for HIPAA
            '2fa_available': TOTP_AVAILABLE,
            'audit_logging_enabled': True,  # Always enabled
            'rate_limiting_enabled': API_RATE_LIMIT > 0,
            'brute_force_protection': True,  # Always enabled
        }
        
        score = sum(1 for v in checks.values() if v) / len(checks) * 100
        
        return jsonify({
            'compliance_score': round(score, 1),
            'checks': checks,
            'encryption': {
                'algorithm': 'AES-256-GCM',
                'key_exists': key_info.get('exists', False),
                'key_created': key_info.get('created'),
                'last_rotation': key_info.get('last_modified'),
                'backups_count': len(key_info.get('backups', []))
            },
            'session': {
                'timeout_seconds': settings.get('session_timeout', SESSION_TIMEOUT),
                'timeout_hours': settings.get('session_timeout', SESSION_TIMEOUT) / 3600
            },
            'password_policy': {
                'min_length': settings.get('password_min_length', 8),
                'require_uppercase': settings.get('password_require_uppercase', True),
                'require_lowercase': settings.get('password_require_lowercase', True),
                'require_numbers': settings.get('password_require_numbers', True),
                'require_special': settings.get('password_require_special', False),
                'expiry_enabled': settings.get('password_expiry_enabled', False),
                'expiry_days': settings.get('password_expiry_days', 90)
            },
            'recommendations': [
                r for r in [
                    None if checks['https_enabled'] else 'Enable HTTPS with valid certificates',
                    None if checks['session_timeout_compliant'] else 'Reduce session timeout to 8 hours or less',
                    None if settings.get('password_require_special') else 'Consider requiring special characters in passwords',
                    None if settings.get('password_expiry_enabled') else 'Consider enabling password expiry',
                    None if key_info.get('backups') else 'Perform initial key rotation to create backup',
                    None if not _check_default_password_in_use() else 'CRITICAL: Default admin password is still in use! Change it immediately.',
                ] if r is not None
            ],
            'default_password_warning': _check_default_password_in_use()
        })
    except Exception as e:
        logging.error(f"Error getting compliance status: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@bp.route('/api/security/cors', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def get_cors_origins():
    """Get configured CORS origins (admin only)"""
    env_origins = [o.strip() for o in _cors_origins_env.split(',') if o.strip()] if _cors_origins_env else []
    
    return jsonify({
        'mode': 'same-origin' if not env_origins and not _auto_allowed_origins else 'configured',
        'environment_origins': env_origins,
        'auto_allowed_origins': list(_auto_allowed_origins),
        'all_allowed': get_allowed_origins() or [],
        'help': {
            'same-origin': 'Only requests from the same host are allowed (most secure)',
            'configured': 'Specific origins are allowed',
            'env_variable': 'PEGAPROX_ALLOWED_ORIGINS',
            'example': 'export PEGAPROX_ALLOWED_ORIGINS="https://pegaprox.example.com"'
        }
    })

@bp.route('/api/security/cors', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def add_cors_origin():
    """Manually add a CORS origin (admin only)

    Note: This is temporary (until server restart). For permanent origins,
    use the PEGAPROX_ALLOWED_ORIGINS environment variable.
    """
    data = request.json or {}
    origin = data.get('origin', '').strip()

    if not origin:
        return jsonify({'error': 'Origin required'}), 400

    if not origin.startswith(('http://', 'https://')):
        return jsonify({'error': 'Origin must start with http:// or https://'}), 400

    if origin == '*':
        return jsonify({'error': 'Wildcard (*) not allowed for security reasons'}), 400

    add_allowed_origin(origin)

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'security.cors_origin_added', f"Added CORS origin: {origin}")

    return jsonify({
        'success': True,
        'message': f'Origin {origin} added',
        'note': 'This is temporary until server restart. Set PEGAPROX_ALLOWED_ORIGINS env var for permanent configuration.'
    })

# API Routes
@bp.route('/')

def index():
    """Serve the web interface"""
    return send_from_directory(WEB_DIR, 'index.html')

@bp.route('/oidc/callback')
def oidc_callback_page():
    """NS: Feb 2026 - Serve SPA for OIDC redirect callback
    
    Identity providers redirect here with ?code=xxx&state=yyy
    The frontend JS picks up the params and calls the API callback endpoint
    """
    return send_from_directory(WEB_DIR, 'index.html')

@bp.route('/api/status', methods=['GET'])
def get_status():
    """Get PegaProx system status - includes version info
    
    NS: unauthenticated users only get version + build, no cluster details
    """
    basic_status = {
        'version': PEGAPROX_VERSION,
        'build': PEGAPROX_BUILD,
        'totp_available': TOTP_AVAILABLE,
    }
    
    # MK: don't show cluster details to unauthenticated users (was leaking infra info)
    session_id = request.headers.get('X-Session-ID') or request.cookies.get('session_id')
    session = validate_session(session_id) if session_id else None
    if session:
        basic_status.update({
            'encryption': {
                'available': ENCRYPTION_AVAILABLE,
                'enabled': ENCRYPTION_AVAILABLE and os.path.exists(KEY_FILE),
                'config_encrypted': os.path.exists(CONFIG_FILE_ENCRYPTED)
            },
            'clusters_count': len(cluster_managers),
            'gevent_available': GEVENT_AVAILABLE,
            'ssh': get_ssh_connection_stats(),
        })
    
    return jsonify(basic_status)


@bp.route('/api/support-bundle', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def generate_support_bundle():
    """Generate a support bundle with logs and system info for troubleshooting
    
    NS: Feb 2026 - Like VMware's support bundle feature
    Collects all relevant diagnostic information into a ZIP file
    Sensitive data (passwords, tokens, secrets) are automatically redacted
    """
    import zipfile
    import io
    import platform
    import socket
    
    try:
        username = request.session.get('user', 'unknown')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        bundle_prefix = f"pegaprox_support_{timestamp}"
        
        log_audit(username, 'support.bundle_generated', 'Generated support bundle for troubleshooting')
        
        # Create in-memory ZIP file
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            
            # 1. System Information
            try:
                import flask as flask_module
                flask_ver = flask_module.__version__
            except:
                flask_ver = 'unknown'
            
            system_info = {
                'generated_at': datetime.now().isoformat(),
                'pegaprox_version': PEGAPROX_VERSION,
                'pegaprox_build': PEGAPROX_BUILD,
                'python_version': platform.python_version(),
                'platform': platform.platform(),
                'hostname': socket.gethostname(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'encryption_available': ENCRYPTION_AVAILABLE,
                'encryption_enabled': ENCRYPTION_AVAILABLE and os.path.exists(KEY_FILE),
                'totp_available': TOTP_AVAILABLE,
                'gevent_available': GEVENT_AVAILABLE,
                'flask_version': flask_ver,
            }
            zf.writestr(f"{bundle_prefix}/system_info.json", json.dumps(system_info, indent=2))
            
            # 2. Cluster Status (sanitized)
            cluster_status = []
            for cluster_id, mgr in cluster_managers.items():
                cluster_status.append({
                    'id': cluster_id,
                    'name': mgr.config.name,
                    'host': mgr.config.host,
                    'status': 'running' if mgr.running else 'stopped',
                    'connected': mgr.is_connected,
                    'connection_error': mgr.connection_error,
                    'ha_enabled': mgr.config.ha_enabled,
                    'auto_migrate': mgr.config.auto_migrate,
                    'dry_run': mgr.config.dry_run,
                    'last_run': mgr.last_run.isoformat() if mgr.last_run else None,
                    'current_host': getattr(mgr, 'current_host', None),
                    'fallback_hosts_count': len(mgr.config.fallback_hosts) if mgr.config.fallback_hosts else 0,
                })
            zf.writestr(f"{bundle_prefix}/cluster_status.json", json.dumps(cluster_status, indent=2))
            
            # 3. SSH Connection Stats
            try:
                ssh_stats = get_ssh_connection_stats()
                zf.writestr(f"{bundle_prefix}/ssh_stats.json", json.dumps(ssh_stats, indent=2))
            except Exception as e:
                zf.writestr(f"{bundle_prefix}/ssh_stats_error.txt", f"Failed: {str(e)}")
            
            # 4. SSE Connection Info
            sse_info = {'active_clients': len(sse_clients), 'clients': []}
            try:
                with sse_clients_lock:
                    for client_id, client_data in list(sse_clients.items())[:50]:
                        sse_info['clients'].append({
                            'user': client_data.get('user', 'unknown'),
                            'clusters': client_data.get('clusters', []),
                            'connected_at': client_data.get('connected_at'),
                            'auth_method': client_data.get('auth_method')
                        })
            except Exception as e:
                sse_info['error'] = str(e)
            zf.writestr(f"{bundle_prefix}/sse_connections.json", json.dumps(sse_info, indent=2))
            
            # 5. Active Sessions (anonymized)
            sessions_info = {'total_active': len(active_sessions), 'sessions': []}
            for sid, sess in list(active_sessions.items())[:50]:
                sessions_info['sessions'].append({
                    'user': sess.get('user', 'unknown'),
                    'role': sess.get('role', 'unknown'),
                    'created_at': sess.get('created_at'),
                    'last_activity': sess.get('last_activity'),
                })
            zf.writestr(f"{bundle_prefix}/sessions_info.json", json.dumps(sessions_info, indent=2))
            
            # 6. Recent Audit Logs (last 500 entries)
            try:
                db = get_db()
                cursor = db.conn.cursor()
                cursor.execute('SELECT timestamp, user, action, details, ip_address FROM audit_log ORDER BY timestamp DESC LIMIT 500')
                audit_entries = []
                for row in cursor.fetchall():
                    audit_entries.append({
                        'timestamp': row[0],
                        'user': row[1],
                        'action': row[2],
                        'details': row[3],
                        'ip': (row[4][:10] + '...') if row[4] and len(row[4]) > 10 else row[4]
                    })
                zf.writestr(f"{bundle_prefix}/audit_log.json", json.dumps(audit_entries, indent=2))
            except Exception as e:
                zf.writestr(f"{bundle_prefix}/audit_log_error.txt", f"Failed: {str(e)}")
            
            # 7. Database Schema Info
            try:
                db = get_db()
                cursor = db.conn.cursor()
                schema_info = {}
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                for table in tables:
                    cursor.execute(f"PRAGMA table_info({table})")
                    columns = [{'name': col[1], 'type': col[2]} for col in cursor.fetchall()]
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    schema_info[table] = {'columns': columns, 'row_count': count}
                zf.writestr(f"{bundle_prefix}/database_schema.json", json.dumps(schema_info, indent=2))
            except Exception as e:
                zf.writestr(f"{bundle_prefix}/database_schema_error.txt", f"Failed: {str(e)}")
            
            # 8. Server Settings (sanitized)
            try:
                settings = load_server_settings()
                safe_settings = {}
                sensitive_keys = ['smtp_password', 'ssl_key', 'password', 'secret', 'token', 'api_key']
                for key, value in settings.items():
                    if any(s in key.lower() for s in sensitive_keys):
                        safe_settings[key] = '[REDACTED]' if value else ''
                    else:
                        safe_settings[key] = value
                zf.writestr(f"{bundle_prefix}/server_settings.json", json.dumps(safe_settings, indent=2))
            except Exception as e:
                zf.writestr(f"{bundle_prefix}/server_settings_error.txt", f"Failed: {str(e)}")
            
            # 9. User List (no sensitive data)
            try:
                users = load_users()
                user_list = []
                for uname, udata in users.items():
                    user_list.append({
                        'username': uname,
                        'role': udata.get('role'),
                        'enabled': udata.get('enabled', True),
                        'totp_enabled': udata.get('totp_enabled', False),
                        'tenant': udata.get('tenant'),
                        'last_login': udata.get('last_login'),
                    })
                zf.writestr(f"{bundle_prefix}/users_list.json", json.dumps(user_list, indent=2))
            except Exception as e:
                zf.writestr(f"{bundle_prefix}/users_list_error.txt", f"Failed: {str(e)}")
            
            # 10. Application Log (last 1000 lines)
            # Check multiple possible log locations
            possible_log_files = [
                os.path.join(CONFIG_DIR, 'pegaprox.log'),
                '/var/log/pegaprox.log',
                'pegaprox.log',
            ]
            log_file = None
            for lf in possible_log_files:
                if os.path.exists(lf):
                    log_file = lf
                    break
            
            if log_file:
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                        lines = f.readlines()
                        last_lines = lines[-1000:] if len(lines) > 1000 else lines
                        redacted_lines = []
                        for line in last_lines:
                            line = re.sub(r'(password["\']?\s*[:=]\s*["\']?)[^"\'&\s]+', r'\1[REDACTED]', line, flags=re.IGNORECASE)
                            line = re.sub(r'(token["\']?\s*[:=]\s*["\']?)[^"\'&\s]+', r'\1[REDACTED]', line, flags=re.IGNORECASE)
                            line = re.sub(r'(secret["\']?\s*[:=]\s*["\']?)[^"\'&\s]+', r'\1[REDACTED]', line, flags=re.IGNORECASE)
                            redacted_lines.append(line)
                        zf.writestr(f"{bundle_prefix}/pegaprox.log", ''.join(redacted_lines))
                except Exception as e:
                    zf.writestr(f"{bundle_prefix}/pegaprox_log_error.txt", f"Failed: {str(e)}")
            else:
                zf.writestr(f"{bundle_prefix}/pegaprox.log", "Log file not found. Checked: " + ", ".join(possible_log_files))
            
            # 11. Recent Tasks
            try:
                recent_tasks = []
                for cluster_id, mgr in cluster_managers.items():
                    if mgr.is_connected:
                        try:
                            tasks = mgr.get_tasks(limit=50)
                            if tasks:
                                for task in tasks:
                                    task['cluster_id'] = cluster_id
                                    recent_tasks.append(task)
                        except:
                            pass
                recent_tasks.sort(key=lambda x: x.get('starttime', 0), reverse=True)
                zf.writestr(f"{bundle_prefix}/recent_tasks.json", json.dumps(recent_tasks[:100], indent=2))
            except Exception as e:
                zf.writestr(f"{bundle_prefix}/recent_tasks_error.txt", f"Failed: {str(e)}")
            
            # 12. Environment Variables (safe ones only)
            safe_env_vars = {}
            safe_prefixes = ['PEGAPROX_', 'FLASK_', 'PYTHON']
            for key, value in os.environ.items():
                if any(key.startswith(p) for p in safe_prefixes):
                    if 'password' in key.lower() or 'secret' in key.lower() or 'key' in key.lower():
                        safe_env_vars[key] = '[REDACTED]'
                    else:
                        safe_env_vars[key] = value
            zf.writestr(f"{bundle_prefix}/environment.json", json.dumps(safe_env_vars, indent=2))
            
            # 13. PegaProx SSH Session Log (last 100 entries)
            # NS: Feb 2026 - Track SSH sessions opened through PegaProx WebSocket terminal
            try:
                db = get_db()
                cursor = db.conn.cursor()
                cursor.execute('''
                    SELECT timestamp, user, action, details, ip_address 
                    FROM audit_log 
                    WHERE action LIKE 'ssh.%' OR action LIKE 'node.shell%'
                    ORDER BY timestamp DESC LIMIT 100
                ''')
                ssh_entries = []
                for row in cursor.fetchall():
                    ssh_entries.append({
                        'timestamp': row[0],
                        'user': row[1],
                        'action': row[2],
                        'details': row[3],
                        'ip': row[4]
                    })
                zf.writestr(f"{bundle_prefix}/ssh_sessions.json", json.dumps(ssh_entries, indent=2))
            except Exception as e:
                zf.writestr(f"{bundle_prefix}/ssh_sessions_error.txt", f"Failed: {str(e)}")
            
            # 14. README
            readme = f"""PegaProx Support Bundle
========================
Generated: {datetime.now().isoformat()}
Version: {PEGAPROX_VERSION} (Build {PEGAPROX_BUILD})

Contents:
- system_info.json: System and environment information
- cluster_status.json: Status of all configured clusters
- ssh_stats.json: SSH connection pool statistics
- sse_connections.json: Server-Sent Events connection info
- sessions_info.json: Active session information (anonymized)
- audit_log.json: Recent audit log entries (last 500)
- database_schema.json: Database table structure and row counts
- server_settings.json: Server configuration (passwords redacted)
- users_list.json: User list (no passwords)
- pegaprox.log: Application log (last 1000 lines, sensitive data redacted)
- recent_tasks.json: Recent Proxmox tasks from all clusters
- environment.json: Relevant environment variables
- ssh_sessions.json: Last 100 PegaProx SSH terminal sessions (connects, disconnects, failures)

Privacy Note:
Sensitive information (passwords, tokens, secrets, API keys) has been 
automatically redacted. Please review contents before sharing.

Generated by: {username}
"""
            zf.writestr(f"{bundle_prefix}/README.txt", readme)
        
        # Prepare response
        zip_buffer.seek(0)
        
        response = make_response(zip_buffer.getvalue())
        response.headers['Content-Type'] = 'application/zip'
        response.headers['Content-Disposition'] = f'attachment; filename=pegaprox_support_{timestamp}.zip'
        
        return response
        
    except Exception as e:
        logging.error(f"Support bundle generation failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to generate support bundle: {str(e)}'}), 500


# ==================== UPDATE MANAGER ====================

@bp.route('/api/clusters/<cluster_id>/updates/check', methods=['POST'])
@require_auth(perms=['node.update'])
def check_cluster_updates(cluster_id):
    """Check for updates on all nodes in the cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    results = {}
    
    try:
        host = mgr.current_host or mgr.config.host
        url = f"https://{host}:8006/api2/json/nodes"
        r = mgr._create_session().get(url, timeout=10)
        
        if r.status_code != 200:
            return jsonify({'error': 'Failed: nodes from cluster'}), 500
        
        nodes_data = r.json().get('data', [])
        node_names = [n.get('node') for n in nodes_data if n.get('node') and n.get('status') == 'online']
    except Exception as e:
        return jsonify({'error': f'Failed to connect to cluster: {str(e)}'}), 500
    
    if not node_names:
        return jsonify({
            'success': True,
            'nodes': {},
            'summary': {
                'total_updates': 0,
                'nodes_with_updates': 0,
                'total_nodes': 0,
                'checked_at': time.strftime('%Y-%m-%d %H:%M:%S')
            }
        })
    
    for node_name in node_names:
        # MK: Feb 2026 - Retry up to 2 times on failure, with clear error reporting
        max_retries = 2
        last_error = None
        for attempt in range(max_retries + 1):
            try:
                updates = mgr.get_node_apt_updates(node_name)
                
                if isinstance(updates, list):
                    update_list = updates
                elif isinstance(updates, dict):
                    update_list = updates.get('data', [])
                else:
                    update_list = []
                
                results[node_name] = {
                    'success': True,
                    'updates': update_list,
                    'count': len(update_list),
                    'retries': attempt
                }
                last_error = None
                break  # Success, no more retries
            except Exception as e:
                last_error = str(e)
                if attempt < max_retries:
                    logging.warning(f"[UpdateCheck] {node_name} attempt {attempt+1} failed: {e}, retrying...")
                    time.sleep(2)
        
        # LW: If all retries failed, show clear error state
        if last_error:
            logging.error(f"[UpdateCheck] {node_name} failed after {max_retries+1} attempts: {last_error}")
            results[node_name] = {
                'success': False,
                'error': last_error,
                'updates': [],
                'count': -1  # NS: -1 signals "check failed" vs 0 which means "no updates"
            }
    
    # MK: count > 0 for updates, ignore -1 (failed checks)
    total_updates = sum(max(r.get('count', 0), 0) for r in results.values())
    nodes_with_updates = sum(1 for r in results.values() if r.get('count', 0) > 0)
    nodes_failed = sum(1 for r in results.values() if not r.get('success', True))
    
    # LW: store timestamp so we can show when last checked
    mgr._last_update_check = time.strftime('%Y-%m-%d %H:%M:%S')
    
    return jsonify({
        'success': True,
        'nodes': results,
        'summary': {
            'total_updates': total_updates,
            'nodes_with_updates': nodes_with_updates,
            'nodes_failed': nodes_failed,
            'total_nodes': len(results),
            'checked_at': mgr._last_update_check
        }
    })


@bp.route('/api/clusters/<cluster_id>/updates/status', methods=['GET'])
@require_auth(perms=['node.view'])
def get_cluster_update_status(cluster_id):
    """Get cached update status for cluster"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    rolling_update = getattr(mgr, '_rolling_update', None)
    
    # Auto-clear completed/failed/cancelled status - NS Jan 2026
    if rolling_update and rolling_update.get('status') in ['completed', 'failed', 'cancelled']:
        completed_at = rolling_update.get('completed_at', '')
        if completed_at:
            try:
                from datetime import datetime
                completed_time = datetime.strptime(completed_at, '%Y-%m-%d %H:%M:%S')
                age_seconds = (datetime.now() - completed_time).total_seconds()
                # Auto-clear after 5 minutes for completed, 30 minutes for failed
                clear_after = 1800 if rolling_update.get('status') == 'failed' else 300
                if age_seconds > clear_after:
                    mgr._rolling_update = None
                    rolling_update = None
            except:
                # Invalid timestamp - clear it
                mgr._rolling_update = None
                rolling_update = None
        else:
            # No completed_at timestamp - this is legacy or broken data, clear it
            mgr._rolling_update = None
            rolling_update = None
    
    return jsonify({
        'success': True,
        'rolling_update': rolling_update,
        'last_check': getattr(mgr, '_last_update_check', None)
    })


@bp.route('/api/clusters/<cluster_id>/updates/rolling', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN], perms=['node.update'])
def start_rolling_update(cluster_id):
    """Start a rolling update across all cluster nodes
    
    MK: Fixed GitHub Issue - skip up-to-date nodes and configurable timeout
    
    Parameters (via JSON body):
    - include_reboot: bool - Whether to reboot nodes after update (default: False)
    - node_order: list - Custom order of nodes to update
    - skip_up_to_date: bool - Skip nodes that have no updates available (default: True)
    - force_all: bool - Force update all nodes even if up-to-date (default: False)
    - evacuation_timeout: int - Timeout in seconds for VM evacuation (default: 1800 = 30 min)
    - update_timeout: int - Timeout in seconds for apt upgrade (default: 900 = 15 min)
    - reboot_timeout: int - Timeout in seconds for node reboot (default: 600 = 10 min)
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    data = request.get_json() or {}
    
    # Configuration options
    include_reboot = data.get('include_reboot', False)
    node_order = data.get('node_order', None)
    skip_up_to_date = data.get('skip_up_to_date', True)
    force_all = data.get('force_all', False)
    skip_evacuation = data.get('skip_evacuation', False)  # MK: Issue #22 - skip VM evacuation (NOT RECOMMENDED)
    wait_for_reboot = data.get('wait_for_reboot', True)  # NS: GitHub #40
    pause_on_evacuation_error = data.get('pause_on_evacuation_error', True)  # NS: GitHub #40
    
    # MK: Configurable timeouts (GitHub Issue fix)
    evacuation_timeout = data.get('evacuation_timeout', 1800)  # 30 minutes default (was 5 min!)
    update_timeout = data.get('update_timeout', 900)  # 15 minutes default
    reboot_timeout = data.get('reboot_timeout', 600)  # 10 minutes default
    
    # Validate timeouts (min 60s, max 2 hours)
    evacuation_timeout = max(60, min(7200, int(evacuation_timeout)))
    update_timeout = max(60, min(7200, int(update_timeout)))
    reboot_timeout = max(60, min(7200, int(reboot_timeout)))
    
    # check already running
    if hasattr(mgr, '_rolling_update') and mgr._rolling_update and mgr._rolling_update.get('status') == 'running':
        return jsonify({'error': 'Rolling update already in progress'}), 400
    
    # Get nodes from cluster status
    try:
        node_status = mgr.get_node_status()
        available_nodes = list(node_status.keys()) if node_status else []
    except Exception as e:
        return jsonify({'error': f'Failed: cluster nodes: {str(e)}'}), 500
    
    if not available_nodes:
        return jsonify({'error': 'No nodes available for update'}), 400
    
    # Get nodes to update (use custom order or default)
    if node_order:
        nodes_to_update = [n for n in node_order if n in available_nodes]
    else:
        nodes_to_update = available_nodes
    
    if not nodes_to_update:
        return jsonify({'error': 'No nodes available for update'}), 400
    
    # init rolling update state
    mgr._rolling_update = {
        'status': 'running',
        'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'include_reboot': include_reboot,
        'skip_up_to_date': skip_up_to_date,
        'skip_evacuation': skip_evacuation,  # MK: Issue #22
        'wait_for_reboot': wait_for_reboot,  # NS: GitHub #40
        'pause_on_evacuation_error': pause_on_evacuation_error,  # NS: GitHub #40
        'force_all': force_all,
        'evacuation_timeout': evacuation_timeout,
        'update_timeout': update_timeout,
        'reboot_timeout': reboot_timeout,
        'nodes': nodes_to_update,
        'current_index': 0,
        'current_node': nodes_to_update[0],
        'current_step': 'starting',
        'completed_nodes': [],
        'skipped_nodes': [],  # MK: Track skipped nodes
        'failed_nodes': [],
        'rebooting_nodes': [],
        'paused_reason': None,
        'paused_details': None,
        'logs': []
    }
    
    # Start the rolling update in a background thread
    def run_rolling_update():
        try:
            logging.info(f"[RollingUpdate] Starting rolling update for cluster, nodes: {nodes_to_update}")
            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Rolling update started")
            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Settings: skip_up_to_date={skip_up_to_date}, skip_evacuation={skip_evacuation}, evacuation_timeout={evacuation_timeout}s")
            
            if skip_evacuation:
                mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ⚠️ WARNING: VM evacuation disabled - VMs may be affected if update fails!")
            
            for idx, node_name in enumerate(nodes_to_update):
                if not hasattr(mgr, '_rolling_update') or mgr._rolling_update.get('status') != 'running':
                    logging.info(f"[RollingUpdate] Update cancelled or stopped")
                    break
                
                mgr._rolling_update['current_index'] = idx
                mgr._rolling_update['current_node'] = node_name
                mgr._rolling_update['current_step'] = 'checking'
                mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] === Processing {node_name} ({idx+1}/{len(nodes_to_update)}) ===")
                logging.info(f"[RollingUpdate] Processing node: {node_name}")
                
                try:
                    # MK: Step 0 - Check if node has updates available (GitHub Issue fix)
                    if skip_up_to_date and not force_all:
                        mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Checking for available updates on {node_name}...")
                        
                        # First refresh apt cache
                        try:
                            mgr.refresh_node_apt(node_name)
                            time.sleep(3)  # Wait for refresh
                        except:
                            pass
                        
                        try:
                            available_updates = mgr.get_node_apt_updates(node_name)
                        except Exception as e:
                            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ⚠ Failed to check updates on {node_name}: {e}")
                            logging.warning(f"[RollingUpdate] Update check failed for {node_name}: {e}")
                            available_updates = []
                        update_count = len(available_updates) if available_updates else 0
                        
                        if update_count == 0:
                            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ⏭ {node_name} is already up-to-date - SKIPPING")
                            mgr._rolling_update['skipped_nodes'].append(node_name)
                            logging.info(f"[RollingUpdate] Node {node_name} is up-to-date, skipping")
                            continue
                        else:
                            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Found {update_count} updates available on {node_name}")
                            logging.info(f"[RollingUpdate] Node {node_name} has {update_count} updates available")
                    
                    # Step 1: Enable maintenance mode (evacuate VMs unless skip_evacuation is set)
                    mgr._rolling_update['current_step'] = 'maintenance'
                    if skip_evacuation:
                        mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Enabling maintenance mode on {node_name} (SKIP EVACUATION)")
                        logging.info(f"[RollingUpdate] Enabling maintenance mode on {node_name} (skip_evacuation=True)")
                    else:
                        mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Enabling maintenance mode on {node_name}")
                        logging.info(f"[RollingUpdate] Enabling maintenance mode on {node_name}")
                    
                    maintenance_task = mgr.enter_maintenance_mode(node_name, skip_evacuation=skip_evacuation)
                    
                    if not maintenance_task:
                        logging.error(f"[RollingUpdate] Failed to start maintenance mode on {node_name}")
                        raise Exception(f"Failed to start maintenance mode")
                    
                    # Wait for evacuation to complete (unless skipped)
                    if skip_evacuation:
                        mgr._rolling_update['current_step'] = 'updating'
                        mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ⚠️ Skipping VM evacuation - VMs remain on node")
                        evacuation_completed = True
                    else:
                        mgr._rolling_update['current_step'] = 'evacuating'
                        mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Waiting for VM evacuation (timeout: {evacuation_timeout}s)...")
                        waited = 0
                        evacuation_completed = False
                        last_progress_log = 0
                        
                        while waited < evacuation_timeout:
                            if mgr._rolling_update.get('status') not in ['running', 'paused']:
                                break
                            if node_name in mgr.nodes_in_maintenance:
                                maintenance_task = mgr.nodes_in_maintenance[node_name]
                                if maintenance_task.status == 'completed':
                                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ✓ Evacuation completed - all VMs migrated")
                                    evacuation_completed = True
                                    break
                                elif maintenance_task.status == 'completed_with_errors':
                                    failed_vm_list = getattr(maintenance_task, 'failed_vms', [])
                                    failed_names = [f"{v.get('name', 'VM')} (VMID: {v.get('vmid', '?')})" for v in failed_vm_list]
                                    migrated = getattr(maintenance_task, 'migrated_vms', 0)
                                    total = getattr(maintenance_task, 'total_vms', 0)
                                    mgr._rolling_update['logs'].append(
                                        f"[{time.strftime('%H:%M:%S')}] ⚠️ Evacuation: {migrated}/{total} migrated, {len(failed_vm_list)} failed")
                                    for fn in failed_names:
                                        mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}]   ✗ Failed: {fn}")
                                    
                                    if pause_on_evacuation_error:
                                        mgr._rolling_update['status'] = 'paused'
                                        mgr._rolling_update['current_step'] = 'paused_evacuation'
                                        mgr._rolling_update['paused_reason'] = 'evacuation_failures'
                                        mgr._rolling_update['paused_details'] = {
                                            'node': node_name, 'migrated': migrated, 'total': total,
                                            'failed_vms': [{'vmid': v.get('vmid'), 'name': v.get('name', 'VM'), 'error': v.get('error', '')} for v in failed_vm_list],
                                            'message': f"{len(failed_vm_list)} VM(s) failed to migrate from {node_name}. Manually migrate/shutdown these VMs, then click Continue or Cancel."
                                        }
                                        mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ⏸ PAUSED - Waiting for user action.")
                                        logging.warning(f"[RollingUpdate] Paused on {node_name}: {len(failed_vm_list)} VMs failed to migrate")
                                        while mgr._rolling_update.get('status') == 'paused':
                                            time.sleep(2)
                                        if mgr._rolling_update.get('status') == 'cancelled':
                                            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Rolling update cancelled by user during pause")
                                            break
                                        elif mgr._rolling_update.get('status') == 'running':
                                            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ▶ Resumed by user - continuing update on {node_name}")
                                            mgr._rolling_update['paused_reason'] = None
                                            mgr._rolling_update['paused_details'] = None
                                            evacuation_completed = True
                                            break
                                    else:
                                        mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ⚠️ Continuing despite failures (pause_on_evacuation_error=False)")
                                        evacuation_completed = True
                                        break
                                elif maintenance_task.status == 'failed':
                                    error_msg = getattr(maintenance_task, 'error', 'Unknown error')
                                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ✗ Evacuation failed: {error_msg}")
                                    raise Exception(f"Evacuation failed: {error_msg}")
                                else:
                                    if waited - last_progress_log >= 30:
                                        if hasattr(maintenance_task, 'migrated_vms') and hasattr(maintenance_task, 'total_vms'):
                                            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Evacuating: {maintenance_task.migrated_vms}/{maintenance_task.total_vms} VMs ({waited}s)")
                                        else:
                                            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Evacuation in progress... ({waited}s)")
                                        last_progress_log = waited
                            time.sleep(5)
                            waited += 5
                        if mgr._rolling_update.get('status') == 'cancelled':
                            break
                        if not evacuation_completed:
                            raise Exception(f"Evacuation timed out after {evacuation_timeout}s")
                    
                    # Step 2: Run apt update/upgrade
                    mgr._rolling_update['current_step'] = 'updating'
                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Installing updates on {node_name}")
                    logging.info(f"[RollingUpdate] Installing updates on {node_name}")
                    
                    update_task = mgr.start_node_update(node_name, reboot=include_reboot)
                    
                    if not update_task:
                        logging.error(f"[RollingUpdate] start_node_update returned None for {node_name}")
                        raise Exception(f"Update failed: Could not start update task")
                    
                    # Step 3: Wait for update task to complete
                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Waiting for update task (timeout: {update_timeout}s)...")
                    update_waited = 0
                    last_phase = None
                    while update_waited < update_timeout:
                        if update_task.status in ['completed', 'failed']:
                            break
                        # Log phase changes
                        if hasattr(update_task, 'phase') and update_task.phase != last_phase:
                            last_phase = update_task.phase
                            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Update phase: {last_phase}")
                        time.sleep(10)
                        update_waited += 10
                    
                    if update_task.status == 'failed':
                        raise Exception(f"Update failed: {update_task.error or 'Unknown error'}")
                    
                    if update_task.status != 'completed':
                        raise Exception(f"Update timed out after {update_timeout}s (status: {update_task.status})")
                    
                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ✓ Updates installed")
                    
                    # Step 4: If reboot was included, wait for node to come back
                    if include_reboot:
                        mgr._rolling_update['current_step'] = 'rebooting'
                        mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Node {node_name} rebooting (timeout: {reboot_timeout}s)...")
                        if 'rebooting_nodes' not in mgr._rolling_update:
                            mgr._rolling_update['rebooting_nodes'] = []
                        mgr._rolling_update['rebooting_nodes'].append(node_name)
                        
                        # Phase 1: Wait for offline
                        offline_waited = 0
                        node_went_offline = False
                        while offline_waited < 120:
                            try:
                                ns = mgr.get_node_status()
                                if node_name not in ns or ns[node_name].get('status') != 'online':
                                    node_went_offline = True
                                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] {node_name} is now offline")
                                    break
                            except:
                                node_went_offline = True
                                break
                            time.sleep(5)
                            offline_waited += 5
                        
                        if not node_went_offline:
                            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ⚠️ {node_name} did not go offline within 120s")
                        
                        if wait_for_reboot:
                            # Phase 2: Wait for online
                            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Waiting for {node_name} to come back online...")
                            waited = 0
                            node_back_online = False
                            while waited < reboot_timeout:
                                if mgr._rolling_update.get('status') == 'cancelled':
                                    break
                                try:
                                    ns = mgr.get_node_status()
                                    if node_name in ns and ns[node_name].get('status') == 'online':
                                        node_back_online = True
                                        mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ✓ {node_name} back online ({waited}s)")
                                        if node_name in mgr._rolling_update.get('rebooting_nodes', []):
                                            mgr._rolling_update['rebooting_nodes'].remove(node_name)
                                        time.sleep(10)
                                        break
                                except:
                                    pass
                                time.sleep(10)
                                waited += 10
                                if waited % 60 == 0:
                                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Still waiting for {node_name} ({waited}s/{reboot_timeout}s)...")
                            
                            if not node_back_online and mgr._rolling_update.get('status') != 'cancelled':
                                mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ✗ {node_name} reboot timeout ({reboot_timeout}s). Pausing.")
                                mgr._rolling_update['status'] = 'paused'
                                mgr._rolling_update['current_step'] = 'paused_reboot'
                                mgr._rolling_update['paused_reason'] = 'reboot_timeout'
                                mgr._rolling_update['paused_details'] = {
                                    'node': node_name, 'timeout': reboot_timeout,
                                    'message': f"{node_name} did not come back online within {reboot_timeout}s. Check manually, then Continue or Cancel."
                                }
                                while mgr._rolling_update.get('status') == 'paused':
                                    time.sleep(2)
                                if mgr._rolling_update.get('status') == 'cancelled':
                                    break
                                elif mgr._rolling_update.get('status') == 'running':
                                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ▶ Resumed after reboot timeout")
                                    mgr._rolling_update['paused_reason'] = None
                                    mgr._rolling_update['paused_details'] = None
                                    if node_name in mgr._rolling_update.get('rebooting_nodes', []):
                                        mgr._rolling_update['rebooting_nodes'].remove(node_name)
                        else:
                            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Not waiting for {node_name} (wait_for_reboot=False)")
                    
                    if mgr._rolling_update.get('status') == 'cancelled':
                        break
                    
                    # Step 5: Disable maintenance mode
                    mgr._rolling_update['current_step'] = 'finishing'
                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Disabling maintenance mode on {node_name}")
                    mgr.exit_maintenance_mode(node_name)
                    
                    mgr._rolling_update['completed_nodes'].append(node_name)
                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ✓ {node_name} updated successfully")
                    logging.info(f"[RollingUpdate] Node {node_name} updated successfully")
                    
                except Exception as e:
                    logging.error(f"[RollingUpdate] Error updating {node_name}: {e}")
                    mgr._rolling_update['failed_nodes'].append({'node': node_name, 'error': str(e)})
                    mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ✗ ERROR on {node_name}: {e}")
                    # Try to exit maintenance mode even if update failed
                    try:
                        mgr.exit_maintenance_mode(node_name)
                    except:
                        pass
            
            # Final summary
            completed = len(mgr._rolling_update['completed_nodes'])
            skipped = len(mgr._rolling_update['skipped_nodes'])
            failed = len(mgr._rolling_update['failed_nodes'])
            
            mgr._rolling_update['status'] = 'completed'
            mgr._rolling_update['completed_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] === Rolling update completed ===")
            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Summary: {completed} updated, {skipped} skipped (up-to-date), {failed} failed")
            logging.info(f"[RollingUpdate] Rolling update completed: {completed} updated, {skipped} skipped, {failed} failed")
            
        except Exception as e:
            logging.error(f"[RollingUpdate] Rolling update failed with exception: {e}")
            mgr._rolling_update['status'] = 'failed'
            mgr._rolling_update['completed_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
            mgr._rolling_update['error'] = str(e)
            mgr._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Rolling update failed: {e}")
    
    import threading
    update_thread = threading.Thread(target=run_rolling_update, daemon=True)
    update_thread.start()
    
    return jsonify({
        'success': True,
        'message': 'Rolling update started',
        'nodes': nodes_to_update,
        'include_reboot': include_reboot,
        'skip_up_to_date': skip_up_to_date,
        'evacuation_timeout': evacuation_timeout,
        'update_timeout': update_timeout,
        'reboot_timeout': reboot_timeout
    })


@bp.route('/api/clusters/<cluster_id>/updates/rolling', methods=['DELETE'])
@require_auth(roles=[ROLE_ADMIN])
def cancel_rolling_update(cluster_id):
    """Cancel a running rolling update"""
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    
    if not hasattr(manager, '_rolling_update') or not manager._rolling_update:
        return jsonify({'error': 'No rolling update in progress'}), 400
    
    manager._rolling_update['status'] = 'cancelled'
    manager._rolling_update['completed_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
    manager._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] Rolling update cancelled by user")
    
    # Try to exit maintenance mode on current node
    current_node = manager._rolling_update.get('current_node')
    if current_node:
        try:
            manager.exit_maintenance_mode(current_node)
        except:
            pass
    
    return jsonify({'success': True, 'message': 'Rolling update cancelled'})


@bp.route('/api/clusters/<cluster_id>/updates/rolling/resume', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def resume_rolling_update(cluster_id):
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    manager = cluster_managers[cluster_id]
    if not hasattr(manager, '_rolling_update') or not manager._rolling_update:
        return jsonify({'error': 'No rolling update in progress'}), 400
    if manager._rolling_update.get('status') != 'paused':
        return jsonify({'error': f"Not paused (status: {manager._rolling_update.get('status')})"}), 400
    paused_reason = manager._rolling_update.get('paused_reason', 'unknown')
    manager._rolling_update['status'] = 'running'
    manager._rolling_update['logs'].append(f"[{time.strftime('%H:%M:%S')}] ▶ Resumed (was: {paused_reason})")
    return jsonify({'success': True, 'message': 'Resumed', 'was_paused_for': paused_reason})


@bp.route('/api/clusters/<cluster_id>/updates/rolling/clear', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def clear_rolling_update_status(cluster_id):
    """Clear completed/cancelled rolling update status (dismiss notification)"""
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    manager = cluster_managers[cluster_id]
    
    if hasattr(manager, '_rolling_update') and manager._rolling_update:
        status = manager._rolling_update.get('status', '')
        # Only clear if not currently running
        if status in ['completed', 'cancelled', 'failed']:
            manager._rolling_update = None
            return jsonify({'success': True, 'message': 'Status cleared'})
        else:
            return jsonify({'error': 'Cannot clear running update'}), 400
    
    return jsonify({'success': True, 'message': 'Nothing to clear'})



# ============================================
# APT Repository Management
# APT repo management per node
# ============================================

# Standard Proxmox repositories
# Note: Proxmox 8.x uses .sources files (DEB822 format) instead of .list
# The API handles both formats, we match by URI
PROXMOX_REPOS = {
    'pve-enterprise': {
        'name': 'Proxmox VE Enterprise',
        'file': '/etc/apt/sources.list.d/pve-enterprise.list',  # Legacy
        'sources_file': '/etc/apt/sources.list.d/pve-enterprise.sources',  # New format
        'line': 'deb https://enterprise.proxmox.com/debian/pve bookworm pve-enterprise',
        'description': 'Stable enterprise repository (requires subscription)',
        'requires_subscription': True,
        'match_uri': 'enterprise.proxmox.com/debian/pve'
    },
    'pve-no-subscription': {
        'name': 'Proxmox VE No-Subscription',
        'file': '/etc/apt/sources.list.d/pve-no-subscription.list',
        'sources_file': '/etc/apt/sources.list.d/pve-no-subscription.sources',
        'line': 'deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription',
        'description': 'Testing/community repository (no subscription required)',
        'requires_subscription': False,
        'match_uri': 'download.proxmox.com/debian/pve'
    },
    'ceph-squid': {
        'name': 'Ceph Squid (19.x)',
        'file': '/etc/apt/sources.list.d/ceph.list',
        'sources_file': '/etc/apt/sources.list.d/ceph.sources',
        'line': 'deb http://download.proxmox.com/debian/ceph-squid bookworm no-subscription',
        'description': 'Ceph Squid storage repository (newest)',
        'requires_subscription': False,
        'match_uri': 'ceph-squid'
    },
    'ceph-reef': {
        'name': 'Ceph Reef (18.x)',
        'file': '/etc/apt/sources.list.d/ceph.list',
        'sources_file': '/etc/apt/sources.list.d/ceph.sources',
        'line': 'deb http://download.proxmox.com/debian/ceph-reef bookworm no-subscription',
        'description': 'Ceph Reef storage repository',
        'requires_subscription': False,
        'match_uri': 'ceph-reef'
    },
    'ceph-quincy': {
        'name': 'Ceph Quincy (17.x)',
        'file': '/etc/apt/sources.list.d/ceph.list',
        'sources_file': '/etc/apt/sources.list.d/ceph.sources',
        'line': 'deb http://download.proxmox.com/debian/ceph-quincy bookworm no-subscription',
        'description': 'Ceph Quincy storage repository (older)',
        'requires_subscription': False,
        'match_uri': 'ceph-quincy'
    },
    'ceph-enterprise': {
        'name': 'Ceph Enterprise',
        'file': '/etc/apt/sources.list.d/ceph.list',
        'sources_file': '/etc/apt/sources.list.d/ceph.sources',
        'line': 'deb https://enterprise.proxmox.com/debian/ceph-squid bookworm enterprise',
        'description': 'Ceph Enterprise repository (requires subscription)',
        'requires_subscription': True,
        'match_uri': 'enterprise.proxmox.com/debian/ceph'
    }
}


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/repos', methods=['GET'])
@require_auth(perms=['node.view'])
def get_node_repos(cluster_id, node):
    """Get APT repository configuration for a node
    
    MK: Fixed to match by full URI path, not just domain
    e.g. /debian/pve vs /debian/ceph-reef
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    try:
        host = mgr.current_host or mgr.config.host
        
        # Get all repos via Proxmox API
        file_url = f"https://{host}:8006/api2/json/nodes/{node}/apt/repositories"
        r = mgr._create_session().get(file_url, timeout=10)
        
        if r.status_code != 200:
            return jsonify({'error': 'Failed to get repositories from Proxmox API'}), 500
        
        api_data = r.json().get('data', {})
        api_files = api_data.get('files', [])
        
        logging.debug(f"[REPOS] Got {len(api_files)} files from Proxmox API for node {node}")
        for f in api_files:
            logging.debug(f"[REPOS] File: {f.get('path')} with {len(f.get('repositories', []))} repos")
        
        repos = []
        
        # Check each known repo
        for repo_id, repo_info in PROXMOX_REPOS.items():
            repo_data = {
                'id': repo_id,
                'name': repo_info['name'],
                'description': repo_info['description'],
                'file': repo_info['file'],  # Expected file (may differ from actual)
                'actual_file': None,  # Where we actually found it
                'expected_line': repo_info['line'],
                'requires_subscription': repo_info.get('requires_subscription', False),
                'enabled': False,
                'exists': False,
                'content': None,
                'index': None  # Index within the file for toggle
            }
            
            # Use the match_uri if defined, otherwise parse from line
            match_uri = repo_info.get('match_uri', '')
            if not match_uri:
                expected_parts = repo_info['line'].split()
                expected_url = expected_parts[1] if len(expected_parts) > 1 else ''
                url_without_proto = expected_url.replace('https://', '').replace('http://', '')
                url_parts = url_without_proto.split('/')
                match_uri = '/'.join(url_parts[:3]) if len(url_parts) >= 3 else url_without_proto
            
            logging.debug(f"[REPOS] Looking for {repo_id}: match_uri={match_uri}")
            
            # Search in ALL files
            for file_info in api_files:
                file_path = file_info.get('path', '')
                
                for idx, repo_entry in enumerate(file_info.get('repositories', [])):
                    repo_uris = repo_entry.get('URIs', [])
                    
                    for uri in repo_uris:
                        uri_clean = uri.replace('https://', '').replace('http://', '')
                        
                        # Match by the match_uri string
                        if match_uri in uri_clean:
                            repo_data['exists'] = True
                            repo_data['actual_file'] = file_path
                            repo_data['index'] = idx
                            
                            # Proxmox API: Enabled is 1 for enabled, 0 for disabled
                            enabled_val = repo_entry.get('Enabled')
                            if enabled_val is None:
                                repo_data['enabled'] = True
                            else:
                                repo_data['enabled'] = (enabled_val == 1)
                            
                            repo_data['content'] = repo_entry
                            repo_data['file'] = file_path
                            logging.info(f"[REPOS] Found {repo_id} in {file_path}[{idx}]: enabled={repo_data['enabled']}, uri={uri}")
                            break
                    
                    if repo_data['exists']:
                        break
                
                if repo_data['exists']:
                    break
            
            repos.append(repo_data)
        
        # Also add any other Proxmox-related repos found that we don't have defined
        # This helps when Proxmox adds new repos
        known_uris = set()
        for repo_info in PROXMOX_REPOS.values():
            known_uris.add(repo_info.get('match_uri', ''))
        
        for file_info in api_files:
            file_path = file_info.get('path', '')
            
            for idx, repo_entry in enumerate(file_info.get('repositories', [])):
                repo_uris = repo_entry.get('URIs', [])
                
                for uri in repo_uris:
                    uri_clean = uri.replace('https://', '').replace('http://', '')
                    
                    # Only show Proxmox-related repos that aren't already in our list
                    if ('proxmox.com' in uri_clean or 'download.proxmox' in uri_clean):
                        # Check if this is already covered by known repos
                        already_known = any(known_uri in uri_clean for known_uri in known_uris if known_uri)
                        
                        if not already_known:
                            # This is an unknown Proxmox repo - show it
                            enabled_val = repo_entry.get('Enabled')
                            is_enabled = enabled_val == 1 if enabled_val is not None else True
                            
                            # Generate a unique ID
                            repo_id_other = f"other-{hash(uri) % 10000}"
                            
                            repos.append({
                                'id': repo_id_other,
                                'name': uri_clean.split('/')[0],  # Domain as name
                                'description': f'Found in {file_path}',
                                'file': file_path,
                                'actual_file': file_path,
                                'expected_line': f"deb {uri}",
                                'requires_subscription': 'enterprise' in uri_clean.lower(),
                                'enabled': is_enabled,
                                'exists': True,
                                'content': repo_entry,
                                'index': idx,
                                'uri': uri,
                                'is_other': True  # Flag for UI
                            })
        
        return jsonify({
            'success': True,
            'node': node,
            'repositories': repos
        })
        
    except Exception as e:
        logging.error(f"Failed to get repositories: {e}")
        return jsonify({'error': f'Failed to get repositories: {str(e)}'}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/repos/<repo_id>', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN], perms=['node.update'])
def update_node_repo(cluster_id, node, repo_id):
    """Enable or disable a repository on a node
    
    MK: Fixed to match by full URI path, not just domain
    NS: Extended to support "other" repos by file path and index
    """
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    data = request.get_json() or {}
    enabled = data.get('enabled', True)
    
    # Check if this is a known repo or an "other" repo
    if repo_id.startswith('other-'):
        # For "other" repos, we need the file path and index from the request
        file_path = data.get('file')
        repo_index = data.get('index')
        
        if file_path is None or repo_index is None:
            return jsonify({'error': 'file and index required for custom repository toggle'}), 400
        
        repo_name = data.get('name', repo_id)
    elif repo_id not in PROXMOX_REPOS:
        return jsonify({'error': f'Unknown repository: {repo_id}'}), 400
    else:
        repo_info = PROXMOX_REPOS[repo_id]
        repo_name = repo_info['name']
    
    try:
        host = mgr.current_host or mgr.config.host
        
        # Use Proxmox API to modify repository
        url = f"https://{host}:8006/api2/json/nodes/{node}/apt/repositories"
        
        # For known repos, we need to find them first
        if not repo_id.startswith('other-'):
            # First get current repos to find the index
            r = mgr._create_session().get(url, timeout=10)
            if r.status_code != 200:
                return jsonify({'error': 'Failed to get current repositories'}), 500
            
            api_repos = r.json().get('data', {})
            
            # Use match_uri for consistent matching
            match_uri = repo_info.get('match_uri', '')
            if not match_uri:
                expected_parts = repo_info['line'].split()
                expected_url = expected_parts[1] if len(expected_parts) > 1 else ''
                url_without_proto = expected_url.replace('https://', '').replace('http://', '')
                url_parts = url_without_proto.split('/')
                match_uri = '/'.join(url_parts[:3]) if len(url_parts) >= 3 else url_without_proto
            
            # Find the repo in ANY file
            repo_index = None
            found_file_path = None
            
            for file_info in api_repos.get('files', []):
                current_path = file_info.get('path', '')
                
                for idx, repo_entry in enumerate(file_info.get('repositories', [])):
                    repo_uris = repo_entry.get('URIs', [])
                    for uri in repo_uris:
                        uri_clean = uri.replace('https://', '').replace('http://', '')
                        # Match by match_uri
                        if match_uri in uri_clean:
                            repo_index = idx
                            found_file_path = current_path
                            logging.info(f"[REPOS] Found {repo_id} at index {idx} in {current_path}")
                            break
                    if repo_index is not None:
                        break
                if repo_index is not None:
                    break
            
            if repo_index is None:
                return jsonify({
                    'error': 'Repository not found. Manual setup required.',
                    'hint': f'Add the repository to /etc/apt/sources.list or create {repo_info["file"]}'
                }), 400
        else:
            # For "other" repos, we already have file_path and repo_index from the request
            found_file_path = file_path
        
        # Toggle the repo
        toggle_url = f"https://{host}:8006/api2/json/nodes/{node}/apt/repositories"
        payload = {
            'path': found_file_path,
            'index': repo_index,
            'enabled': 1 if enabled else 0
        }
        
        logging.info(f"[REPOS] Toggling {repo_id}: path={found_file_path}, index={repo_index}, enabled={enabled}")
        
        r = mgr._create_session().post(toggle_url, data=payload, timeout=10)
        
        if r.status_code in [200, 204]:
            action = 'enabled' if enabled else 'disabled'
            log_audit(request.session['user'], 'node.repo.updated', 
                     f"Repository {repo_name} {action} on {node}")
            
            return jsonify({
                'success': True,
                'message': f"Repository {repo_name} {action}",
                'repo': repo_id,
                'enabled': enabled
            })
        else:
            return jsonify({
                'error': f'Failed to update repository: {r.status_code}',
                'details': r.text
            }), 500
        
    except Exception as e:
        return jsonify({'error': f'Failed to update repository: {str(e)}'}), 500


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/repos/refresh', methods=['POST'])
@require_auth(perms=['node.update'])
def refresh_node_repos(cluster_id, node):
    """Run apt update on a node to refresh package lists"""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    
    mgr = cluster_managers[cluster_id]
    
    try:
        host = mgr.current_host or mgr.config.host
        url = f"https://{host}:8006/api2/json/nodes/{node}/apt/update"
        
        r = mgr._create_session().post(url, timeout=30)
        
        if r.status_code == 200:
            task_id = r.json().get('data')
            return jsonify({
                'success': True,
                'message': 'Package list refresh started',
                'task_id': task_id
            })
        else:
            return jsonify({'error': f'Failed to refresh: {r.status_code}'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Failed to refresh repositories: {str(e)}'}), 500


@bp.route('/api/timezones', methods=['GET'])
def get_timezones_api():
    """Get list of available timezones"""
    # Return a static list - works for any cluster
    return jsonify([
        'UTC', 'Europe/Berlin', 'Europe/Vienna', 'Europe/Zurich', 'Europe/London',
        'Europe/Paris', 'Europe/Amsterdam', 'Europe/Brussels', 'Europe/Rome',
        'Europe/Madrid', 'Europe/Warsaw', 'Europe/Prague', 'Europe/Budapest',
        'America/New_York', 'America/Chicago', 'America/Los_Angeles',
        'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Singapore',
        'Australia/Sydney', 'Pacific/Auckland',
    ])


# ==================== END NODE MANAGEMENT API ENDPOINTS ====================

# ============================================
# WebSocket Live Updates
# ============================================

# =====================================================
# MK: Feb 2026 - LDAP Test Connection
# =====================================================

@bp.route('/api/settings/ldap/test', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def test_ldap():
    """Test LDAP connection and optionally test user authentication"""
    data = request.json or {}
    
    # NS: Build config from request data (for testing before save)
    saved = load_server_settings()
    
    config = {
        'enabled': True,  # Force enabled for test
        'server': data.get('ldap_server', saved.get('ldap_server', '')),
        'port': int(data.get('ldap_port', saved.get('ldap_port', 389))),
        'use_ssl': data.get('ldap_use_ssl', saved.get('ldap_use_ssl', False)),
        'use_starttls': data.get('ldap_use_starttls', saved.get('ldap_use_starttls', False)),
        'bind_dn': data.get('ldap_bind_dn', saved.get('ldap_bind_dn', '')),
        'bind_password': data.get('ldap_bind_password', ''),
        'base_dn': data.get('ldap_base_dn', saved.get('ldap_base_dn', '')),
        'user_filter': data.get('ldap_user_filter', saved.get('ldap_user_filter', '(&(objectClass=person)(sAMAccountName={username}))')),
        'username_attribute': data.get('ldap_username_attribute', saved.get('ldap_username_attribute', 'sAMAccountName')),
        'email_attribute': data.get('ldap_email_attribute', saved.get('ldap_email_attribute', 'mail')),
        'display_name_attribute': data.get('ldap_display_name_attribute', saved.get('ldap_display_name_attribute', 'displayName')),
    }
    
    # Use saved password if masked
    if not config['bind_password'] or config['bind_password'] == '********':
        config['bind_password'] = get_db()._decrypt(saved.get('ldap_bind_password', ''))  # MK: Decrypt stored credential
    
    if not config['server']:
        return jsonify({'error': 'LDAP server is required'}), 400
    
    try:
        import ldap3
        from ldap3 import Server, Connection, ALL, SUBTREE, Tls
        from ldap3.utils.conv import escape_filter_chars
        import ssl as ssl_module
    except ImportError:
        return jsonify({'error': 'ldap3 module not installed. Run: pip install ldap3'}), 500
    
    results = {'steps': []}
    
    try:
        # Step 1: Connect to server
        tls_config = None
        if config['use_ssl'] or config['use_starttls']:
            tls_config = Tls(validate=ssl_module.CERT_NONE)
        
        server = Server(config['server'], port=config['port'], 
                       use_ssl=config['use_ssl'], tls=tls_config, 
                       get_info=ALL, connect_timeout=10)
        
        # Step 2: Bind with service account
        # NS: same fix as ldap_authenticate - starttls before bind!!
        use_starttls = config['use_starttls'] and not config['use_ssl']
        
        if config['bind_dn'] and config['bind_password']:
            conn = Connection(server, user=config['bind_dn'], password=config['bind_password'],
                            raise_exceptions=True)
        else:
            conn = Connection(server, raise_exceptions=True)
        
        try:
            conn.open()
            # Issue #70: Report "Server connection" AFTER conn.open() -- Server() doesn't actually connect
            results['steps'].append({'step': 'Server connection', 'status': 'ok', 'detail': f"{config['server']}:{config['port']}"})
            
            if use_starttls:
                conn.start_tls()
                results['steps'].append({'step': 'STARTTLS', 'status': 'ok'})
            
            conn.bind()
            
            if config['bind_dn'] and config['bind_password']:
                results['steps'].append({'step': 'Service account bind', 'status': 'ok', 'detail': config['bind_dn']})
            else:
                results['steps'].append({'step': 'Anonymous bind', 'status': 'ok'})
            
            # Step 3: Search base DN
            if config['base_dn']:
                conn.search(config['base_dn'], '(objectClass=*)', search_scope='BASE', attributes=['objectClass'])  # Issue #70: 'dn' is not a valid attribute
                results['steps'].append({'step': 'Base DN accessible', 'status': 'ok', 'detail': config['base_dn']})
            
            # Step 4: Optional - test user search
            test_username = data.get('test_username', '')
            if test_username and config['base_dn']:
                user_filter = config['user_filter'].replace('{username}', escape_filter_chars(test_username))
                conn.search(config['base_dn'], user_filter, search_scope=SUBTREE,
                           attributes=[config['username_attribute'], config['email_attribute'], 
                                      config['display_name_attribute'], 'memberOf'])
                
                if conn.entries:
                    entry = conn.entries[0]
                    user_info = {
                        'dn': str(entry.entry_dn),
                        'email': str(entry[config['email_attribute']]) if config['email_attribute'] in entry else '',
                        'display_name': str(entry[config['display_name_attribute']]) if config['display_name_attribute'] in entry else '',
                        'groups': len(entry['memberOf']) if 'memberOf' in entry else 0
                    }
                    results['steps'].append({'step': f'User search: {test_username}', 'status': 'ok', 'detail': user_info})
                else:
                    results['steps'].append({'step': f'User search: {test_username}', 'status': 'warning', 'detail': 'User not found'})
            
            # LW: Get server info
            results['server_info'] = {
                'vendor': str(server.info.vendor_name) if server.info and server.info.vendor_name else 'Unknown',
                'naming_contexts': [str(nc) for nc in (server.info.naming_contexts or [])] if server.info else [],
            }
            
            results['success'] = True
            results['message'] = 'LDAP connection successful'
            
        finally:
            # Issue #70: Always clean up connection, even on error
            try:
                conn.unbind()
            except Exception:
                pass
        
    except Exception as e:
        results['success'] = False
        results['error'] = str(e)
        # Issue #70: Identify which step failed based on what succeeded so far
        completed = [s['step'] for s in results['steps']]
        if 'Server connection' not in completed:
            failed_step = 'Server connection'
        elif not any('bind' in s.lower() for s in completed):
            failed_step = 'Bind'
        elif 'Base DN accessible' not in completed and config.get('base_dn'):
            failed_step = 'Base DN search'
        else:
            failed_step = 'Connection'
        results['steps'].append({'step': failed_step, 'status': 'error', 'detail': str(e)})
    
    return jsonify(results)



