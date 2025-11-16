#!/usr/bin/env python3
"""
InstaChecker — single-file interactive CLI to analyze Instagram mutual follows.

Behavior change:
- If core dependencies (instaloader, rich, questionary) are missing the script will automatically
  install them into the current Python environment (no prompts).
- Optional dependencies (cryptography, keyring) remain optional and are installed on demand
  only if the user enables encryption/keyring flows (the script may ask to install them then).
Notes:
- Automatic installation modifies the current environment. Run inside a virtualenv you control.
- The script uses pip via the same Python interpreter (sys.executable -m pip).
"""
from __future__ import annotations
import sys
import os
import json
import re
import tempfile
import subprocess
from pathlib import Path
from typing import Optional, Dict, Tuple, List
import importlib

# -----------------------
# Auto-install helper for core packages (no prompts)
# -----------------------
def _pip_install(packages: List[str]) -> None:
    """
    Install packages via pip into the current interpreter, non-interactively.
    Errors will be raised if installation fails.
    """
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "--disable-pip-version-check", "--no-input", "-q"] + packages
    # Use check_call so error bubbles up
    subprocess.check_call(cmd)

def ensure_core_packages_auto(pkgs: List[str]) -> None:
    """
    Ensure the given package names can be imported; if not, install them automatically
    (no user prompt), then re-import.
    pkgs: list of top-level import names (e.g. ["instaloader","rich","questionary"])
    """
    missing = []
    for name in pkgs:
        try:
            importlib.import_module(name)
        except Exception:
            missing.append(name)
    if not missing:
        return
    # Attempt auto-install silently
    try:
        _pip_install(missing)
    except subprocess.CalledProcessError as e:
        print(f"Automatic installation of required packages failed: {e}", file=sys.stderr)
        print("Install them manually, e.g.: pip install " + " ".join(missing), file=sys.stderr)
        sys.exit(1)
    # re-import to ensure availability
    for name in missing:
        try:
            importlib.import_module(name)
        except Exception as e:
            print(f"Failed to import {name} after installation: {e}", file=sys.stderr)
            sys.exit(1)

# Ensure core dependencies (instaloader, rich, questionary) are present (auto-install)
ensure_core_packages_auto(["instaloader", "rich", "questionary"])

# Now safe to import core libs
import instaloader
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
import questionary

console = Console()
DEFAULT_SESSION_STORE = Path("session_store.json")

# -----------------------
# Utilities
# -----------------------
def normalize_username(raw: str) -> str:
    if not raw:
        raise ValueError("Пустой ввод.")
    s = raw.strip()
    s = s.strip("<>")
    if s.startswith("@"):
        s = s[1:].strip()
    m = re.match(r"^(?:https?://)?(?:www\.)?instagram\.com/([^/?#]+)", s, flags=re.I)
    if m:
        s = m.group(1)
    s = s.split("?")[0].split("/")[0]
    s = s.strip()
    if not re.match(r"^[A-Za-z0-9._]+$", s):
        raise ValueError("Неверный формат username.")
    return s


def chunked(lst: List, n: int):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


# -----------------------
# Session store (optional encryption)
# -----------------------
_ENCRYPTION_AVAILABLE = False
try:
    import base64
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
    from cryptography.hazmat.primitives import hashes  # type: ignore
    from cryptography.fernet import Fernet  # type: ignore
    from cryptography.hazmat.backends import default_backend  # type: ignore
    import secrets
    _ENCRYPTION_AVAILABLE = True
except Exception:
    _ENCRYPTION_AVAILABLE = False

class EncryptionNotAvailableError(RuntimeError):
    pass

class SessionStore:
    def __init__(self, path: Path = DEFAULT_SESSION_STORE):
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.exists()

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        if not _ENCRYPTION_AVAILABLE:
            raise EncryptionNotAvailableError("cryptography not available")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200_000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def load(self, master_password: Optional[str] = None) -> Dict:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not raw.get("encrypted"):
            return raw.get("data", {})
        if not _ENCRYPTION_AVAILABLE:
            raise EncryptionNotAvailableError("cryptography not installed; cannot decrypt session store.")
        salt_b64 = raw.get("salt")
        token_b64 = raw.get("data")
        if not salt_b64 or not token_b64:
            raise RuntimeError("Неверный формат хранилища.")
        salt = base64.b64decode(salt_b64)
        key = self._derive_key(master_password, salt)
        f = Fernet(key)
        try:
            decrypted = f.decrypt(token_b64.encode())
        except Exception:
            raise RuntimeError("Не удалось расшифровать хранилище: неверный пароль.")
        return json.loads(decrypted.decode("utf-8"))

    def save(self, data: Dict, master_password: Optional[str] = None):
        if master_password:
            if not _ENCRYPTION_AVAILABLE:
                raise EncryptionNotAvailableError("cryptography not installed; cannot encrypt session store.")
            salt = secrets.token_bytes(16)
            key = self._derive_key(master_password, salt)
            f = Fernet(key)
            token = f.encrypt(json.dumps(data).encode("utf-8"))
            to_store = {
                "encrypted": True,
                "salt": base64.b64encode(salt).decode("ascii"),
                "data": token.decode()
            }
        else:
            to_store = {
                "encrypted": False,
                "data": data
            }
        self.path.write_text(json.dumps(to_store, ensure_ascii=False, indent=2), encoding="utf-8")


# -----------------------
# Keyring helpers (optional)
# -----------------------
_KEYRING_AVAILABLE = False
try:
    import keyring
    _KEYRING_AVAILABLE = True
except Exception:
    _KEYRING_AVAILABLE = False

SERVICE = "instachecker"

def keyring_available() -> bool:
    return _KEYRING_AVAILABLE

def keyring_get_master(account: Optional[str] = None) -> Optional[str]:
    if not _KEYRING_AVAILABLE:
        return None
    acct = account or os.getlogin()
    try:
        return keyring.get_password(SERVICE, acct)
    except Exception:
        return None

def keyring_set_master(password: str, account: Optional[str] = None) -> bool:
    if not _KEYRING_AVAILABLE:
        return False
    acct = account or os.getlogin()
    try:
        keyring.set_password(SERVICE, acct, password)
        return True
    except Exception:
        return False


# -----------------------
# Instagram client
# -----------------------
class InstagramClient:
    def __init__(self, session_store_path: Path = DEFAULT_SESSION_STORE):
        self.L = instaloader.Instaloader(download_pictures=False,
                                         download_videos=False,
                                         download_video_thumbnails=False,
                                         save_metadata=False,
                                         compress_json=False)
        self.session_store = SessionStore(path=session_store_path)
        self._logged_in_user: Optional[str] = None

    @property
    def is_logged_in(self) -> bool:
        return self._logged_in_user is not None

    def has_saved_session(self) -> bool:
        if any(Path(".").glob("*.session")):
            return True
        return self.session_store.exists()

    def load_saved_session(self, master_password: Optional[str] = None):
        # try encrypted store first
        if self.session_store.exists():
            try:
                data = self.session_store.load(master_password=master_password)
                if data:
                    username = list(data.keys())[-1]
                    session_bytes = data[username].get("session_bytes")
                    if session_bytes:
                        with tempfile.NamedTemporaryFile(delete=False) as tf:
                            tf.write(session_bytes.encode("latin1"))
                            tmp_name = tf.name
                        try:
                            try:
                                self.L.load_session_from_file(username, filename=Path(tmp_name))
                            except TypeError:
                                self.L.load_session_from_file(username)
                            self._logged_in_user = username
                            return
                        finally:
                            try:
                                os.unlink(tmp_name)
                            except Exception:
                                pass
            except EncryptionNotAvailableError:
                raise
            except Exception:
                # fallback to plain .session
                pass

        # fallback: plain .session file
        for p in Path(".").glob("*.session"):
            username = p.stem
            try:
                try:
                    self.L.load_session_from_file(username, filename=p)
                except TypeError:
                    self.L.load_session_from_file(username)
                self._logged_in_user = username
                return
            except Exception:
                continue
        raise RuntimeError("Файл сессии не найден.")

    def login(self, username: str, password: str, save_session: bool = True, master_password: Optional[str] = None):
        # Note: instaloader may raise for 2FA or checkpoint
        self.L.login(username, password)
        self._logged_in_user = username
        # save to .session file (Instaloader default)
        try:
            self.L.save_session_to_file()
        except Exception:
            try:
                self.L.context.save_session_to_file()
            except Exception:
                pass
        # store encrypted session blob if requested and cryptography available
        if save_session:
            session_file = Path(f"{username}.session")
            if session_file.exists():
                data = session_file.read_bytes()
                try:
                    self.session_store.save({username: {"session_bytes": data.decode("latin1")}}, master_password=master_password)
                except EncryptionNotAvailableError:
                    # ignore if encryption not available; .session still exists
                    pass

    def _collect_usernames_with_progress(self, generator, total: Optional[int] = None) -> List[str]:
        usernames = []
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn()) as progress:
            task = progress.add_task("Загрузка...", total=total)
            i = 0
            for prof in generator:
                i += 1
                try:
                    usernames.append(prof.username)
                except Exception:
                    try:
                        usernames.append(str(prof))
                    except Exception:
                        pass
                progress.update(task, advance=1)
            progress.update(task, completed=total or i)
        return usernames

    def get_followers_and_following(self, target_username: str, show_progress: bool = True) -> Tuple[List[str], List[str], Dict]:
        profile = instaloader.Profile.from_username(self.L.context, target_username)
        meta = {}
        try:
            meta["followers_count"] = profile.followers
            meta["following_count"] = profile.followees
        except Exception:
            pass

        followers_gen = profile.get_followers()
        followees_gen = profile.get_followees()

        if show_progress:
            followers = self._collect_usernames_with_progress(followers_gen, total=meta.get("followers_count"))
            following = self._collect_usernames_with_progress(followees_gen, total=meta.get("following_count"))
        else:
            followers = [p.username for p in followers_gen]
            following = [p.username for p in followees_gen]

        return followers, following, meta


# -----------------------
# CLI
# -----------------------
def main():
    console.print(Panel.fit("[bold magenta]InstaChecker[/]\nПростой CLI для анализа взаимных подписок", title="InstaChecker", width=80))
    client = InstagramClient()

    # Load saved session if available
    if client.has_saved_session():
        if questionary.confirm("Найдена сохранённая сессия. Использовать её?").ask():
            mp = None
            if client.session_store.exists():
                # try keyring first
                if keyring_available():
                    mp = keyring_get_master()
                    if mp:
                        console.print("[green]Мастер-пароль получен из keyring.[/]")
                    else:
                        mp = questionary.password("Введите мастер-пароль для расшифровки (или ENTER, если хранилище не зашифровано):").ask()
                else:
                    mp = questionary.password("Введите мастер-пароль для расшифровки (или ENTER, если хранилище не зашифровано):").ask()
            try:
                client.load_saved_session(master_password=mp)
                console.print("[green]Сессия загружена.[/]")
            except Exception as e:
                console.print(f"[yellow]Не удалось загрузить сессию: {e}[/]")

    # Login if needed
    if not client.is_logged_in:
        login_flow(client)

    # Main loop
    while True:
        target_input = questionary.text("Введите никнейм или ссылку на аккаунт (или 'exit'):", qmark=">").ask()
        if not target_input:
            continue
        if target_input.strip().lower() in ("exit", "quit"):
            console.print("Выход.")
            sys.exit(0)

        try:
            target = normalize_username(target_input)
        except ValueError as e:
            console.print(f"[red]Ошибка: {e}[/]")
            continue

        console.print(f"Получаю данные для [bold cyan]@{target}[/] ...")
        try:
            followers, following, meta = client.get_followers_and_following(target, show_progress=True)
        except Exception as e:
            console.print(f"[red]Ошибка при получении данных: {e}[/]")
            continue

        followers_set = set(followers)
        following_set = set(following)

        only_following = sorted(following_set - followers_set)
        only_followers = sorted(followers_set - following_set)

        # Summary
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Показатель")
        table.add_column("Значение", justify="right")
        table.add_row("Целевой аккаунт", f"@{target}")
        table.add_row("Подписчики (followers)", str(meta.get("followers_count", len(followers))))
        table.add_row("Подписки (following)", str(meta.get("following_count", len(following))))
        table.add_row("Не взаимные (you -> they)", str(len(only_following)))
        table.add_row("Не взаимные (they -> you)", str(len(only_followers)))
        console.print(table)

        # Details
        choice = questionary.select(
            "Показать подробные списки?",
            choices=[
                "Кто на меня не подписан (you -> they)",
                "Кто я не подписан (they -> you)",
                "Обе таблицы",
                "Нет"
            ],
        ).ask()

        def print_list(title, items):
            t = Table(title=title, show_header=True)
            t.add_column("#", style="dim", width=6)
            t.add_column("username", style="cyan")
            for i, name in enumerate(items, start=1):
                t.add_row(str(i), f"@{name}")
            console.print(t)

        if choice == "Кто на меня не подписан (you -> they)":
            print_list("Not following you back (you -> they)", only_following)
        elif choice == "Кто я не подписан (they -> you)":
            print_list("You don't follow back (they -> you)", only_followers)
        elif choice == "Обе таблицы":
            print_list("Not following you back (you -> they)", only_following)
            print_list("You don't follow back (they -> you)", only_followers)

        if questionary.confirm("Экспортировать список (you -> they) в файл?").ask():
            filename = f"unfollowers_{target}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                for u in only_following:
                    f.write(f"@{u}\n")
            console.print(f"[green]Сохранено в {filename}[/]")

        if not questionary.confirm("Проверить ещё аккаунт?").ask():
            console.print("Завершение работы.")
            break


def login_flow(client: InstagramClient):
    console.print("[bold]Вход в Instagram[/]")
    while not client.is_logged_in:
        username = questionary.text("Instagram username:").ask()
        if not username:
            continue
        password = questionary.password("Password (ввод скрыт):").ask()
        if password is None:
            console.print("Отмена входа.")
            break

        protect = questionary.confirm("Шифровать сохранённую сессион паролем? (рекомендуется)").ask()
        master_password = None
        if protect:
            if not _ENCRYPTION_AVAILABLE:
                console.print("[yellow]cryptography не установлена — шифрование недоступно.[/]")
                console.print("[yellow]Чтобы включить шифрование, установите: pip install cryptography[/]")
            else:
                master_password = questionary.password("Введите мастер-пароль для шифрования сессии:").ask()
                if master_password and not _KEYRING_AVAILABLE:
                    console.print("[yellow]keyring не установлен — сохранение мастер-пароля в keyring невозможно.[/]")
                    console.print("[yellow]Чтобы включить keyring: pip install keyring[/]")
                if master_password and _KEYRING_AVAILABLE:
                    if questionary.confirm("Сохранить мастер-пароль в системном keyring?").ask():
                        ok = keyring_set_master(master_password, account=username)
                        if ok:
                            console.print("[green]Мастер-пароль сохранён в keyring.[/]")
                        else:
                            console.print("[yellow]Не удалось сохранить мастер-пароль в keyring.[/]")
        try:
            client.login(username.strip(), password.strip(), save_session=True, master_password=master_password)
            console.print("[green]Успешный вход! Сессия сохранена.[/]")
        except Exception as e:
            console.print(f"[red]Login failed: {e}[/]")
            if not questionary.confirm("Попробовать ещё раз?").ask():
                break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Прервано пользователем[/]")
        sys.exit(0)
        