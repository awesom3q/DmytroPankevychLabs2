"""Завдання 1: Модель користувача, безпечних сесій та журналу аудиту (ООП)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import re

PBKDF2_ITERATIONS = 100_000
SESSION_TIMEOUT_SEC = 900

# Локальна частина: починається з латинської літери, 3-64 символи (літери, цифри, ., _, -),
# далі @ та доменне ім'я з принаймні однією крапкою.
EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9._-]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
)


class User:
    """Клас користувача системи з безпечним зберіганням пароля."""

    def __init__(self, username: str, email: str, role: str = "user") -> None:
        if not username or not username.strip():
            raise ValueError("Ім'я користувача не може бути порожнім.")
        self.username: str = username.strip()
        self.role: str = role
        self.active: bool = True
        self._email: str = ""
        self.email = email
        self.__password_salt: bytes = b""
        self.__password_hash: bytes = b""

    @property
    def email(self) -> str:
        """Повертає email користувача."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        """Валідує та встановлює новий email через регулярний вираз."""
        if not isinstance(value, str) or not EMAIL_PATTERN.match(value):
            raise ValueError(
                f"Некоректний формат email: '{value}'. "
                "Локальна частина має починатися з літери (3-64 символи), "
                "містити '@' і домен із крапкою."
            )
        self._email = value

    def set_password(self, password: str) -> None:
        """Хешує пароль алгоритмом PBKDF2-HMAC-SHA256 із випадковою сіллю."""
        if not isinstance(password, str) or len(password) < 4:
            raise ValueError("Пароль має містити щонайменше 4 символи.")
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Перевіряє пароль за допомогою захищеного порівняння hmac.compare_digest."""
        if not self.__password_hash or not self.__password_salt:
            return False
        candidate_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, candidate_hash)

    def deactivate(self) -> None:
        """Деактивує обліковий запис користувача."""
        self.active = False

    def __str__(self) -> str:
        status = "Active" if self.active else "Inactive"
        return (
            f"User(username='{self.username}', email='{self.email}', "
            f"role='{self.role}', status='{status}')"
        )


class Admin(User):
    """Клас адміністратора, що успадковує User та додає систему дозволів."""

    def __init__(
        self,
        username: str,
        email: str,
        permissions: list[str] | set[str] | None = None,
    ) -> None:
        super().__init__(username=username, email=email, role="admin")
        self.permissions: set[str] = (
            set(permissions) if permissions is not None else set()
        )

    def grant_permission(self, permission: str) -> None:
        """Надає адміністратору новий дозвіл."""
        if permission and permission.strip():
            self.permissions.add(permission.strip())

    def revoke_permission(self, permission: str) -> None:
        """Відкликає дозвіл у адміністратора."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевіряє наявність конкретного дозволу."""
        return permission in self.permissions

    def __str__(self) -> str:
        perms = ", ".join(sorted(self.permissions)) if self.permissions else "None"
        return f"{super().__str__()} | Permissions: [{perms}]"


class Session:
    """Клас сеансу користувача з контролем часу активності в UTC."""

    def __init__(self, ip: str) -> None:
        self.ip: str = ip
        now = datetime.now(timezone.utc)
        self.login_time: datetime = now
        self.last_activity: datetime = now

    def touch(self) -> None:
        """Оновлює час останньої активності сеансу."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевіряє, чи не минув таймаут з моменту останньої активності."""
        if timeout_sec <= 0:
            raise ValueError("Параметр timeout_sec має бути більшим за 0.")
        now = datetime.now(timezone.utc)
        return (now - self.last_activity) <= timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
class AuditEntry:
    """Окремий запис у журналі аудиту безпеки."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал аудиту подій безпеки."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def add_log(self, username: str, action: str) -> None:
        """Додає новий запис із поточним часом UTC (без паролів)."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self._entries.append(entry)

    def show_all(self) -> list[AuditEntry]:
        """Повертає копію списку всіх записів журналу."""
        return list(self._entries)


class UserAccount:
    """Керування обліковим записом через композицію User, Session та AuditLog."""

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.user: User = user
        self.session: Session | None = session
        self.audit_log: AuditLog = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Перевіряє облікові дані, створює сесію та логує результат."""
        if not self.user.active or self.user.username != username:
            self.audit_log.add_log(username, "login_failure")
            return False

        if self.user.check_password(password):
            self.session = Session(ip=ip)
            self.session.touch()
            self.audit_log.add_log(username, "login_success")
            return True

        self.audit_log.add_log(username, "login_failure")
        return False

    def is_authenticated(self) -> bool:
        """Перевіряє активність сесії без оновлення часу останньої активності."""
        if self.session is None:
            return False
        return self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        """Завершує активний сеанс і записує подію в журнал аудиту."""
        self.session = None
        self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str) -> User | Session | AuditLog | None:
        """Дозволяє доступ через синтаксис account['user']."""
        if key == "user":
            return self.user
        if key == "session":
            return self.session
        if key == "audit_log":
            return self.audit_log
        raise KeyError(f"Невідомий або заборонений ключ: '{key}'")

    def __setitem__(self, key: str, value: object) -> None:
        """Дозволяє змінювати дозволені поля з перевіркою типу."""
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Очікується об'єкт типу User.")
            self.user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError("Очікується об'єкт типу Session або None.")
            self.session = value
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError("Очікується об'єкт типу AuditLog.")
            self.audit_log = value
        else:
            raise KeyError(f"Невідомий або заборонений для запису ключ: '{key}'")
