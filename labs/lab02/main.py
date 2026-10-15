"""Головний модуль Лабораторної роботи №2 (команди demo та analyze)."""

from __future__ import annotations

import argparse
from datetime import timedelta
import logging
from pathlib import Path
import sys

from labs.lab02.task1 import Admin, AuditLog, User, UserAccount
from labs.lab02.task2 import run_ssh_audit
from shared.student import STUDENT_NAME, VARIANT_NUMBER


def run_demo() -> None:
    """Наочна демонстрація всіх можливостей ООП із Завдання 1."""
    print("=" * 72)
    print(
        f"ЛАБОРАТОРНА РОБОТА №2 | Студент: {STUDENT_NAME} | Варіант: {VARIANT_NUMBER}"
    )
    print("ДЕМОНСТРАЦІЯ ЗАВДАННЯ 1: Модель користувача, сесії та аудиту")
    print("=" * 72)

    # 1. Створення користувача та перевірка пароля
    print("\n1. [Створення User та безпечне хешування пароля PBKDF2]")
    user = User(username="dmytro_p", email="dmytro.pankevych@lpnu.ua", role="analyst")
    user.set_password("CyberSec_2026!")
    print(f"   Об'єкт: {user}")
    print(f"   Перевірка правильного пароля : {user.check_password('CyberSec_2026!')}")
    print(f"   Перевірка хибного пароля     : {user.check_password('wrong_pass')}")

    # 2. Валідація email через декоратор @property
    print("\n2. [Валідація атрибута email через @property]")
    user.email = "d.pankevych_sec@gmail.com"
    print(f"   Успішно змінено email на     : {user.email}")
    try:
        user.email = "123_invalid_email@"
    except ValueError as err:
        print(f"   Відхилено некоректний email  : {err}")

    # 3. Наслідування: клас Admin та керування правами
    print("\n3. [Наслідування: клас Admin(User) та керування дозволами]")
    admin = Admin(
        username="sec_admin",
        email="admin.soc@lpnu.ua",
        permissions=["read_logs", "block_ips"],
    )
    admin.set_password("AdminRoot#2026")
    admin.grant_permission("manage_users")
    admin.revoke_permission("read_logs")
    print(f"   Об'єкт Admin                 : {admin}")
    print(f"   Наявність права 'block_ips'  : {admin.has_permission('block_ips')}")
    print(f"   Наявність права 'read_logs'  : {admin.has_permission('read_logs')}")

    # 4. Композиція: UserAccount, вхід у систему (успішний та невдалий)
    print("\n4. [Композиція: UserAccount, автентифікація та сесія]")
    audit_log = AuditLog()
    account = UserAccount(user=user, audit_log=audit_log)

    fail_login = account.login("dmytro_p", "BadPassword", ip="10.0.0.15")
    print(
        f"   Вхід із хибним паролем       : {fail_login} (is_authenticated={account.is_authenticated()})"
    )

    ok_login = account.login("dmytro_p", "CyberSec_2026!", ip="192.168.1.25")
    print(
        f"   Вхід із вірним паролем       : {ok_login} (is_authenticated={account.is_authenticated()})"
    )

    # 5. Спеціальні методи __getitem__ та __setitem__
    print("\n5. [Спеціальні методи __getitem__ та __setitem__]")
    print(f"   account['user']              : {account['user']}")
    try:
        _ = account["__password_hash"]
    except KeyError as err:
        print(f"   Захист приватних полів       : {err}")

    # 6. Завершення сеансу за таймаутом
    print("\n6. [Перевірка завершення сеансу за таймаутом (SESSION_TIMEOUT_SEC = 900)]")
    if account.session is not None:
        # Імітуємо, що остання активність була 16 хвилин тому (960 секунд)
        account.session.last_activity -= timedelta(seconds=960)
        print(
            f"   Сесія після 16 хв простою    : is_authenticated={account.is_authenticated()}"
        )

    # 7. Вихід із системи (logout) та деактивація
    print("\n7. [Вихід із системи (logout) та деактивація користувача]")
    account.logout()
    print(
        f"   Статус після logout()        : is_authenticated={account.is_authenticated()}"
    )
    user.deactivate()
    relogin = account.login("dmytro_p", "CyberSec_2026!", ip="192.168.1.25")
    print(f"   Вхід деактивованого юзера    : {relogin} ({user})")

    # 8. Виведення журналу аудиту AuditLog (@dataclass)
    print("\n8. [Журнал аудиту безпеки AuditLog (@dataclass AuditEntry)]")
    for idx, entry in enumerate(audit_log.show_all(), start=1):
        ts_str = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        print(
            f"   #{idx:02d} [{ts_str}] user='{entry.username}' -> action='{entry.action}'"
        )

    print("=" * 72)


def build_parser() -> argparse.ArgumentParser:
    """Створює головний CLI-парсер із командами demo та analyze."""
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab02.main",
        description="Лабораторна робота №2: ООП та CLI-утиліти кібербезпеки",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Команда demo
    subparsers.add_parser(
        "demo",
        help="Запустити демонстрацію Завдання 1 (User, Admin, Session, AuditLog)",
    )

    # Команда analyze
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Запустити Завдання 2 (Варіант 4: Аналізатор логів SSH)",
    )
    analyze_parser.add_argument(
        "--auth-log",
        type=Path,
        default=Path("labs/lab02/data/data_v04/auth.log"),
        help="Шлях до файлу журналу auth.log (за замовчуванням: labs/lab02/data/data_v04/auth.log)",
    )
    analyze_parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Поріг невдалих спроб входу за часове вікно (за замовчуванням: 5)",
    )
    analyze_parser.add_argument(
        "--window-min",
        type=int,
        default=5,
        help="Розмір часового вікна в хвилинах (за замовчуванням: 5)",
    )
    analyze_parser.add_argument(
        "--output-json",
        type=Path,
        default=Path("labs/lab02/data/blocklist_ips.json"),
        help="Шлях для збереження JSON-звіту зі списком блокування",
    )

    return parser


def main() -> None:
    """Точка входу програми."""
    logging.basicConfig(level=logging.ERROR, format="[ALERT] %(message)s")
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        try:
            run_ssh_audit(
                auth_log=args.auth_log,
                threshold=args.threshold,
                window_min=args.window_min,
                output_json=args.output_json,
            )
        except Exception as err:
            logging.error("Помилка виконання аналізу: %s", err)
            sys.exit(1)


if __name__ == "__main__":
    main()
