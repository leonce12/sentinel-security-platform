"""Command-line administration.

  python -m app.cli seed            create roles and built-in detection rules
  python -m app.cli create-admin    create the first administrator (prompts for the password)
  python -m app.cli load-demo       load the synthetic demonstration dataset

create-admin never uses a default password. It prompts (input hidden) or, for automated
setups, reads the password from the environment variable named by --password-env, which
should be removed afterwards.
"""

import argparse
import getpass
import os
import sys

from app.database.session import SessionLocal
from app.services import demo, users as user_service


def cmd_seed(_args) -> int:
    with SessionLocal() as db:
        demo.seed_reference_data(db)
    print("Roles and detection rules are in place.")
    return 0


def cmd_create_admin(args) -> int:
    with SessionLocal() as db:
        demo.seed_reference_data(db)
        if args.password_env:
            password = os.environ.get(args.password_env)
            if not password:
                print(f"Environment variable {args.password_env} is empty", file=sys.stderr)
                return 1
        else:
            password = getpass.getpass("Password for the new administrator: ")
            if password != getpass.getpass("Repeat password: "):
                print("Passwords do not match", file=sys.stderr)
                return 1
        try:
            user = user_service.create_user(db, username=args.username, email=args.email, password=password,
                                            full_name=args.full_name, role="admin")
        except Exception as exc:  # show policy errors clearly
            details = getattr(exc, "details", None)
            print(f"Could not create administrator: {getattr(exc, 'message', exc)}", file=sys.stderr)
            for line in details or []:
                print(f"  - {line}", file=sys.stderr)
            return 1
    print(f"Administrator '{user.username}' created.")
    return 0


def cmd_load_demo(_args) -> int:
    with SessionLocal() as db:
        demo.seed_reference_data(db)
        result = demo.load_demo(db, actor=None)
    for job in result["jobs"]:
        det = job["detection"] or {}
        print(f"{job['file']}: {job['processed']} stored, {job['duplicates']} duplicates, {job['rejected']} rejected; "
              f"{det.get('alerts_created', 0)} alerts created, {det.get('alerts_updated', 0)} updated")
    print(f"Local threat intelligence indicators added: {result['intel_indicators_added']}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("seed").set_defaults(func=cmd_seed)
    admin = sub.add_parser("create-admin")
    admin.add_argument("--username", required=True)
    admin.add_argument("--email", required=True)
    admin.add_argument("--full-name", default="")
    admin.add_argument("--password-env", help="Read the password from this environment variable instead of prompting")
    admin.set_defaults(func=cmd_create_admin)
    sub.add_parser("load-demo").set_defaults(func=cmd_load_demo)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
