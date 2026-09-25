from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys

from . import __version__
from .config import atomic_json, load
from .firewall import cleanup, counters, restore_generation
from .i18n import STRINGS, tr
from .paths import CACHE, CONFIG, CURRENT, EVENT_LOG, rooted
from .ping import disable as ping_disable
from .ping import enable as ping_enable
from .updater import perform, source_catalog


class LocalizedParser(argparse.ArgumentParser):
    def __init__(self, lang: str, **kwargs):
        self.lang = lang
        super().__init__(add_help=False, **kwargs)
        self._positionals.title = tr(lang, "commands")
        self._optionals.title = tr(lang, "options")
        self.add_argument("-h", "--help", action="help", help=tr(lang, "help_help"))

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, tr(self.lang, "argument_error", error=message) + "\n")


def language(override: str | None) -> str:
    if override:
        return override
    try:
        return load()["language"]
    except (OSError, ValueError, json.JSONDecodeError):
        return "ru"


def root(command: str, lang: str) -> bool:
    if os.geteuid() == 0:
        return True
    print(tr(lang, "need_root", command=command), file=sys.stderr)
    return False


def status(lang: str) -> int:
    cfg = load()
    print(tr(lang, "title")); print(tr(lang, "status"))
    catalog = source_catalog()
    for module in cfg["modules"]:
        state = tr(lang, "enabled" if cfg["modules"][module] else "disabled")
        if module != "ping" and cfg["modules"][module]:
            available = any((CACHE / s["id"] / "networks.json").exists() for s in catalog if s["module"] == module)
            if not available:
                state = tr(lang, "not_covered")
        print(f"- {tr(lang, 'module_' + module)}: {state}")
    if CURRENT.exists():
        gen = json.loads((CURRENT / "generation.json").read_text())
        print(f"{tr(lang, 'generation')}: {gen['id']} ({len(gen['networks'])})")
    else:
        print(f"{tr(lang, 'generation')}: —")
    for source in catalog:
        meta = CACHE / source["id"] / "metadata.json"
        value = json.loads(meta.read_text()) if meta.exists() else {}
        print(f"- {source['id']}: IPv4={value.get('ipv4_count', 0)}, IPv6 skipped={value.get('ipv6_skipped', 0)}, last={value.get('last_success', '—')}, error={value.get('error') or '—'}")
    output = counters()
    if output:
        print(output.rstrip())
    return 0


def apply_config(cfg: dict, lang: str) -> None:
    cfg["configured"] = True
    atomic_json(CONFIG, cfg)
    perform(download=True)
    override = rooted("/etc/systemd/system/nextguard-update.timer.d/interval.conf")
    override.parent.mkdir(parents=True, exist_ok=True)
    override.write_text(f"[Timer]\nOnUnitActiveSec={cfg['interval_minutes']}min\n", encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "restart", "nextguard-update.timer"], check=False)
    if cfg["modules"]["ping"]:
        subprocess.run(["systemctl", "enable", "--now", "nextguard-ping.service"], check=False)
        ping_enable(cfg["logging"]["ping"])
    else:
        subprocess.run(["systemctl", "disable", "--now", "nextguard-ping.service"], check=False)
        ping_disable()
    print(tr(lang, "apply"))


def interactive(lang: str) -> int:
    if not sys.stdin.isatty():
        try:
            tty = open("/dev/tty", "r+")
            sys.stdin, sys.stdout = tty, tty
        except OSError:
            print(tr(lang, "no_tty"), file=sys.stderr); return 2
    active = load(); draft = copy.deepcopy(active); lang = draft["language"]
    if not active.get("configured", False):
        try:
            selected = input("1 — Русский, 2 — English: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n" + tr(lang, "cancel")); return 0
        if selected in {"1", "2"}:
            lang = draft["language"] = "ru" if selected == "1" else "en"
    while True:
        print(f"\n{tr(lang, 'title')}\n{tr(lang, 'developer')}")
        for key, value in draft["modules"].items():
            print(f"  {key}: {tr(lang, 'enabled' if value else 'disabled')} — {tr(lang, 'module_' + key)}")
        print(f"{tr(lang, 'menu')}\ninterval={draft['interval_minutes']}; logging={','.join(k for k,v in draft['logging'].items() if v) or 'off'}")
        try:
            choice = input(tr(lang, "choice")).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n" + tr(lang, "cancel")); return 0
        if choice == "0": print(tr(lang, "cancel")); return 0
        if choice == "1":
            keys = list(draft["modules"]); print("  ".join(f"{i+1} {tr(lang, 'module_'+k)}" for i,k in enumerate(keys)))
            selected = input(tr(lang, "choice")).strip()
            if selected.isdigit() and 1 <= int(selected) <= len(keys):
                key = keys[int(selected)-1]; draft["modules"][key] = not draft["modules"][key]
        elif choice == "2":
            selected = input("30 / 60: ").strip(); draft["interval_minutes"] = int(selected) if selected in {"30", "60"} else draft["interval_minutes"]
        elif choice == "3":
            print("rkn attackers scanners ping all off")
            selected = input(tr(lang, "choice")).strip()
            if selected == "all": draft["logging"] = {k: True for k in draft["logging"]}
            elif selected == "off": draft["logging"] = {k: False for k in draft["logging"]}
            elif selected in draft["logging"]: draft["logging"][selected] = not draft["logging"][selected]
        elif choice == "4":
            selected = input("1 — Русский, 2 — English: ").strip()
            if selected in {"1", "2"}: lang = draft["language"] = "ru" if selected == "1" else "en"
        elif choice == "5": status(lang)
        elif choice == "6":
            result = perform(); print(tr(lang, "update_done", networks=len(result["generation"]["networks"]), failed=result["failed"]))
        elif choice == "7": apply_config(draft, lang); active = copy.deepcopy(draft)
        elif choice == "8": show_logs()
        elif choice == "9":
            expected = "УДАЛИТЬ" if lang == "ru" else "REMOVE"
            if input(tr(lang, "confirm_uninstall")).strip() == expected:
                subprocess.run(["/opt/nextguard/uninstall.sh", "--confirmed"]); return 0
        else: print(tr(lang, "bad"))


def show_logs() -> int:
    if EVENT_LOG.exists():
        print("\n".join(EVENT_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-100:]))
    return 0


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    requested = next((raw[i + 1] for i, value in enumerate(raw[:-1]) if value == "--lang" and raw[i + 1] in {"ru", "en"}), None)
    help_lang = language(requested)
    parser = LocalizedParser(help_lang, description=tr(help_lang, "usage"))
    parser.add_argument("command", nargs="?", choices=["status", "update", "logs", "restore", "uninstall"], help=tr(help_lang, "commands_help"))
    parser.add_argument("--lang", choices=["ru", "en"], help=tr(help_lang, "lang_help"))
    parser.add_argument("--version", action="version", version=f"NextGuard {__version__}", help=tr(help_lang, "version_help"))
    args = parser.parse_args(raw); lang = language(args.lang)
    if args.command == "logs": return show_logs()
    if args.command == "status": return status(lang)
    if not root(args.command or "", lang): return 1
    try:
        if args.command == "update":
            result = perform(); print(tr(lang, "update_done", networks=len(result["generation"]["networks"]), failed=result["failed"])); return 0
        if args.command == "restore":
            restore_generation(CURRENT); return 0
        if args.command == "uninstall":
            return subprocess.run(["/opt/nextguard/uninstall.sh"]).returncode
        return interactive(lang)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(tr(lang, "update_failed", error=exc), file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())
