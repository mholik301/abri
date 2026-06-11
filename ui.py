"""
ui.py — Terminal UI wrapper for l3.py (abri password manager)
Run with: python3 ui.py   (or: python ui.py)

Place this file in the same directory as l3.py.
"""

import sys
import os
import io
import shutil
import getpass
import contextlib

# ── Locate and import l3.py without running its CLI entry-point ──────────────

_here    = os.path.dirname(os.path.abspath(__file__))
_l3_path = os.path.join(_here, "l3.py")

if not os.path.isfile(_l3_path):
    print(f"\n  [ERROR] Cannot find l3.py in: {_here}")
    print("  Make sure ui.py and l3.py are in the same directory.\n")
    sys.exit(1)

_real_argv = sys.argv[:]
sys.argv   = ["l3.py"]
sys.path.insert(0, _here)

_devnull = io.StringIO()
with contextlib.redirect_stdout(_devnull):
    try:
        import l3
    except SystemExit:
        pass

sys.argv = _real_argv

addUser       = l3.addUser
updatePwd     = l3.updatePwd
setChangeFlag = l3.setChangeFlag
delUser       = l3.delUser
login         = l3.login
vaultGet      = l3.vaultGet
vaultPut      = l3.vaultPut
vaultList     = l3.vaultList
vaultDel      = l3.vaultDel
_max_input    = l3._max_input_len

# ── Session state ─────────────────────────────────────────────────────────────

_session_user = None   # currently logged-in username
_session_pwd  = None   # their plaintext password (vault key)

def _set_session(user, pwd):
    global _session_user, _session_pwd
    _session_user = user
    _session_pwd  = pwd

def _clear_session():
    global _session_user, _session_pwd
    _session_user = None
    _session_pwd  = None

# ── ANSI helpers ──────────────────────────────────────────────────────────────

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
FG      = "\033[97m"
ACCENT  = "\033[33m"
SUCCESS = "\033[32m"
ERROR   = "\033[31m"
INFO    = "\033[36m"
MUTED   = "\033[90m"

def c(text, *styles):
    return "".join(styles) + str(text) + RESET

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def term_width():
    return min(shutil.get_terminal_size((80, 24)).columns, 72)

def rule(char="─", color=MUTED):
    print(c(char * term_width(), color))

def header():
    print()
    rule("═", ACCENT)
    title = c("  🔐  ABRI  —  Password Manager", BOLD, ACCENT)
    badge = (c(f"   ● {_session_user}", SUCCESS)) if _session_user else ""
    print(title + badge)
    rule("═", ACCENT)
    print()

def section(title):
    print()
    print(c(f"  {title}", BOLD, INFO))
    rule()

def ok(msg):   print(c(f"  ✔  {msg}", SUCCESS))
def err(msg):  print(c(f"  ✖  {msg}", ERROR))
def info(msg): print(c(f"  ·  {msg}", MUTED))
def tip(msg):  print(c(f"  ⚑  {msg}", DIM))

def _pause():
    print()
    input(c("  Press ENTER to continue…", MUTED))

def prompt_username(label="Username"):
    return input(c(f"  {label}: ", FG)).strip()

def prompt_address(label="Address / service"):
    return input(c(f"  {label}: ", FG)).strip()

# ── Stdout tee (pass-through + colour last line) ──────────────────────────────

class _Tee:
    def __init__(self, real):
        self._real = real
        self.lines = []

    def write(self, text):
        self._real.write(text)
        self._real.flush()
        if text.strip():
            self.lines.append(text.rstrip())

    def flush(self):
        self._real.flush()

    def __getattr__(self, name):
        return getattr(self._real, name)


@contextlib.contextmanager
def _tee_stdout():
    tee = _Tee(sys.stdout)
    sys.stdout = tee
    try:
        yield tee
    finally:
        sys.stdout = tee._real


def _recolour_last(tee):
    if not tee.lines:
        return
    last = tee.lines[-1].strip()
    if not last:
        return
    lo = last.lower()
    if any(w in lo for w in ("error", "incorrect", "mismatch", "failed", "warning")):
        style = ERROR
    elif any(w in lo for w in ("success", "added", "updated", "deleted",
                                "stored", "login successful")):
        style = SUCCESS
    elif any(w in lo for w in ("change", "requested", "will be", "empty")):
        style = DIM
    else:
        return
    sys.stdout.write(f"\033[1A\033[2K  {c(last, style)}\n")
    sys.stdout.flush()


# ── Admin screens (always available) ─────────────────────────────────────────

def screen_login():
    section("LOGIN")
    user = prompt_username()
    if not user:
        err("Username cannot be empty."); _pause(); return
    print()
    with _tee_stdout() as tee:
        try:
            pwd = login(user)
        except KeyboardInterrupt:
            print(); err("Cancelled."); _pause(); return
        except IOError:
            err("Password mismatch."); _pause(); return
    _recolour_last(tee)

    if pwd is not None:
        _set_session(user, pwd)
        print()
        ok("Session started — vault commands are now available.")

    _pause()

def screen_logout():
    section("LOGOUT")
    print()
    info(f"Logged out {_session_user}.")
    _clear_session()
    _pause()

def screen_add_user():
    section("ADD USER")
    user = prompt_username("New username")
    if not user:
        err("Username cannot be empty."); _pause(); return
    if len(user) > _max_input:
        err(f"Username must be fewer than {_max_input} characters."); _pause(); return
    print()
    with _tee_stdout() as tee:
        try:
            addUser(user)
        except KeyboardInterrupt:
            print(); err("Cancelled."); _pause(); return
        except IOError:
            err("Password mismatch — passwords did not match."); _pause(); return
    _recolour_last(tee)
    _pause()

def screen_change_password():
    section("CHANGE PASSWORD")
    # When logged in, always change the current user's own password
    user = _session_user if _session_user else prompt_username()
    if not user:
        err("Username cannot be empty."); _pause(); return
    if _session_user:
        info(f"Changing password for: {user}")
    print()
    with _tee_stdout() as tee:
        try:
            updatePwd(user)
        except KeyboardInterrupt:
            print(); err("Cancelled."); _pause(); return
        except IOError:
            err("Password mismatch — passwords did not match."); _pause(); return
    _recolour_last(tee)
    # Session password is now stale — force re-login
    if _session_user and user == _session_user:
        tip("Your session password has changed — please log in again.")
        _clear_session()
    _pause()

def screen_force_password():
    section("FORCE PASSWORD CHANGE")
    user = prompt_username()
    if not user:
        err("Username cannot be empty."); _pause(); return
    print()
    with _tee_stdout() as tee:
        setChangeFlag(user)
    _recolour_last(tee)
    _pause()

def screen_delete_user():
    section("DELETE USER")
    user = prompt_username()
    if not user:
        err("Username cannot be empty."); _pause(); return
    confirm = input(c(f"  Delete '{user}'? This cannot be undone. [y/N]: ", ERROR)).strip().lower()
    if confirm != "y":
        info("Cancelled."); _pause(); return
    print()
    with _tee_stdout() as tee:
        delUser(user)
    _recolour_last(tee)
    if _session_user and user == _session_user:
        _clear_session()
    _pause()


# ── Vault screens (only when logged in) ──────────────────────────────────────

def screen_vault_list():
    section(f"VAULT  ·  LIST ENTRIES  [{_session_user}]")
    print()
    with _tee_stdout() as tee:
        vaultList(_session_user, _session_pwd)
    _recolour_last(tee)
    _pause()

def screen_vault_get():
    section(f"VAULT  ·  GET PASSWORD  [{_session_user}]")
    address = prompt_address()
    if not address:
        err("Address cannot be empty."); _pause(); return
    print()
    with _tee_stdout() as tee:
        vaultGet(_session_user, _session_pwd, address)
    _recolour_last(tee)
    _pause()

def screen_vault_put():
    section(f"VAULT  ·  STORE PASSWORD  [{_session_user}]")
    address = prompt_address()
    if not address:
        err("Address cannot be empty."); _pause(); return
    entry_pwd = getpass.getpass(c("  Password to store: ", FG))
    if not entry_pwd:
        err("Password cannot be empty."); _pause(); return
    print()
    with _tee_stdout() as tee:
        vaultPut(_session_user, _session_pwd, address, entry_pwd)
    _recolour_last(tee)
    _pause()

def screen_vault_del():
    section(f"VAULT  ·  DELETE ENTRY  [{_session_user}]")
    address = prompt_address()
    if not address:
        err("Address cannot be empty."); _pause(); return
    confirm = input(c(f"  Delete entry for '{address}'? [y/N]: ", ERROR)).strip().lower()
    if confirm != "y":
        info("Cancelled."); _pause(); return
    print()
    with _tee_stdout() as tee:
        vaultDel(_session_user, _session_pwd, address)
    _recolour_last(tee)
    _pause()


# ── Menus ─────────────────────────────────────────────────────────────────────

def screen_main_menu():
    clear()
    header()

    if _session_user:
        print(c("  Account management:", FG))
        print()
        print(c("   [1]", ACCENT, BOLD) + c("  Change my password",                    FG))
        print(c("   [2]", ACCENT, BOLD) + c("  Add user",                              FG))
        print(c("   [3]", ACCENT, BOLD) + c("  Force password change (any user)",      FG))
        print(c("   [4]", ACCENT, BOLD) + c("  Delete user",                           FG))
        print()
        print(c("  Vault:", FG))
        print()
        print(c("   [5]", ACCENT, BOLD) + c("  List stored entries",                   FG))
        print(c("   [6]", ACCENT, BOLD) + c("  Get a password",                        FG))
        print(c("   [7]", ACCENT, BOLD) + c("  Store / update a password",             FG))
        print(c("   [8]", ACCENT, BOLD) + c("  Delete an entry",                       FG))
        print()
        print(c("   [9]", MUTED,  BOLD) + c("  Log out",                               MUTED))
        print(c("   [0]", MUTED,  BOLD) + c("  Quit",                                  MUTED))
    else:
        print(c("  Choose an action:", FG))
        print()
        print(c("   [1]", ACCENT, BOLD) + c("  Login",                                 FG))
        print(c("   [2]", ACCENT, BOLD) + c("  Add user",                              FG))
        print(c("   [3]", ACCENT, BOLD) + c("  Change password",                       FG))
        print(c("   [4]", ACCENT, BOLD) + c("  Force password change on next login",   FG))
        print(c("   [5]", ACCENT, BOLD) + c("  Delete user",                           FG))
        print()
        print(c("   [0]", MUTED,  BOLD) + c("  Quit",                                  MUTED))

    print()
    rule()
    return input(c("  › ", ACCENT, BOLD)).strip()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    while True:
        choice = screen_main_menu()

        if _session_user:
            if   choice == "1": screen_change_password()
            elif choice == "2": screen_add_user()
            elif choice == "3": screen_force_password()
            elif choice == "4": screen_delete_user()
            elif choice == "5": screen_vault_list()
            elif choice == "6": screen_vault_get()
            elif choice == "7": screen_vault_put()
            elif choice == "8": screen_vault_del()
            elif choice == "9": screen_logout()
            elif choice == "0":
                clear(); print(); print(c("  Goodbye.", ACCENT, BOLD)); print(); sys.exit(0)
            else:
                clear(); header(); err("Unknown option."); _pause()
        else:
            if   choice == "1": screen_login()
            elif choice == "2": screen_add_user()
            elif choice == "3": screen_change_password()
            elif choice == "4": screen_force_password()
            elif choice == "5": screen_delete_user()
            elif choice == "0":
                clear(); print(); print(c("  Goodbye.", ACCENT, BOLD)); print(); sys.exit(0)
            else:
                clear(); header(); err("Unknown option."); _pause()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print(c("\n  Interrupted. Goodbye.", MUTED))
        print()
        sys.exit(0)
