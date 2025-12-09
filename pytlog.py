#!/usr/bin/env python3
# coding: utf-8



import os
import re
import subprocess  

def print_banner():
    """
    Big 'PYTHON' banner in PURPLE, with a frame.
    Inside the same frame: small text 'PYTHON LOG ANALYZER'
    and 'Project by: Itay Bechor'.
    """

    PURPLE = "\033[95m"
    RESET  = "\033[0m"

   
    os.system("clear")

   
    ascii_art = subprocess.check_output(
        ["toilet", "-f", "mono12", "PYTHON"],
        text=True
    )

    lines = ascii_art.rstrip("\n").split("\n")
    width = max(len(l) for l in lines)   

   
    sub1 = "PYTHON FUNDAMENTALS PROJECT".center(width)
    sub2 = "Project by: Itay Bechor".center(width)

   
    print(PURPLE, end="")

   
    print("+" + "-" * (width + 2) + "+")

   
    for l in lines:
        print("| " + l.ljust(width) + " |")

    
    print("| " + sub1 + " |")
    print("| " + sub2 + " |")

    
    print("+" + "-" * (width + 2) + "+")

    
    print(RESET, end="\n\n")




LOG_FILE = "/var/log/auth.log"

TIME_COL_WIDTH = 34
USER_COL_WIDTH = 12
CMD_COL_WIDTH  = 12




def read_auth_log(path=LOG_FILE):
    """
    Read the auth.log file line by line and yield each line
    without the trailing newline character.
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            # Remove the newline at the end of the line
            yield line.rstrip("\n")

# ========= PART 1: COMMAND USAGE (1.1–1.3) =========

def extract_command_usage(path=LOG_FILE):
    """
    Print Time | User | Command for each line in auth.log.
    Here "Command" is the log message (everything after the first ':').
    """

    # Print table header
    print("Time".ljust(20), "|", "User".ljust(12), "|", "Command")
    print("-" * 80)

    # Go over every line in auth.log
    for line in read_auth_log(path):
        # Split line into parts separated by spaces
        parts = line.split()

        # We expect at least 5 fields: month day time host process:
        if len(parts) < 5:
            # Skip very short / malformed lines
            continue

        # 1.1 Build the timestamp string, e.g. "Jul 10 00:00:02"
        timestamp = " ".join(parts[0:3])

        # 1.2 Find the user that is mentioned in the line
        user = "unknown"      # Default value if we cannot find a user

        # Case 1: pattern "user=ROOT"
        if "user=" in line:
            user = line.split("user=")[1].split()[0]

        # Case 2: pattern "invalid user NAME"
        elif "invalid user" in line:
            user = line.split("invalid user")[1].split()[0]

        # Case 3: pattern "Failed password for NAME from ..."
        elif "Failed password for " in line and " from " in line:
            try:
                user = line.split("Failed password for ")[1].split()[0]
            except IndexError:
                # If parsing fails, keep user = "unknown"
                pass

        # 1.3 Extract the "command" – here we treat it as the log message:
        # Everything after the first ':' in the line
        if ":" in line:
            command = line.split(":", 1)[1].strip()
        else:
            command = "unknown"

        # בסוף הפונקציה: הדפסה של Time | User | Command
        print(timestamp.ljust(20), "|", user.ljust(12), "|", command)



# ======================================
# 2.x  MONITOR USER AUTHENTICATION CHANGES
# ======================================

def find_new_users(lines):
    """
    2.1 Print details of newly added users, including the Timestamp.

    Looks for lines with 'useradd' or 'new user:' patterns.
    """
    print("\n[2.1] Newly added users")
    print("-" * 60)

    found = False
    for line in lines:
        if "useradd" not in line and "new user" not in line:
            continue

        timestamp = get_timestamp(line)
        username = "unknown"

        # Pattern: new user: name=itay
        m = re.search(r"name=([A-Za-z0-9_-]+)", line)
        if m:
            username = m.group(1)

        print(f"{timestamp.ljust(20)} | user added: {username}")
        found = True

    if not found:
        print("No 'useradd' / new user entries found.")


# ================================
# 2.x MONITOR USER AUTHENTICATION CHANGES
# ================================

def get_timestamp(line):
    """
    Extract the timestamp from an auth.log line.
    Example:
    '2025-12-01T09:43:17.765954-05:00 kali sudo: ...'
    -> '2025-12-01T09:43:17.765954-05:00'
    """
    parts = line.split()
    if not parts:
        return "UNKNOWN_TIME"
    return parts[0]


def find_new_users(lines):
    """
    2.1 Print details of newly added users, including the Timestamp.
        Looks for lines with 'useradd' or 'new user:' patterns.
    """
    print("\n[2.1] Newly added users")
    print("-" * 60)

    pattern = re.compile(r"new user: name=([A-Za-z0-9_]+)")
    found = False

    for line in lines:
        # רק שורות שקשורות ל־useradd / new user
        if "useradd" not in line and "new user" not in line:
            continue

        timestamp = get_timestamp(line)

        m = pattern.search(line)
        username = m.group(1) if m else "unknown"

        print(f"{timestamp:25} | user added: {username}")
        found = True

    if not found:
        print("No 'useradd' / 'new user' entries found.")


def find_deleted_users(lines):
    """
    2.2 Print details of deleted users, including the Timestamp.
        Looks for lines with 'userdel' and 'delete user'.
    """
    print("\n[2.2] Deleted users")
    print("-" * 60)

    pattern = re.compile(r"delete user '([^']+)'")
    found = False

    for line in lines:
        if "userdel" not in line:
            continue

        timestamp = get_timestamp(line)

        m = pattern.search(line)
        username = m.group(1) if m else "unknown"

        print(f"{timestamp:25} | user deleted: {username}")
        found = True

    if not found:
        print("No 'userdel' entries found.")


def find_password_changes(lines):
    """
    2.3 Print details of password changes, including the Timestamp.
        Looks for lines with 'passwd' and 'password changed for'.
    """
    print("\n[2.3] Password changes")
    print("-" * 60)

    pattern = re.compile(r"password (?:changed|reset) for (?:user )?([A-Za-z0-9_]+)")
    found = False

    for line in lines:
        if "passwd" not in line:
            continue

        timestamp = get_timestamp(line)

        m = pattern.search(line)
        if not m:
            # ייתכן שורה כמו "password check failed" – נדלג כאן
            continue

        username = m.group(1)
        print(f"{timestamp:25} | password changed for: {username}")
        found = True

    if not found:
        print("No password change entries found.")


def find_su_usage(lines):
    """
    2.4 Monitor 'su' usage (switch user), including time and user.
        Looks for lines that contain ' su['.
    """
    print("\n[2.4] 'su' usage")
    print("-" * 60)

    # לוכד את שם המשתמש לפני 'su['
    pattern = re.compile(r"\s([A-Za-z0-9_]+)\s+su\[")
    found = False

    for line in lines:
        if " su[" not in line:
            continue

        timestamp = get_timestamp(line)

        m = pattern.search(line)
        user = m.group(1) if m else "unknown"

        print(f"{timestamp:25} | su used by: {user}")
        found = True

    if not found:
        print("No 'su' usage entries found.")


def find_sudo_usage(lines):
    """
    2.5 Monitor 'sudo' usage, including time, user and command.
        Looks for lines with 'sudo:' and 'COMMAND='.
    """
    print("\n[2.5] 'sudo' usage")
    print("-" * 60)

    cmd_pattern = re.compile(r"COMMAND=(.+)")
    found = False

    for line in lines:
        if "sudo:" not in line:
            continue

        # timestamp מהשורה
        timestamp = get_timestamp(line)

        # חילוק השורה לשדות כדי למצוא את המשתמש
        parts = line.split()
        if len(parts) < 3:
            continue

        user = parts[1]        # כאן נקבע שהמשתמש הוא השדה השני – למשל 'kali'

        # חיפוש הפקודה אחרי COMMAND=
        cm = cmd_pattern.search(line)
        if not cm:
            continue
        cmd = cm.group(1)

        print(f"{timestamp:25} | sudo by: {user:8} | {cmd}")
        found = True

    if not found:
        print("No 'sudo' usage entries found.")




def find_failed_sudo(lines):
    """
    2.6 Print ALERT! If users failed to use the sudo command; include the command.
    בנוסף נכללים גם ניסיונות התחברות ssh שנכשלו (אימות).
    """

    print("\n[2.6] Failed sudo / authentication attempts")
    print("-" * 80)

    found = False

    for line in lines:
        low = line.lower()

        
        if "failed" not in low:
            continue

       
        if "sudo:" not in low and "sshd" not in low and "unix_chkpwd" not in low:
            continue

        
        timestamp = get_timestamp(line)

       
        parts = line.split()
        if len(parts) >= 3:
            command = parts[2].rstrip(":")
        else:
            command = "unknown"

       
        user = "unknown"

        
        # "password check failed for user (bob)"
        m = re.search(r'for user\s*\(?([A-Za-z0-9_]+)\)?', line)
        if not m:
            # "Failed password for kali from ..."
            # "Failed password for invalid user alice from ..."
            m = re.search(r'[Ff]ailed password for (?:invalid user )?([A-Za-z0-9_]+)', line)

        if m:
            user = m.group(1)
        else:
            
            continue

        print(f"{timestamp:25} | ALERT! failed auth for user: {user:<8} | cmd: {command}")
        found = True

    if not found:
        print("No failed sudo / auth entries found.")




def monitor_auth_changes(path):
    """
    Wrapper that loads all lines once and calls each 2.x function.
    """
    # Read all lines into a list so we can scan multiple times
    lines = list(read_auth_log(path))

    find_new_users(lines)
    find_deleted_users(lines)
    find_password_changes(lines)
    find_su_usage(lines)
    find_sudo_usage(lines)
    find_failed_sudo(lines)


# ========================
# Main entry point
# ========================

# ============================
# Main entry point
# ============================

def main():
    """
    Main function:
    1) Extract command usage (1.1–1.3)
    2) Monitor user authentication changes (2.1–2.6)
    """
    print_banner()

    # ---- PART 1: COMMAND USAGE ----
    extract_command_usage(LOG_FILE)

    print()  

    # ---- PART 2: AUTH CHANGES ----
    monitor_auth_changes(LOG_FILE)


if __name__ == "__main__":
    main()

