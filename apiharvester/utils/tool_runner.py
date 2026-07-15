"""External tool wrapper — try tool, return output or None."""
import shutil
import subprocess
import sys


def tool_available(name):
    return shutil.which(name) is not None


def run_tool(name, args, timeout=300, stdin_data=None):
    """Run an external tool. Returns (stdout, stderr, returncode) or None if not installed."""
    if not tool_available(name):
        print(f"[*] {name} not installed, using fallback", file=sys.stderr)
        return None
    try:
        result = subprocess.run(
            [name] + args,
            capture_output=True, text=True,
            timeout=timeout,
            input=stdin_data)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        print(f"[!] {name} timed out after {timeout}s", file=sys.stderr)
        return "", f"timeout after {timeout}s", 1
    except Exception as e:
        print(f"[!] {name} failed: {e}", file=sys.stderr)
        return "", str(e), 1


def run_tool_lines(name, args, timeout=300):
    """Run tool, return list of non-empty output lines, or empty list if not installed."""
    result = run_tool(name, args, timeout=timeout)
    if result is None:
        return []
    stdout, _, _ = result
    return [l.strip() for l in stdout.splitlines() if l.strip()]
