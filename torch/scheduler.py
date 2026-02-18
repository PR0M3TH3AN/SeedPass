import subprocess
import sys


def run_command(command):
    try:
        result = subprocess.run(
            command, shell=True, check=True, capture_output=True, text=True
        )
        print(f"Command '{command}' passed.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Command '{command}' failed with exit code {e.returncode}.")
        print(e.stderr)
        return e.stderr


def main():
    print("Running daily checks...")
    # Check for vulnerabilities
    print("\n--- pip-audit ---")
    run_command("pip-audit")

    # Check style
    print("\n--- flake8 ---")
    run_command("flake8 --exit-zero")

    # Run tests
    print("\n--- pytest ---")
    run_command("pytest")

    print("\nDaily checks completed.")


if __name__ == "__main__":
    main()
