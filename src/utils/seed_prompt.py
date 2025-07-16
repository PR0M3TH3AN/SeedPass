import os
import sys

try:
    import msvcrt  # type: ignore
except ImportError:  # pragma: no cover - Windows only
    msvcrt = None  # type: ignore

try:
    import termios
    import tty
except ImportError:  # pragma: no cover - POSIX only
    termios = None  # type: ignore
    tty = None  # type: ignore

from utils.terminal_utils import clear_screen


def _masked_input_windows(prompt: str) -> str:
    """Windows implementation using ``msvcrt``."""
    if msvcrt is None:  # pragma: no cover - should not happen
        return input(prompt)

    sys.stdout.write(prompt)
    sys.stdout.flush()
    buffer: list[str] = []
    while True:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):
            sys.stdout.write("\n")
            return "".join(buffer)
        if ch in ("\b", "\x7f"):
            if buffer:
                buffer.pop()
                sys.stdout.write("\b \b")
        else:
            buffer.append(ch)
            sys.stdout.write("*")
        sys.stdout.flush()


def _masked_input_posix(prompt: str) -> str:
    """POSIX implementation using ``termios`` and ``tty``."""
    if termios is None or tty is None:  # pragma: no cover - should not happen
        return input(prompt)

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    sys.stdout.write(prompt)
    sys.stdout.flush()
    buffer: list[str] = []
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch in ("\r", "\n"):
                sys.stdout.write("\n")
                return "".join(buffer)
            if ch in ("\x7f", "\b"):
                if buffer:
                    buffer.pop()
                    sys.stdout.write("\b \b")
            else:
                buffer.append(ch)
                sys.stdout.write("*")
            sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def masked_input(prompt: str) -> str:
    """Return input from the user while masking typed characters."""
    if sys.platform == "win32":
        return _masked_input_windows(prompt)
    return _masked_input_posix(prompt)


def prompt_seed_words(count: int = 12) -> str:
    """Prompt the user for a BIP-39 seed phrase.

    The user is asked for each word one at a time. A numbered list is
    displayed showing ``*`` for entered words and ``_`` for words yet to be
    provided. After all words are entered the user is asked to confirm each
    word individually. If the user answers ``no`` to a confirmation prompt the
    word can be re-entered.

    Parameters
    ----------
    count:
        Number of words to prompt for. Defaults to ``12``.

    Returns
    -------
    str
        The complete seed phrase.

    Raises
    ------
    ValueError
        If the resulting phrase fails ``Mnemonic.check`` validation.
    """

    from mnemonic import Mnemonic

    m = Mnemonic("english")
    words: list[str] = [""] * count

    idx = 0
    while idx < count:
        clear_screen()
        progress = [f"{i+1}: {'*' if w else '_'}" for i, w in enumerate(words)]
        print("\n".join(progress))
        entered = masked_input(f"Enter word number {idx+1}: ").strip().lower()
        if entered not in m.wordlist:
            print("Invalid word, try again.")
            continue
        words[idx] = entered
        idx += 1

    for i in range(count):
        while True:
            clear_screen()
            progress = [f"{j+1}: {'*' if j < i else '_'}" for j in range(count)]
            print("\n".join(progress))
            response = (
                input(f"Is this the correct word for number {i+1}? {words[i]} (Y/N): ")
                .strip()
                .lower()
            )
            if response in ("y", "yes"):
                break
            if response in ("n", "no"):
                while True:
                    clear_screen()
                    progress = [f"{j+1}: {'*' if j < i else '_'}" for j in range(count)]
                    print("\n".join(progress))
                    new_word = (
                        masked_input(f"Re-enter word number {i+1}: ").strip().lower()
                    )
                    if new_word in m.wordlist:
                        words[i] = new_word
                        break
                    print("Invalid word, try again.")
                # Ask for confirmation again with the new word
            else:
                print("Please respond with 'Y' or 'N'.")
                continue

    phrase = " ".join(words)
    if not m.check(phrase):
        raise ValueError("Invalid BIP-39 seed phrase")
    return phrase
