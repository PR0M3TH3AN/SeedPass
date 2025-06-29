# test_import.py

try:
    from bip_utils import Bip39SeedGenerator

    print("Bip39SeedGenerator imported successfully.")
except ImportError as e:
    print(f"ImportError: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
