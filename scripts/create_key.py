import sys

from app.auth import generate_key, hash_key


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[2] not in {"client", "admin"}:
        print("Usage: python -m scripts.create_key <name> <client|admin>")
        sys.exit(1)

    name, role = sys.argv[1], sys.argv[2]
    raw = generate_key()

    print("=" * 64)
    print(f"API KEY for {name} (shown ONCE. Store it safely, never commit it):")
    print(raw)
    print("=" * 64)
    print("Add this entry under 'keys:' in api_keys.yaml:\n")
    print(f"  - name: {name}")
    print(f"    role: {role}")
    print(f'    key_hash: "{hash_key(raw)}"')
    print("    rate_limit_per_minute: 20")


if __name__ == "__main__":
    main()