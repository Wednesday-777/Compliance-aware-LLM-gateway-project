import json

from app.auth import load_keys


def main() -> None:
    keys = load_keys()  # honours API_KEYS_FILE and validates every entry
    payload = {
        "keys": [
            {
                "name": k.name,
                "role": k.role,
                "key_hash": k.key_hash,
                "rate_limit_per_minute": k.rate_limit_per_minute,
            }
            for k in keys
        ]
    }
    print(json.dumps(payload, separators=(",", ":")))


if __name__ == "__main__":
    main()