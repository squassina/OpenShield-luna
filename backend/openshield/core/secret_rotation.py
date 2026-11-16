import os

from openshield.core.bootstrap import load_runtime_secrets
from openshield.core.secrets import SecretStore
from openshield.core.storage import PostgresStore


def main() -> None:
    load_runtime_secrets(create=False)
    store = PostgresStore(os.getenv("OPENSHIELD_DATABASE_URL", ""))
    verified = SecretStore(store).reencrypt_all()
    print(f"Verified {verified} integration secret(s) with the active encryption key.")


if __name__ == "__main__":
    main()
