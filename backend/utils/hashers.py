import secrets



def generate_salt(length=16) -> str:
    """
    Generates a random salt.
    """
    return secrets.token_hex(length)
