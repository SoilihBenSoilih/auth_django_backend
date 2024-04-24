import re



def is_valid_uuid(uuid_string):
    """ Check if uuid is valid"""
    if not uuid_string:
        return False
    return bool(re.match(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        uuid_string,
        re.IGNORECASE
    ))
