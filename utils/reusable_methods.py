import datetime
import jwt
import random
from cryptography.fernet import Fernet
from rest_framework.utils.serializer_helpers import ReturnList
from User_Management_Backend.settings import JWT_ENCODING_SECRET_KEY, JWT_TOKEN_EXPIRY_DELTA


def encrypt_token(token):
    """Encrypt the jwt token so users cannot see token content"""
    secret_key_bytes = b"LD7i4Pe_VDdXhRyHSQrQe3RpIJ8RymjbU_zA0Yi4Hlg="
    fernet = Fernet(secret_key_bytes)
    return fernet.encrypt(token.encode()).decode("utf-8")


def decrypt_token(encrypted_token):
    """Decrypt the encrypted token string to get the original jwt token"""
    secret_key_bytes = b"LD7i4Pe_VDdXhRyHSQrQe3RpIJ8RymjbU_zA0Yi4Hlg="
    fernet = Fernet(secret_key_bytes)
    return fernet.decrypt(encrypted_token.encode()).decode()


def generate_access_token(user):
    # nbf: Defines the time before which the JWT MUST NOT be accepted for processing
    access_token_payload = {
        'username': user.username,
        'iat': datetime.datetime.utcnow(),
    }
    exp_claim = {
        "exp": access_token_payload.get("iat") + datetime.timedelta(seconds=int(JWT_TOKEN_EXPIRY_DELTA))}
    # Add expiry claim to token_payload
    token_payload = {**access_token_payload, **exp_claim}
    encoded_token = jwt.encode(token_payload, JWT_ENCODING_SECRET_KEY, algorithm='HS256')
    jwt_token = encrypt_token(encoded_token)
    return jwt_token


def get_first_error_message(serialized_errors, default_message=""):
    if not serialized_errors:
        return default_message
    try:
        serialized_error_dict = serialized_errors
        if isinstance(serialized_errors, ReturnList):
            serialized_error_dict = serialized_errors[0]

        serialized_errors_keys = list(serialized_error_dict.keys())
        print(serialized_errors_keys)
        try:
            message = serialized_error_dict[serialized_errors_keys[0]][0].replace("This", serialized_errors_keys[0])
            print(message)
            return message
        except:
            return serialized_error_dict[serialized_errors_keys[0]][0]

    except Exception as e:
        return default_message
    
    
def generate_six_length_random_number():
    random_number = random.SystemRandom().randint(100000, 999999)
    return random_number
