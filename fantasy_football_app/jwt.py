import jwt
import requests
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from django.conf import settings

# def decode_and_verify_token(token):
#     try:
#         # Fetch the public keys from Cognito
#         # jwks_url = f"{settings.COGNITO_USER_POOL_URL}/.well-known/jwks.json"
#         jwks_url = settings.OAUTH2_TENANT_JWKS
#         response = requests.get(jwks_url)
#         response.raise_for_status()
#         jwks = response.json()

#         # Get the header to find the key id
#         headers = jwt.get_unverified_header(token)
#         key_id = headers['kid']

#         # Find the appropriate key in the JWKS
#         public_key = None
#         for key in jwks['keys']:
#             if key['kid'] == key_id:
#                 public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
#                 break

#         if not public_key:
#             raise ValueError("Public key not found for token.")

#         # Decode and verify the token
#         decoded_token = jwt.decode(
#             token,
#             public_key,
#             algorithms=["RS256"],
#             audience=settings.AWS_COGNITO['CLIENT_ID'],
#             issuer=f"{settings.COGNITO_USER_POOL_URL}"
#         )

#         return decoded_token

#     except ExpiredSignatureError:
#         raise ValueError("Token has expired.")
#     except InvalidTokenError as e:
#         raise ValueError(f"Invalid token: {str(e)}")
#     except requests.RequestException as e:
#         raise ValueError(f"Error fetching JWKS: {str(e)}")


def decode_and_verify_token(token: str):
    """Decode JWT and validate the claims."""
    print(f"Decoding JWT token:\n > '{token}'")
    # jwks = get_jwks()
    jwks_url = settings.OAUTH2_TENANT_JWKS
    response = requests.get(jwks_url)
    response.raise_for_status()
    jwks = response.json()

    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    
    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e'],
            }
    
    if not rsa_key:
        raise ValueError("Token has expired.")

    try:
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=settings.AWS_COGNITO['CLIENT_ID'],
            options={"verify_aud": True}
        )
        return payload
    except InvalidTokenError as e:
        raise ValueError(f"Invalid token: {str(e)}")