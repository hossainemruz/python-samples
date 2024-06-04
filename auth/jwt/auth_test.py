import unittest

import jwt

from auth import JWTAuthWithRefresh


class JWTAuthTest(unittest.TestCase):
    def test_access_key_creation(self):
        jwt_auth = JWTAuthWithRefresh(
            secret_key="test_secret",
            revoked_token_ids=[],
            access_token_expire_seconds=60,
            refresh_token_expire_seconds=60,
        )
        access_token = jwt_auth.create_access_token(audience="test", payload={"data": "test"})
        print(access_token)

    def test_refresh_key_creation(self):
        jwt_auth = JWTAuthWithRefresh(
            secret_key="test_secret",
            revoked_token_ids=[],
            access_token_expire_seconds=60,
            refresh_token_expire_seconds=60,
        )
        refresh_token = jwt_auth.create_refresh_token(audience="test")
        print(refresh_token)

    def test_verify_access_token(self):
        jwt_auth = JWTAuthWithRefresh(
            secret_key="test_secret",
            revoked_token_ids=[],
            access_token_expire_seconds=60,
            refresh_token_expire_seconds=60,
        )
        access_token = jwt_auth.create_access_token(audience="test", payload={"data": "test"})
        jwt_auth.verify_token(token=access_token, audience="test")

    def test_verify_access_token_revocation(self):
        jwt_auth = JWTAuthWithRefresh(
            secret_key="test_secret",
            revoked_token_ids=[],
            access_token_expire_seconds=60,
            refresh_token_expire_seconds=60,
        )
        access_token = jwt_auth.create_access_token(audience="test", payload={"data": "test"})

        payload = jwt.decode(
            jwt=access_token,
            key=jwt_auth.secret_key,
            algorithms=["HS256"],
            issuer=jwt_auth.issuer,
            audience="test",
        )
        jwt_auth.revoked_token_ids.append(payload.get("token_id"))

        try:
            jwt_auth.verify_token(token=access_token, audience="test")
            self.fail("Token should be revoked")
        except jwt.InvalidTokenError:
            pass


if __name__ == '__main__':
    unittest.main()
