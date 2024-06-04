import time
import uuid
from enum import Enum

import jwt
from pydantic import BaseModel, Field


class JWTTokenTypes(str, Enum):
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"


class JWTTokenAttributes(BaseModel):
    expires_in: int = Field(serialization_alias="exp", default=None)
    issued_at: int = Field(serialization_alias="iat", default=None)
    never_seen_before: int = Field(serialization_alias="nbf", default=None)
    issuer: str = Field(serialization_alias="iss", default=None)
    audience: str = Field(serialization_alias="aud", default=None)
    token_type: JWTTokenTypes = Field(serialization_alias="token_type", default="access_token")
    token_id: str = Field(serialization_alias="token_id", default=None)


class JWTAuthWithRefresh(BaseModel):
    algorithm: str = "HS256"
    issuer: str = "jwt.example.com"
    secret_key: str
    revoked_token_ids: list[str]
    access_token_expire_seconds: int
    refresh_token_expire_seconds: int

    def __init__(
            self,
            *,
            secret_key: str,
            revoked_token_ids: list[str],
            access_token_expire_seconds: int,
            refresh_token_expire_seconds: int,
            **kwargs,
    ):
        super().__init__(
            secret_key=secret_key,
            revoked_token_ids=revoked_token_ids,
            access_token_expire_seconds=access_token_expire_seconds,
            refresh_token_expire_seconds=refresh_token_expire_seconds,
            **kwargs,
        )

    def create_access_token(self, audience: str, payload: dict) -> str:
        cur_time = int(time.time())
        token_attributes = JWTTokenAttributes(
            expires_in=cur_time + self.access_token_expire_seconds,
            issued_at=cur_time,
            never_seen_before=cur_time,
            issuer=self.issuer,
            audience=audience,
            token_type=JWTTokenTypes.ACCESS_TOKEN,
            token_id=str(uuid.uuid4()),
        )

        combined_payload = {
            **token_attributes.model_dump(exclude_none=True, by_alias=True),
            **payload,
        }
        return jwt.encode(
            payload=combined_payload,
            key=self.secret_key,
            algorithm=self.algorithm,
        )

    def create_refresh_token(self, audience: str) -> str:
        cur_time = int(time.time())
        token_attributes = JWTTokenAttributes(
            expires_in=cur_time + self.refresh_token_expire_seconds,
            issued_at=cur_time,
            never_seen_before=cur_time,
            issuer=self.issuer,
            audience=audience,
            token_type=JWTTokenTypes.REFRESH_TOKEN,
            token_id=str(uuid.uuid4()),
        )

        return jwt.encode(
            payload=token_attributes.model_dump(exclude_none=True, by_alias=True),
            key=self.secret_key,
            algorithm=self.algorithm,
        )

    def verify_token(self, audience: str, token: str) -> dict:
        payload = jwt.decode(
            jwt=token,
            key=self.secret_key,
            algorithms=[self.algorithm],
            issuer=self.issuer,
            audience=audience,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
                "verify_nbf": True,
                "verify_iat": True,
            }
        )
        if payload.get("token_id") in self.revoked_token_ids:
            raise jwt.InvalidTokenError("Token has been revoked")

        return payload
