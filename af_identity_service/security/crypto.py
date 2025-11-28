# ============================================================
# SPDX-License-Identifier: GPL-3.0-or-later
# This program was generated as part of the AgentFoundry project.
# Copyright (C) 2025  John Brosnihan
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ============================================================
"""Cryptographic utilities for token encryption.

This module provides AES-256-GCM encryption for sensitive token data.
The encryption key is loaded from the GITHUB_TOKEN_ENC_KEY environment
variable and must be a 32-byte (256-bit) key encoded as hex or base64.

Key Management:
    - Keys should be generated with sufficient entropy (e.g., secrets.token_bytes(32))
    - Keys must be stored securely, preferably in a KMS or secrets manager
    - Key rotation requires re-encrypting all stored tokens before removing old key

Security Properties:
    - AES-256-GCM provides authenticated encryption (confidentiality + integrity)
    - Random 12-byte IVs are generated for each encryption operation
    - Ciphertext includes authentication tag to detect tampering
    - No plaintext is ever logged

Example:
    >>> import os
    >>> os.environ["GITHUB_TOKEN_ENC_KEY"] = secrets.token_hex(32)
    >>> encryptor = TokenEncryptor.from_env()
    >>> ciphertext = encryptor.encrypt("my_secret_token")
    >>> plaintext = encryptor.decrypt(ciphertext)
"""

import base64
import os
import secrets
from abc import ABC, abstractmethod

import structlog

logger = structlog.get_logger(__name__)

# AES-256-GCM constants
AES_KEY_SIZE = 32  # 256 bits
GCM_IV_SIZE = 12  # 96 bits - recommended for GCM
GCM_TAG_SIZE = 16  # 128 bits
KEY_ID_SIZE = 8  # 8 bytes for key version identifier


class TokenEncryptionError(Exception):
    """Base exception for token encryption errors.

    This exception provides safe error messages that do not leak
    sensitive information like keys or plaintext.
    """

    pass


class EncryptionKeyError(TokenEncryptionError):
    """Raised when the encryption key is missing, invalid, or cannot be loaded."""

    pass


class DecryptionError(TokenEncryptionError):
    """Raised when decryption fails.

    Common causes:
    - Key rotation occurred before re-encrypting tokens
    - Ciphertext was corrupted or tampered with
    - Wrong key is being used

    The error message is intentionally generic to avoid leaking information.
    """

    pass


class TokenEncryptor(ABC):
    """Abstract base class for token encryption.

    Implementations must provide encrypt() and decrypt() methods.
    This abstraction allows swapping encryption backends (e.g., local AES vs KMS).

    AAD (Authenticated Associated Data) is used to bind ciphertext to a specific
    context (e.g., user_id), preventing token swapping attacks where an attacker
    with database write access moves encrypted tokens between users.
    """

    @abstractmethod
    def encrypt(self, plaintext: str, aad: bytes | None = None) -> bytes:
        """Encrypt a plaintext string.

        Args:
            plaintext: The string to encrypt.
            aad: Optional authenticated associated data (e.g., user_id bytes).
                 AAD is authenticated but not encrypted, binding ciphertext
                 to a specific context to prevent token swapping.

        Returns:
            The encrypted ciphertext as bytes (includes IV and auth tag).

        Raises:
            TokenEncryptionError: If encryption fails.
        """
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes, aad: bytes | None = None) -> str:
        """Decrypt ciphertext back to plaintext string.

        Args:
            ciphertext: The encrypted data (includes IV and auth tag).
            aad: Optional authenticated associated data. Must match the AAD
                 used during encryption, or decryption will fail.

        Returns:
            The decrypted plaintext string.

        Raises:
            DecryptionError: If decryption fails (wrong key, corrupted data,
                            AAD mismatch, etc.).
        """
        pass


class AES256GCMEncryptor(TokenEncryptor):
    """AES-256-GCM implementation of TokenEncryptor.

    This implementation uses the cryptography library for AES-256-GCM
    authenticated encryption with random 12-byte IVs.

    Ciphertext format: IV (12 bytes) || ciphertext || auth_tag (16 bytes)

    AAD (Authenticated Associated Data) Support:
        When AAD is provided, it is authenticated but not encrypted. This binds
        the ciphertext to a specific context (e.g., user_id), preventing an
        attacker with database write access from swapping tokens between users.

    Attributes:
        _key: The 32-byte AES key (never logged or exposed).
    """

    def __init__(self, key: bytes) -> None:
        """Initialize the encryptor with an AES-256 key.

        Args:
            key: A 32-byte (256-bit) encryption key.

        Raises:
            EncryptionKeyError: If the key is not exactly 32 bytes.
        """
        if len(key) != AES_KEY_SIZE:
            raise EncryptionKeyError(
                f"Encryption key must be exactly {AES_KEY_SIZE} bytes, "
                f"got {len(key)} bytes"
            )
        self._key = key
        logger.debug("AES256GCMEncryptor initialized")

    def encrypt(self, plaintext: str, aad: bytes | None = None) -> bytes:
        """Encrypt a plaintext string using AES-256-GCM.

        Generates a random 12-byte IV for each encryption operation.

        Args:
            plaintext: The string to encrypt.
            aad: Optional authenticated associated data (e.g., user_id bytes).
                 AAD is authenticated but not encrypted, binding ciphertext
                 to a specific context to prevent token swapping.

        Returns:
            Bytes containing: IV (12) || ciphertext || auth_tag (16)

        Raises:
            TokenEncryptionError: If encryption fails.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        try:
            # Generate random IV
            iv = secrets.token_bytes(GCM_IV_SIZE)

            # Encrypt with AES-256-GCM
            aesgcm = AESGCM(self._key)
            ciphertext_with_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), aad)

            # Return IV || ciphertext_with_tag
            return iv + ciphertext_with_tag

        except Exception as e:
            # Log error without exposing plaintext
            logger.error("Encryption failed", error_type=type(e).__name__)
            raise TokenEncryptionError("Failed to encrypt token") from e

    def decrypt(self, ciphertext: bytes, aad: bytes | None = None) -> str:
        """Decrypt ciphertext back to plaintext string.

        Args:
            ciphertext: Bytes containing: IV (12) || ciphertext || auth_tag (16)
            aad: Optional authenticated associated data. Must match the AAD
                 used during encryption, or decryption will fail.

        Returns:
            The decrypted plaintext string.

        Raises:
            DecryptionError: If decryption fails.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if len(ciphertext) < GCM_IV_SIZE + GCM_TAG_SIZE:
            logger.warning("Ciphertext too short for decryption")
            raise DecryptionError(
                "Decryption failed - ciphertext may be corrupted or key may have changed"
            )

        try:
            # Extract IV and ciphertext_with_tag
            iv = ciphertext[:GCM_IV_SIZE]
            ciphertext_with_tag = ciphertext[GCM_IV_SIZE:]

            # Decrypt with AES-256-GCM
            aesgcm = AESGCM(self._key)
            plaintext_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, aad)

            return plaintext_bytes.decode("utf-8")

        except Exception as e:
            # Log error without exposing any sensitive data
            logger.warning(
                "Decryption failed - key rotation or data corruption may have occurred",
                error_type=type(e).__name__,
            )
            raise DecryptionError(
                "Decryption failed - ciphertext may be corrupted or key may have changed. "
                "If key was rotated, existing tokens must be re-encrypted with the new key."
            ) from e

    @classmethod
    def from_env(cls, env_var: str = "GITHUB_TOKEN_ENC_KEY") -> "AES256GCMEncryptor":
        """Create an encryptor from an environment variable.

        The key can be provided as:
        - 64 hex characters (32 bytes)
        - 44 base64 characters (32 bytes)

        Args:
            env_var: Name of the environment variable containing the key.

        Returns:
            An initialized AES256GCMEncryptor.

        Raises:
            EncryptionKeyError: If the key is missing or invalid.
        """
        key_str = os.environ.get(env_var)
        if not key_str:
            raise EncryptionKeyError(
                f"{env_var} environment variable is required for token encryption. "
                "Generate a key with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        key = _parse_key(key_str, env_var)
        return cls(key)


def _parse_key(key_str: str, source: str = "key") -> bytes:
    """Parse a key from hex or base64 encoding.

    Args:
        key_str: The key string in hex or base64 format.
        source: Description of key source for error messages.

    Returns:
        The decoded key bytes.

    Raises:
        EncryptionKeyError: If the key cannot be parsed or is wrong size.
    """
    key_str = key_str.strip()

    # Try hex first (64 chars = 32 bytes)
    if len(key_str) == 64:
        try:
            key = bytes.fromhex(key_str)
            if len(key) == AES_KEY_SIZE:
                return key
        except ValueError:
            pass

    # Try base64 (44 chars with padding = 32 bytes)
    try:
        # Handle both with and without padding
        padded = key_str
        if len(key_str) % 4:
            padded = key_str + "=" * (4 - len(key_str) % 4)
        key = base64.b64decode(padded)
        if len(key) == AES_KEY_SIZE:
            return key
    except Exception:
        pass

    raise EncryptionKeyError(
        f"Invalid {source}: must be a 256-bit key encoded as 64 hex characters "
        "or base64. Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )


class KeyringEncryptor(TokenEncryptor):
    """Multi-key encryptor supporting non-disruptive key rotation.

    This implementation maintains a keyring of multiple keys identified by
    version IDs. It always encrypts with the current (newest) key but can
    decrypt ciphertext encrypted with any key in the keyring.

    Ciphertext format: key_id (8 bytes) || IV (12 bytes) || ciphertext || auth_tag (16 bytes)

    Key Rotation Strategy:
        1. Add new key to keyring as the current key
        2. New encryptions use the new key
        3. Old ciphertexts are decrypted with their original key from the keyring
        4. Gradually re-encrypt old data with the new key
        5. Remove old keys from keyring after all data is re-encrypted

    Environment Variables:
        - GITHUB_TOKEN_ENC_KEY: Current encryption key (used for new encryptions)
        - GITHUB_TOKEN_ENC_KEY_OLD: Previous key (used only for decryption during rotation)

    Attributes:
        _keys: Dictionary mapping key IDs to key bytes.
        _current_key_id: The ID of the key used for encryption.
        _current_key: The current key bytes.
    """

    def __init__(self, keys: dict[str, bytes], current_key_id: str) -> None:
        """Initialize the keyring encryptor.

        Args:
            keys: Dictionary mapping key IDs (8 chars max) to 32-byte keys.
            current_key_id: The ID of the key to use for new encryptions.

        Raises:
            EncryptionKeyError: If keys dict is empty, current_key_id not in keys,
                               key IDs are too long, or any key is wrong size.
        """
        if not keys:
            raise EncryptionKeyError("At least one encryption key is required")

        if current_key_id not in keys:
            raise EncryptionKeyError(
                f"Current key ID '{current_key_id}' not found in keyring"
            )

        # Validate all keys
        for key_id, key in keys.items():
            if len(key_id.encode("utf-8")) > KEY_ID_SIZE:
                raise EncryptionKeyError(
                    f"Key ID '{key_id}' exceeds maximum length of {KEY_ID_SIZE} bytes"
                )
            if len(key) != AES_KEY_SIZE:
                raise EncryptionKeyError(
                    f"Key '{key_id}' must be exactly {AES_KEY_SIZE} bytes, "
                    f"got {len(key)} bytes"
                )

        self._keys = keys
        self._current_key_id = current_key_id
        self._current_key = keys[current_key_id]
        logger.debug(
            "KeyringEncryptor initialized",
            num_keys=len(keys),
            current_key_id=current_key_id,
        )

    def _encode_key_id(self, key_id: str) -> bytes:
        """Encode key ID to fixed-size bytes with null padding."""
        encoded = key_id.encode("utf-8")
        return encoded.ljust(KEY_ID_SIZE, b"\x00")

    def _decode_key_id(self, key_id_bytes: bytes) -> str:
        """Decode key ID from fixed-size bytes, stripping null padding."""
        return key_id_bytes.rstrip(b"\x00").decode("utf-8")

    def encrypt(self, plaintext: str, aad: bytes | None = None) -> bytes:
        """Encrypt plaintext using the current key.

        The ciphertext includes the key ID prefix for decryption routing.

        Args:
            plaintext: The string to encrypt.
            aad: Optional authenticated associated data.

        Returns:
            Bytes: key_id (8) || IV (12) || ciphertext || auth_tag (16)

        Raises:
            TokenEncryptionError: If encryption fails.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        try:
            # Generate random IV
            iv = secrets.token_bytes(GCM_IV_SIZE)

            # Encrypt with AES-256-GCM using current key
            aesgcm = AESGCM(self._current_key)
            ciphertext_with_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), aad)

            # Return key_id || IV || ciphertext_with_tag
            key_id_bytes = self._encode_key_id(self._current_key_id)
            return key_id_bytes + iv + ciphertext_with_tag

        except Exception as e:
            logger.error("Encryption failed", error_type=type(e).__name__)
            raise TokenEncryptionError("Failed to encrypt token") from e

    def decrypt(self, ciphertext: bytes, aad: bytes | None = None) -> str:
        """Decrypt ciphertext using the appropriate key from the keyring.

        Extracts the key ID from the ciphertext prefix and uses the
        corresponding key for decryption.

        Args:
            ciphertext: Bytes: key_id (8) || IV (12) || ciphertext || auth_tag (16)
            aad: Optional authenticated associated data.

        Returns:
            The decrypted plaintext string.

        Raises:
            DecryptionError: If decryption fails (unknown key ID, wrong key, etc.).
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        min_length = KEY_ID_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE
        if len(ciphertext) < min_length:
            logger.warning("Ciphertext too short for decryption")
            raise DecryptionError(
                "Decryption failed - ciphertext may be corrupted or key may have changed"
            )

        try:
            # Extract key ID, IV, and encrypted data
            key_id_bytes = ciphertext[:KEY_ID_SIZE]
            key_id = self._decode_key_id(key_id_bytes)
            iv = ciphertext[KEY_ID_SIZE : KEY_ID_SIZE + GCM_IV_SIZE]
            ciphertext_with_tag = ciphertext[KEY_ID_SIZE + GCM_IV_SIZE :]

            # Look up the key
            key = self._keys.get(key_id)
            if key is None:
                logger.warning(
                    "Unknown key ID during decryption",
                    key_id=key_id,
                    error_code="UNKNOWN_KEY_ID",
                )
                raise DecryptionError(
                    f"Decryption failed - unknown key ID. The key '{key_id}' may have "
                    "been removed from the keyring before re-encrypting all tokens."
                )

            # Decrypt with the appropriate key
            aesgcm = AESGCM(key)
            plaintext_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, aad)

            return plaintext_bytes.decode("utf-8")

        except DecryptionError:
            raise
        except Exception as e:
            logger.warning(
                "Decryption failed - key rotation or data corruption may have occurred",
                error_type=type(e).__name__,
            )
            raise DecryptionError(
                "Decryption failed - ciphertext may be corrupted or key may have changed. "
                "If key was rotated, existing tokens must be re-encrypted with the new key."
            ) from e

    @classmethod
    def from_env(
        cls,
        current_key_env: str = "GITHUB_TOKEN_ENC_KEY",
        old_key_env: str = "GITHUB_TOKEN_ENC_KEY_OLD",
    ) -> "KeyringEncryptor":
        """Create a keyring encryptor from environment variables.

        Loads the current key and optionally an old key for rotation support.

        Args:
            current_key_env: Env var name for the current encryption key.
            old_key_env: Env var name for the previous key (during rotation).

        Returns:
            An initialized KeyringEncryptor.

        Raises:
            EncryptionKeyError: If the current key is missing or invalid.
        """
        current_key_str = os.environ.get(current_key_env)
        if not current_key_str:
            raise EncryptionKeyError(
                f"{current_key_env} environment variable is required for token encryption. "
                "Generate a key with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        keys: dict[str, bytes] = {}

        # Parse current key
        current_key = _parse_key(current_key_str, current_key_env)
        current_key_id = "current"
        keys[current_key_id] = current_key

        # Parse old key if present (for key rotation)
        old_key_str = os.environ.get(old_key_env)
        if old_key_str:
            try:
                old_key = _parse_key(old_key_str, old_key_env)
                keys["old"] = old_key
                logger.info(
                    "Loaded old encryption key for rotation support",
                    old_key_env=old_key_env,
                )
            except EncryptionKeyError as e:
                logger.warning(
                    "Invalid old encryption key - ignoring",
                    old_key_env=old_key_env,
                    error=str(e),
                )

        return cls(keys=keys, current_key_id=current_key_id)

class NoOpEncryptor(TokenEncryptor):
    """No-operation encryptor for development/testing only.

    WARNING: This encryptor does NOT encrypt data. It only base64-encodes
    for format compatibility. Use ONLY in development environments.
    """

    def __init__(self) -> None:
        """Initialize the no-op encryptor with a warning."""
        logger.warning(
            "NoOpEncryptor initialized - tokens are NOT encrypted! "
            "This is only suitable for development."
        )

    def encrypt(self, plaintext: str, aad: bytes | None = None) -> bytes:
        """Base64-encode the plaintext (no real encryption).

        Args:
            plaintext: The string to encode.
            aad: Ignored in no-op mode.

        Returns:
            Base64-encoded bytes.
        """
        return base64.b64encode(plaintext.encode("utf-8"))

    def decrypt(self, ciphertext: bytes, aad: bytes | None = None) -> str:
        """Base64-decode the ciphertext.

        Args:
            ciphertext: Base64-encoded bytes.
            aad: Ignored in no-op mode.

        Returns:
            The decoded string.

        Raises:
            DecryptionError: If decoding fails.
        """
        try:
            return base64.b64decode(ciphertext).decode("utf-8")
        except Exception as e:
            raise DecryptionError("Failed to decode token") from e


def get_token_encryptor(
    require_encryption: bool = True,
    env_var: str = "GITHUB_TOKEN_ENC_KEY",
    old_key_env: str = "GITHUB_TOKEN_ENC_KEY_OLD",
    use_keyring: bool = True,
) -> TokenEncryptor:
    """Get a TokenEncryptor instance based on environment configuration.

    In production (require_encryption=True), this requires a valid encryption
    key and returns an encryptor. If use_keyring=True and an old key is present,
    returns a KeyringEncryptor for key rotation support.

    In development (require_encryption=False), this returns a NoOpEncryptor
    if no key is configured, with a warning.

    Args:
        require_encryption: If True, raises error when key is missing.
        env_var: Name of the environment variable containing the current key.
        old_key_env: Name of the environment variable for the old key (rotation).
        use_keyring: If True, uses KeyringEncryptor when old key is present.

    Returns:
        A TokenEncryptor instance.

    Raises:
        EncryptionKeyError: If require_encryption is True and key is missing.
    """
    key_str = os.environ.get(env_var)

    if key_str:
        old_key_str = os.environ.get(old_key_env)

        # Use KeyringEncryptor if rotation support is enabled and old key exists
        if use_keyring and old_key_str:
            return KeyringEncryptor.from_env(env_var, old_key_env)

        # Fall back to simple AES256GCMEncryptor
        return AES256GCMEncryptor.from_env(env_var)

    if require_encryption:
        raise EncryptionKeyError(
            f"{env_var} environment variable is required in production. "
            "Generate a key with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    # Development mode - use no-op encryptor
    return NoOpEncryptor()
