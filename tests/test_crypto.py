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
"""Tests for token encryption module."""

import base64
import os
import secrets
from unittest import mock

import pytest

from af_identity_service.security.crypto import (
    KEY_ID_SIZE,
    AES256GCMEncryptor,
    DecryptionError,
    EncryptionKeyError,
    KeyringEncryptor,
    NoOpEncryptor,
    TokenEncryptionError,
    _parse_key,
    get_token_encryptor,
)


class TestAES256GCMEncryptor:
    """Tests for AES256GCMEncryptor."""

    @pytest.fixture
    def valid_key(self) -> bytes:
        """Generate a valid 256-bit key."""
        return secrets.token_bytes(32)

    @pytest.fixture
    def encryptor(self, valid_key: bytes) -> AES256GCMEncryptor:
        """Create an encryptor with a valid key."""
        return AES256GCMEncryptor(valid_key)

    def test_init_with_valid_key(self, valid_key: bytes) -> None:
        """Test that encryptor initializes with a valid 32-byte key."""
        encryptor = AES256GCMEncryptor(valid_key)
        assert encryptor is not None

    def test_init_with_invalid_key_length_raises_error(self) -> None:
        """Test that encryptor raises error for invalid key length."""
        with pytest.raises(EncryptionKeyError) as exc_info:
            AES256GCMEncryptor(b"too_short")
        assert "32 bytes" in str(exc_info.value)

    def test_encrypt_returns_bytes(self, encryptor: AES256GCMEncryptor) -> None:
        """Test that encrypt returns bytes."""
        plaintext = "my_secret_token"
        ciphertext = encryptor.encrypt(plaintext)
        assert isinstance(ciphertext, bytes)

    def test_encrypt_returns_different_ciphertext_each_time(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that encrypt uses random IVs (different ciphertext each time)."""
        plaintext = "my_secret_token"
        ciphertext1 = encryptor.encrypt(plaintext)
        ciphertext2 = encryptor.encrypt(plaintext)
        # Random IVs should produce different ciphertexts
        assert ciphertext1 != ciphertext2

    def test_decrypt_recovers_plaintext(self, encryptor: AES256GCMEncryptor) -> None:
        """Test that decrypt recovers the original plaintext."""
        plaintext = "my_secret_token"
        ciphertext = encryptor.encrypt(plaintext)
        decrypted = encryptor.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_decrypt_with_unicode(self, encryptor: AES256GCMEncryptor) -> None:
        """Test that encrypt/decrypt handles unicode characters."""
        plaintext = "token_with_émojis_🎉_and_ünïcödé"
        ciphertext = encryptor.encrypt(plaintext)
        decrypted = encryptor.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_decrypt_with_empty_string(self, encryptor: AES256GCMEncryptor) -> None:
        """Test that encrypt/decrypt handles empty strings."""
        plaintext = ""
        ciphertext = encryptor.encrypt(plaintext)
        decrypted = encryptor.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_decrypt_with_long_token(self, encryptor: AES256GCMEncryptor) -> None:
        """Test that encrypt/decrypt handles long tokens."""
        plaintext = "x" * 10000  # 10KB token
        ciphertext = encryptor.encrypt(plaintext)
        decrypted = encryptor.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_with_aad(self, encryptor: AES256GCMEncryptor) -> None:
        """Test that encrypt/decrypt works with AAD."""
        plaintext = "my_secret_token"
        aad = b"user_id_12345"
        ciphertext = encryptor.encrypt(plaintext, aad)
        decrypted = encryptor.decrypt(ciphertext, aad)
        assert decrypted == plaintext

    def test_decrypt_with_wrong_aad_raises_error(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that decrypt fails with wrong AAD."""
        plaintext = "my_secret_token"
        aad1 = b"user_id_1"
        aad2 = b"user_id_2"

        ciphertext = encryptor.encrypt(plaintext, aad1)

        # Decryption with wrong AAD should fail
        with pytest.raises(DecryptionError):
            encryptor.decrypt(ciphertext, aad2)

    def test_decrypt_without_aad_when_encrypted_with_aad_raises_error(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that decrypt fails if AAD is omitted when it was used in encryption."""
        plaintext = "my_secret_token"
        aad = b"user_id_12345"

        ciphertext = encryptor.encrypt(plaintext, aad)

        # Decryption without AAD should fail
        with pytest.raises(DecryptionError):
            encryptor.decrypt(ciphertext)

    def test_decrypt_with_wrong_key_raises_error(self, valid_key: bytes) -> None:
        """Test that decrypt fails with wrong key."""
        encryptor1 = AES256GCMEncryptor(valid_key)
        encryptor2 = AES256GCMEncryptor(secrets.token_bytes(32))

        plaintext = "my_secret_token"
        ciphertext = encryptor1.encrypt(plaintext)

        with pytest.raises(DecryptionError) as exc_info:
            encryptor2.decrypt(ciphertext)
        assert "corrupted or key may have changed" in str(exc_info.value)

    def test_decrypt_with_corrupted_ciphertext_raises_error(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that decrypt fails with corrupted ciphertext."""
        plaintext = "my_secret_token"
        ciphertext = encryptor.encrypt(plaintext)

        # Corrupt the ciphertext
        corrupted = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])

        with pytest.raises(DecryptionError):
            encryptor.decrypt(corrupted)

    def test_decrypt_with_too_short_ciphertext_raises_error(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that decrypt fails with ciphertext shorter than IV + tag."""
        with pytest.raises(DecryptionError) as exc_info:
            encryptor.decrypt(b"short")
        assert "corrupted" in str(exc_info.value)

    def test_ciphertext_contains_iv_plus_data(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that ciphertext is at least IV (12) + tag (16) bytes."""
        plaintext = "x"
        ciphertext = encryptor.encrypt(plaintext)
        # IV (12) + 1 byte plaintext encrypted + tag (16) = at least 29 bytes
        assert len(ciphertext) >= 12 + 16

    def test_from_env_with_hex_key(self) -> None:
        """Test creating encryptor from hex-encoded env var."""
        hex_key = secrets.token_hex(32)  # 64 hex chars
        with mock.patch.dict(os.environ, {"TEST_KEY": hex_key}):
            encryptor = AES256GCMEncryptor.from_env("TEST_KEY")
            assert encryptor is not None
            # Verify it works
            plaintext = "test"
            assert encryptor.decrypt(encryptor.encrypt(plaintext)) == plaintext

    def test_from_env_with_base64_key(self) -> None:
        """Test creating encryptor from base64-encoded env var."""
        raw_key = secrets.token_bytes(32)
        b64_key = base64.b64encode(raw_key).decode("ascii")
        with mock.patch.dict(os.environ, {"TEST_KEY": b64_key}):
            encryptor = AES256GCMEncryptor.from_env("TEST_KEY")
            assert encryptor is not None
            # Verify it works
            plaintext = "test"
            assert encryptor.decrypt(encryptor.encrypt(plaintext)) == plaintext

    def test_from_env_missing_key_raises_error(self) -> None:
        """Test that missing env var raises error."""
        with mock.patch.dict(os.environ, {}, clear=True):
            # Ensure MISSING_KEY is not set
            if "MISSING_KEY" in os.environ:
                del os.environ["MISSING_KEY"]
            with pytest.raises(EncryptionKeyError) as exc_info:
                AES256GCMEncryptor.from_env("MISSING_KEY")
            assert "MISSING_KEY" in str(exc_info.value)
            assert "required" in str(exc_info.value)

    def test_from_env_invalid_key_raises_error(self) -> None:
        """Test that invalid key format raises error."""
        with mock.patch.dict(os.environ, {"TEST_KEY": "invalid_key"}):
            with pytest.raises(EncryptionKeyError) as exc_info:
                AES256GCMEncryptor.from_env("TEST_KEY")
            assert "256-bit key" in str(exc_info.value)


class TestParseKey:
    """Tests for _parse_key function."""

    def test_parse_hex_key(self) -> None:
        """Test parsing a valid hex key."""
        hex_key = "a" * 64  # 64 hex chars = 32 bytes
        key = _parse_key(hex_key, "test")
        assert len(key) == 32
        assert key == bytes.fromhex(hex_key)

    def test_parse_base64_key(self) -> None:
        """Test parsing a valid base64 key."""
        raw_key = secrets.token_bytes(32)
        b64_key = base64.b64encode(raw_key).decode("ascii")
        key = _parse_key(b64_key, "test")
        assert key == raw_key

    def test_parse_base64_key_without_padding(self) -> None:
        """Test parsing base64 key without padding."""
        raw_key = secrets.token_bytes(32)
        b64_key = base64.b64encode(raw_key).decode("ascii").rstrip("=")
        key = _parse_key(b64_key, "test")
        assert key == raw_key

    def test_parse_key_with_whitespace(self) -> None:
        """Test that whitespace is stripped from key."""
        hex_key = "  " + "a" * 64 + "  \n"
        key = _parse_key(hex_key, "test")
        assert len(key) == 32

    def test_parse_invalid_key_raises_error(self) -> None:
        """Test that invalid key raises error."""
        with pytest.raises(EncryptionKeyError) as exc_info:
            _parse_key("not_a_valid_key", "test")
        assert "256-bit key" in str(exc_info.value)

    def test_parse_wrong_size_hex_raises_error(self) -> None:
        """Test that wrong-size hex key raises error."""
        with pytest.raises(EncryptionKeyError):
            _parse_key("a" * 32, "test")  # 16 bytes, not 32


class TestNoOpEncryptor:
    """Tests for NoOpEncryptor (development only)."""

    @pytest.fixture
    def encryptor(self) -> NoOpEncryptor:
        """Create a NoOpEncryptor."""
        return NoOpEncryptor()

    def test_encrypt_returns_base64(self, encryptor: NoOpEncryptor) -> None:
        """Test that encrypt returns base64-encoded data."""
        plaintext = "my_token"
        ciphertext = encryptor.encrypt(plaintext)
        # Should be valid base64
        decoded = base64.b64decode(ciphertext).decode("utf-8")
        assert decoded == plaintext

    def test_decrypt_returns_plaintext(self, encryptor: NoOpEncryptor) -> None:
        """Test that decrypt returns original plaintext."""
        plaintext = "my_token"
        ciphertext = encryptor.encrypt(plaintext)
        decrypted = encryptor.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_decrypt_invalid_base64_raises_error(self, encryptor: NoOpEncryptor) -> None:
        """Test that invalid base64 raises DecryptionError."""
        with pytest.raises(DecryptionError):
            encryptor.decrypt(b"not valid base64!!!")


class TestGetTokenEncryptor:
    """Tests for get_token_encryptor factory function."""

    def test_returns_aes_encryptor_when_key_set(self) -> None:
        """Test that AES encryptor is returned when key is set."""
        hex_key = secrets.token_hex(32)
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN_ENC_KEY": hex_key}):
            encryptor = get_token_encryptor(require_encryption=True)
            assert isinstance(encryptor, AES256GCMEncryptor)

    def test_raises_error_when_key_missing_and_required(self) -> None:
        """Test that error is raised when key is missing but required."""
        with mock.patch.dict(os.environ, {}, clear=True):
            if "GITHUB_TOKEN_ENC_KEY" in os.environ:
                del os.environ["GITHUB_TOKEN_ENC_KEY"]
            with pytest.raises(EncryptionKeyError) as exc_info:
                get_token_encryptor(require_encryption=True)
            assert "required in production" in str(exc_info.value)

    def test_returns_noop_encryptor_when_key_missing_and_not_required(self) -> None:
        """Test that NoOpEncryptor is returned when key is missing but not required."""
        with mock.patch.dict(os.environ, {}, clear=True):
            if "GITHUB_TOKEN_ENC_KEY" in os.environ:
                del os.environ["GITHUB_TOKEN_ENC_KEY"]
            encryptor = get_token_encryptor(require_encryption=False)
            assert isinstance(encryptor, NoOpEncryptor)

    def test_custom_env_var_name(self) -> None:
        """Test using a custom environment variable name."""
        hex_key = secrets.token_hex(32)
        with mock.patch.dict(os.environ, {"CUSTOM_KEY": hex_key}):
            encryptor = get_token_encryptor(
                require_encryption=True, env_var="CUSTOM_KEY"
            )
            assert isinstance(encryptor, AES256GCMEncryptor)


class TestTokenEncryptionError:
    """Tests for token encryption exceptions."""

    def test_token_encryption_error_is_exception(self) -> None:
        """Test that TokenEncryptionError is an Exception."""
        error = TokenEncryptionError("test")
        assert isinstance(error, Exception)

    def test_encryption_key_error_is_token_encryption_error(self) -> None:
        """Test that EncryptionKeyError inherits from TokenEncryptionError."""
        error = EncryptionKeyError("test")
        assert isinstance(error, TokenEncryptionError)

    def test_decryption_error_is_token_encryption_error(self) -> None:
        """Test that DecryptionError inherits from TokenEncryptionError."""
        error = DecryptionError("test")
        assert isinstance(error, TokenEncryptionError)


class TestKeyringEncryptor:
    """Tests for KeyringEncryptor with key rotation support."""

    @pytest.fixture
    def key1(self) -> bytes:
        """Generate first key."""
        return secrets.token_bytes(32)

    @pytest.fixture
    def key2(self) -> bytes:
        """Generate second key."""
        return secrets.token_bytes(32)

    @pytest.fixture
    def encryptor(self, key1: bytes) -> KeyringEncryptor:
        """Create a keyring encryptor with a single key."""
        return KeyringEncryptor(keys={"current": key1}, current_key_id="current")

    def test_init_with_valid_keys(self, key1: bytes) -> None:
        """Test that keyring initializes with valid keys."""
        encryptor = KeyringEncryptor(keys={"v1": key1}, current_key_id="v1")
        assert encryptor is not None

    def test_init_with_multiple_keys(self, key1: bytes, key2: bytes) -> None:
        """Test that keyring initializes with multiple keys."""
        encryptor = KeyringEncryptor(
            keys={"current": key1, "old": key2}, current_key_id="current"
        )
        assert encryptor is not None

    def test_init_empty_keys_raises_error(self) -> None:
        """Test that empty keys dict raises error."""
        with pytest.raises(EncryptionKeyError) as exc_info:
            KeyringEncryptor(keys={}, current_key_id="v1")
        assert "At least one" in str(exc_info.value)

    def test_init_missing_current_key_raises_error(self, key1: bytes) -> None:
        """Test that missing current key ID raises error."""
        with pytest.raises(EncryptionKeyError) as exc_info:
            KeyringEncryptor(keys={"v1": key1}, current_key_id="v2")
        assert "not found" in str(exc_info.value)

    def test_init_invalid_key_size_raises_error(self) -> None:
        """Test that invalid key size raises error."""
        with pytest.raises(EncryptionKeyError) as exc_info:
            KeyringEncryptor(keys={"v1": b"short"}, current_key_id="v1")
        assert "32 bytes" in str(exc_info.value)

    def test_init_key_id_too_long_raises_error(self, key1: bytes) -> None:
        """Test that key ID exceeding max length raises error."""
        long_key_id = "a" * (KEY_ID_SIZE + 1)
        with pytest.raises(EncryptionKeyError) as exc_info:
            KeyringEncryptor(keys={long_key_id: key1}, current_key_id=long_key_id)
        assert "exceeds maximum" in str(exc_info.value)

    def test_encrypt_returns_bytes_with_key_id_prefix(
        self, encryptor: KeyringEncryptor
    ) -> None:
        """Test that encrypt returns bytes with key ID prefix."""
        plaintext = "my_secret_token"
        ciphertext = encryptor.encrypt(plaintext)
        assert isinstance(ciphertext, bytes)
        # Should start with key ID (8 bytes) + IV (12 bytes) + at least tag (16 bytes)
        assert len(ciphertext) >= KEY_ID_SIZE + 12 + 16

    def test_decrypt_recovers_plaintext(self, encryptor: KeyringEncryptor) -> None:
        """Test that decrypt recovers the original plaintext."""
        plaintext = "my_secret_token"
        ciphertext = encryptor.encrypt(plaintext)
        decrypted = encryptor.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_decrypt_with_aad(self, encryptor: KeyringEncryptor) -> None:
        """Test encrypt/decrypt with AAD."""
        plaintext = "my_secret_token"
        aad = b"user_id_12345"
        ciphertext = encryptor.encrypt(plaintext, aad)
        decrypted = encryptor.decrypt(ciphertext, aad)
        assert decrypted == plaintext

    def test_decrypt_with_wrong_aad_raises_error(
        self, encryptor: KeyringEncryptor
    ) -> None:
        """Test that wrong AAD raises error."""
        plaintext = "my_secret_token"
        ciphertext = encryptor.encrypt(plaintext, b"user_1")
        with pytest.raises(DecryptionError):
            encryptor.decrypt(ciphertext, b"user_2")

    def test_key_rotation_decrypt_old_tokens(
        self, key1: bytes, key2: bytes
    ) -> None:
        """Test that tokens encrypted with old key can be decrypted after rotation."""
        # Encrypt with old key
        old_encryptor = KeyringEncryptor(keys={"old": key1}, current_key_id="old")
        old_ciphertext = old_encryptor.encrypt("secret_token")

        # Create new encryptor with both keys, new key is current
        rotated_encryptor = KeyringEncryptor(
            keys={"current": key2, "old": key1}, current_key_id="current"
        )

        # Should be able to decrypt old ciphertext
        decrypted = rotated_encryptor.decrypt(old_ciphertext)
        assert decrypted == "secret_token"

    def test_key_rotation_new_encryptions_use_current_key(
        self, key1: bytes, key2: bytes
    ) -> None:
        """Test that new encryptions use the current key."""
        rotated_encryptor = KeyringEncryptor(
            keys={"current": key2, "old": key1}, current_key_id="current"
        )

        # New encryption should use current key
        ciphertext = rotated_encryptor.encrypt("new_secret")

        # Verify key ID in ciphertext is "current"
        key_id_bytes = ciphertext[:KEY_ID_SIZE]
        key_id = key_id_bytes.rstrip(b"\x00").decode("utf-8")
        assert key_id == "current"

    def test_decrypt_unknown_key_id_raises_error(
        self, key1: bytes, key2: bytes
    ) -> None:
        """Test that decrypting with unknown key ID raises error."""
        # Encrypt with one encryptor
        encryptor1 = KeyringEncryptor(keys={"v1": key1}, current_key_id="v1")
        ciphertext = encryptor1.encrypt("secret")

        # Try to decrypt with different encryptor missing v1 key
        encryptor2 = KeyringEncryptor(keys={"v2": key2}, current_key_id="v2")
        with pytest.raises(DecryptionError) as exc_info:
            encryptor2.decrypt(ciphertext)
        assert "unknown key" in str(exc_info.value).lower()

    def test_decrypt_too_short_ciphertext_raises_error(
        self, encryptor: KeyringEncryptor
    ) -> None:
        """Test that too short ciphertext raises error."""
        with pytest.raises(DecryptionError):
            encryptor.decrypt(b"short")

    def test_from_env_with_single_key(self) -> None:
        """Test creating keyring from env with single key."""
        hex_key = secrets.token_hex(32)
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN_ENC_KEY": hex_key}):
            encryptor = KeyringEncryptor.from_env()
            assert encryptor is not None
            # Verify it works
            plaintext = "test"
            assert encryptor.decrypt(encryptor.encrypt(plaintext)) == plaintext

    def test_from_env_with_rotation_keys(self) -> None:
        """Test creating keyring from env with current and old keys."""
        current_key = secrets.token_hex(32)
        old_key = secrets.token_hex(32)
        with mock.patch.dict(
            os.environ,
            {
                "GITHUB_TOKEN_ENC_KEY": current_key,
                "GITHUB_TOKEN_ENC_KEY_OLD": old_key,
            },
        ):
            encryptor = KeyringEncryptor.from_env()
            assert encryptor is not None
            # Verify it works
            plaintext = "test"
            assert encryptor.decrypt(encryptor.encrypt(plaintext)) == plaintext

    def test_from_env_missing_key_raises_error(self) -> None:
        """Test that missing current key raises error."""
        with mock.patch.dict(os.environ, {}, clear=True):
            if "GITHUB_TOKEN_ENC_KEY" in os.environ:
                del os.environ["GITHUB_TOKEN_ENC_KEY"]
            with pytest.raises(EncryptionKeyError):
                KeyringEncryptor.from_env()


class TestGetTokenEncryptorWithKeyring:
    """Tests for get_token_encryptor with keyring support."""

    def test_returns_keyring_encryptor_with_old_key(self) -> None:
        """Test that KeyringEncryptor is returned when old key is present."""
        current_key = secrets.token_hex(32)
        old_key = secrets.token_hex(32)
        with mock.patch.dict(
            os.environ,
            {
                "GITHUB_TOKEN_ENC_KEY": current_key,
                "GITHUB_TOKEN_ENC_KEY_OLD": old_key,
            },
        ):
            encryptor = get_token_encryptor(require_encryption=True, use_keyring=True)
            assert isinstance(encryptor, KeyringEncryptor)

    def test_returns_aes_encryptor_without_old_key(self) -> None:
        """Test that AES256GCMEncryptor is returned when no old key."""
        current_key = secrets.token_hex(32)
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN_ENC_KEY": current_key}):
            encryptor = get_token_encryptor(require_encryption=True, use_keyring=True)
            assert isinstance(encryptor, AES256GCMEncryptor)

    def test_returns_aes_encryptor_when_keyring_disabled(self) -> None:
        """Test that AES256GCMEncryptor is returned when keyring is disabled."""
        current_key = secrets.token_hex(32)
        old_key = secrets.token_hex(32)
        with mock.patch.dict(
            os.environ,
            {
                "GITHUB_TOKEN_ENC_KEY": current_key,
                "GITHUB_TOKEN_ENC_KEY_OLD": old_key,
            },
        ):
            encryptor = get_token_encryptor(require_encryption=True, use_keyring=False)
            assert isinstance(encryptor, AES256GCMEncryptor)
