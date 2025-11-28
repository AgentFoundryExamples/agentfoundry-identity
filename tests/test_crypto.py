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
    AES256GCMEncryptor,
    DecryptionError,
    EncryptionKeyError,
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
