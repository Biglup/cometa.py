"""
Copyright 2025 Biglup Labs.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import pytest
from cometa.errors import CardanoError, check_error, cardano_error_to_string
from cometa._ffi import ffi, lib


class TestCardanoError:
    """Test the CardanoError exception class."""

    def test_cardano_error_creation(self):
        """Test creating a CardanoError with a message."""
        error = CardanoError("Test error message")
        assert str(error) == "Test error message"
        assert isinstance(error, Exception)

    def test_cardano_error_empty_message(self):
        """Test creating a CardanoError with an empty message."""
        error = CardanoError("")
        assert str(error) == ""

    def test_cardano_error_inheritance(self):
        """Test that CardanoError is an Exception."""
        error = CardanoError("Test")
        assert isinstance(error, Exception)

    def test_cardano_error_can_be_raised(self):
        """Test that CardanoError can be raised and caught."""
        with pytest.raises(CardanoError) as exc_info:
            raise CardanoError("Test error")
        assert str(exc_info.value) == "Test error"

    def test_cardano_error_with_special_characters(self):
        """Test CardanoError with special characters in message."""
        error = CardanoError("Error: \n\t special chars ©")
        assert "special chars" in str(error)


class TestCheckError:
    """Test the check_error helper function."""

    def test_check_error_with_success_code(self):
        """Test check_error does not raise when err is 0."""
        check_error(0, None, None)

    def test_check_error_with_error_code_and_valid_message(self):
        """Test check_error raises CardanoError with message from C library."""
        mock_error_message = b"Test error from C library"
        mock_ptr = ffi.new("char[]", mock_error_message)

        def mock_get_last_error(ctx):
            return mock_ptr

        with pytest.raises(CardanoError) as exc_info:
            check_error(1, mock_get_last_error, None)

        assert str(exc_info.value) == "Test error from C library"

    def test_check_error_with_error_code_and_null_message(self):
        """Test check_error raises CardanoError with default message when C returns NULL."""
        def mock_get_last_error_null(ctx):
            return ffi.NULL

        with pytest.raises(CardanoError) as exc_info:
            check_error(1, mock_get_last_error_null, None)

        assert str(exc_info.value) == "Unknown libcardano-c error"

    def test_check_error_with_various_error_codes(self):
        """Test check_error raises for various non-zero error codes."""
        def mock_get_last_error(ctx):
            return ffi.new("char[]", b"Generic error")

        for error_code in [1, 2, 10, 100, -1]:
            with pytest.raises(CardanoError):
                check_error(error_code, mock_get_last_error, None)

    def test_check_error_does_not_raise_only_for_zero(self):
        """Test check_error only accepts 0 as success."""
        def mock_get_last_error(ctx):
            return ffi.new("char[]", b"Error")

        check_error(0, mock_get_last_error, None)

        with pytest.raises(CardanoError):
            check_error(-1, mock_get_last_error, None)


class TestCardanoErrorToString:
    """Test the cardano_error_to_string function with test vectors from C tests."""

    def test_success_code(self):
        """Test CARDANO_SUCCESS = 0."""
        assert cardano_error_to_string(0) == "Successful operation"

    def test_generic_error(self):
        """Test CARDANO_ERROR_GENERIC = 1."""
        assert cardano_error_to_string(1) == "Generic error"

    def test_insufficient_buffer_size(self):
        """Test CARDANO_ERROR_INSUFFICIENT_BUFFER_SIZE = 2."""
        assert cardano_error_to_string(2) == "Insufficient buffer size"

    def test_pointer_is_null(self):
        """Test CARDANO_ERROR_POINTER_IS_NULL = 3."""
        assert cardano_error_to_string(3) == "Argument is a NULL pointer"

    def test_memory_allocation_failed(self):
        """Test CARDANO_ERROR_MEMORY_ALLOCATION_FAILED = 4."""
        assert cardano_error_to_string(4) == "Requested memory could not be allocated"

    def test_out_of_bounds_memory_read(self):
        """Test CARDANO_ERROR_OUT_OF_BOUNDS_MEMORY_READ = 5."""
        assert cardano_error_to_string(5) == "Out of bounds memory read"

    def test_out_of_bounds_memory_write(self):
        """Test CARDANO_ERROR_OUT_OF_BOUNDS_MEMORY_WRITE = 6."""
        assert cardano_error_to_string(6) == "Out of bounds memory write"

    def test_invalid_argument(self):
        """Test CARDANO_ERROR_INVALID_ARGUMENT = 7."""
        assert cardano_error_to_string(7) == "Invalid argument"

    def test_invalid_url(self):
        """Test CARDANO_ERROR_INVALID_URL = 8."""
        assert cardano_error_to_string(8) == "Invalid argument. Invalid URL"

    def test_element_not_found(self):
        """Test CARDANO_ERROR_ELEMENT_NOT_FOUND = 9."""
        assert cardano_error_to_string(9) == "Element not found"

    def test_encoding_error(self):
        """Test CARDANO_ERROR_ENCODING = 10."""
        assert cardano_error_to_string(10) == "Encoding failure"

    def test_decoding_error(self):
        """Test CARDANO_ERROR_DECODING = 11."""
        assert cardano_error_to_string(11) == "Decoding failure"

    def test_checksum_mismatch(self):
        """Test CARDANO_ERROR_CHECKSUM_MISMATCH = 12."""
        assert cardano_error_to_string(12) == "Checksum mismatch"

    def test_invalid_json(self):
        """Test CARDANO_ERROR_INVALID_JSON = 13."""
        assert cardano_error_to_string(13) == "Invalid JSON"

    def test_integer_overflow(self):
        """Test CARDANO_ERROR_INTEGER_OVERFLOW = 14."""
        assert cardano_error_to_string(14) == "Integer overflow"

    def test_integer_underflow(self):
        """Test CARDANO_ERROR_INTEGER_UNDERFLOW = 15."""
        assert cardano_error_to_string(15) == "Integer underflow"

    def test_conversion_failed(self):
        """Test CARDANO_ERROR_CONVERSION_FAILED = 16."""
        assert cardano_error_to_string(16) == "Conversion error"

    def test_index_out_of_bounds(self):
        """Test CARDANO_ERROR_INDEX_OUT_OF_BOUNDS = 17."""
        assert cardano_error_to_string(17) == "Index out of bounds"

    def test_invalid_certificate_type(self):
        """Test CARDANO_ERROR_INVALID_CERTIFICATE_TYPE = 18."""
        assert cardano_error_to_string(18) == "Invalid certificate type"

    def test_not_implemented(self):
        """Test CARDANO_ERROR_NOT_IMPLEMENTED = 19."""
        assert cardano_error_to_string(19) == "Not implemented"

    def test_invalid_passphrase(self):
        """Test CARDANO_ERROR_INVALID_PASSPHRASE = 20."""
        assert cardano_error_to_string(20) == "Invalid passphrase"

    def test_illegal_state(self):
        """Test CARDANO_ERROR_ILLEGAL_STATE = 21."""
        assert cardano_error_to_string(21) == "Illegal state"

    def test_duplicated_key(self):
        """Test CARDANO_ERROR_DUPLICATED_KEY = 22."""
        assert cardano_error_to_string(22) == "Duplicated key"

    def test_json_type_mismatch(self):
        """Test CARDANO_ERROR_JSON_TYPE_MISMATCH = 23."""
        assert cardano_error_to_string(23) == "JSON type mismatch"

    def test_loss_of_precision(self):
        """Test CARDANO_ERROR_LOSS_OF_PRECISION = 100."""
        assert cardano_error_to_string(100) == "Loss of precision"

    def test_invalid_magic(self):
        """Test CARDANO_ERROR_INVALID_MAGIC = 101."""
        assert cardano_error_to_string(101) == "Invalid magic"

    def test_invalid_checksum(self):
        """Test CARDANO_ERROR_INVALID_CHECKSUM = 102."""
        assert cardano_error_to_string(102) == "Invalid checksum"

    def test_invalid_blake2b_hash_size(self):
        """Test CARDANO_ERROR_INVALID_BLAKE2B_HASH_SIZE = 200."""
        assert cardano_error_to_string(200) == "Invalid Blake2b hash size"

    def test_invalid_ed25519_signature_size(self):
        """Test CARDANO_ERROR_INVALID_ED25519_SIGNATURE_SIZE = 201."""
        assert cardano_error_to_string(201) == "Invalid Ed25519 signature size"

    def test_invalid_ed25519_public_key_size(self):
        """Test CARDANO_ERROR_INVALID_ED25519_PUBLIC_KEY_SIZE = 202."""
        assert cardano_error_to_string(202) == "Invalid Ed25519 public key size"

    def test_invalid_ed25519_private_key_size(self):
        """Test CARDANO_ERROR_INVALID_ED25519_PRIVATE_KEY_SIZE = 203."""
        assert cardano_error_to_string(203) == "Invalid Ed25519 private key size"

    def test_invalid_bip32_public_key_size(self):
        """Test CARDANO_ERROR_INVALID_BIP32_PUBLIC_KEY_SIZE = 204."""
        assert cardano_error_to_string(204) == "Invalid BIP32 public key size"

    def test_invalid_bip32_private_key_size(self):
        """Test CARDANO_ERROR_INVALID_BIP32_PRIVATE_KEY_SIZE = 205."""
        assert cardano_error_to_string(205) == "Invalid BIP32 private key size"

    def test_invalid_bip32_derivation_index(self):
        """Test CARDANO_ERROR_INVALID_BIP32_DERIVATION_INDEX = 206."""
        assert cardano_error_to_string(206) == "Invalid BIP32 derivation index"

    def test_unexpected_cbor_type(self):
        """Test CARDANO_ERROR_UNEXPECTED_CBOR_TYPE = 300."""
        assert cardano_error_to_string(300) == "Unexpected CBOR type"

    def test_invalid_cbor_value(self):
        """Test CARDANO_ERROR_INVALID_CBOR_VALUE = 301."""
        assert cardano_error_to_string(301) == "Invalid CBOR value"

    def test_invalid_cbor_array_size(self):
        """Test CARDANO_ERROR_INVALID_CBOR_ARRAY_SIZE = 302."""
        assert cardano_error_to_string(302) == "Invalid CBOR array size"

    def test_invalid_cbor_map_size(self):
        """Test CARDANO_ERROR_INVALID_CBOR_MAP_SIZE = 303."""
        assert cardano_error_to_string(303) == "Invalid CBOR map size"

    def test_duplicated_cbor_map_key(self):
        """Test CARDANO_ERROR_DUPLICATED_CBOR_MAP_KEY = 304."""
        assert cardano_error_to_string(304) == "Duplicated CBOR map key"

    def test_invalid_cbor_map_key(self):
        """Test CARDANO_ERROR_INVALID_CBOR_MAP_KEY = 305."""
        assert cardano_error_to_string(305) == "Invalid CBOR map key"

    def test_invalid_address_type(self):
        """Test CARDANO_ERROR_INVALID_ADDRESS_TYPE = 400."""
        assert cardano_error_to_string(400) == "Invalid address type"

    def test_invalid_address_format(self):
        """Test CARDANO_ERROR_INVALID_ADDRESS_FORMAT = 401."""
        assert cardano_error_to_string(401) == "Invalid address format"

    def test_invalid_credential_type(self):
        """Test CARDANO_ERROR_INVALID_CREDENTIAL_TYPE = 500."""
        assert cardano_error_to_string(500) == "Invalid credential type"

    def test_invalid_plutus_data_conversion(self):
        """Test CARDANO_ERROR_INVALID_PLUTUS_DATA_CONVERSION = 600."""
        assert cardano_error_to_string(600) == "Invalid Plutus data conversion"

    def test_invalid_datum_type(self):
        """Test CARDANO_ERROR_INVALID_DATUM_TYPE = 601."""
        assert cardano_error_to_string(601) == "Invalid datum type"

    def test_invalid_script_language(self):
        """Test CARDANO_ERROR_INVALID_SCRIPT_LANGUAGE = 700."""
        assert cardano_error_to_string(700) == "Invalid script language"

    def test_invalid_native_script_type(self):
        """Test CARDANO_ERROR_INVALID_NATIVE_SCRIPT_TYPE = 701."""
        assert cardano_error_to_string(701) == "Invalid native script type"

    def test_invalid_plutus_cost_model(self):
        """Test CARDANO_ERROR_INVALID_PLUTUS_COST_MODEL = 702."""
        assert cardano_error_to_string(702) == "Invalid Plutus cost model"

    def test_invalid_procedure_proposal_type(self):
        """Test CARDANO_ERROR_INVALID_PROCEDURE_PROPOSAL_TYPE = 800."""
        assert cardano_error_to_string(800) == "Invalid procedure proposal type"

    def test_invalid_metadatum_conversion(self):
        """Test CARDANO_ERROR_INVALID_METADATUM_CONVERSION = 900."""
        assert cardano_error_to_string(900) == "Invalid metadatum conversion"

    def test_invalid_metadatum_text_string_size(self):
        """Test CARDANO_ERROR_INVALID_METADATUM_TEXT_STRING_SIZE = 901."""
        assert cardano_error_to_string(901) == "Invalid metadatum text string size, must be less than 64 bytes"

    def test_invalid_metadatum_bounded_bytes_size(self):
        """Test CARDANO_ERROR_INVALID_METADATUM_BOUNDED_BYTES_SIZE = 902."""
        assert cardano_error_to_string(902) == "Invalid metadatum bounded bytes size, must be less than 64 bytes"

    def test_invalid_http_request(self):
        """Test CARDANO_ERROR_INVALID_HTTP_REQUEST = 1000."""
        assert cardano_error_to_string(1000) == "Invalid HTTP request"

    def test_balance_insufficient(self):
        """Test CARDANO_ERROR_BALANCE_INSUFFICIENT = 1100."""
        assert cardano_error_to_string(1100) == "Insufficient balance"

    def test_utxo_not_fragmented_enough(self):
        """Test CARDANO_ERROR_UTXO_NOT_FRAGMENTED_ENOUGH = 1101."""
        assert cardano_error_to_string(1101) == "UTXO not fragmented enough"

    def test_utxo_fully_depleted(self):
        """Test CARDANO_ERROR_UTXO_FULLY_DEPLETED = 1102."""
        assert cardano_error_to_string(1102) == "UTXO fully depleted"

    def test_maximum_input_count_exceeded(self):
        """Test CARDANO_ERROR_MAXIMUM_INPUT_COUNT_EXCEEDED = 1103."""
        assert cardano_error_to_string(1103) == "Maximum input count exceeded"

    def test_script_evaluation_failure(self):
        """Test CARDANO_ERROR_SCRIPT_EVALUATION_FAILURE = 1200."""
        assert cardano_error_to_string(1200) == "Script evaluation failure"

    def test_unknown_error_code(self):
        """Test unknown error code returns default message."""
        assert cardano_error_to_string(99999999) == "Unknown error code"

    def test_negative_error_code(self):
        """Test negative error code."""
        result = cardano_error_to_string(-1)
        assert isinstance(result, str)
        assert result == "Unknown error code"

    def test_large_error_code(self):
        """Test very large error code."""
        result = cardano_error_to_string(999999999)
        assert isinstance(result, str)
        assert result == "Unknown error code"

    def test_error_code_boundary_values(self):
        """Test boundary values for error codes."""
        assert cardano_error_to_string(0) == "Successful operation"

        result = cardano_error_to_string(2147483647)
        assert isinstance(result, str)


class TestErrorIntegration:
    """Integration tests for error handling."""

    def test_error_codes_return_strings(self):
        """Test that all valid error codes return non-empty strings."""
        valid_error_codes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
            20, 21, 22, 23, 100, 101, 102, 200, 201, 202, 203, 204, 205, 206,
            300, 301, 302, 303, 304, 305, 400, 401, 500, 600, 601, 700, 701, 702,
            800, 900, 901, 902, 1000, 1100, 1101, 1102, 1103, 1200
        ]

        for code in valid_error_codes:
            result = cardano_error_to_string(code)
            assert isinstance(result, str)
            assert len(result) > 0
            assert result != ""

    def test_cardano_error_can_hold_error_string(self):
        """Test that CardanoError can be raised with messages from cardano_error_to_string."""
        error_msg = cardano_error_to_string(1)
        error = CardanoError(error_msg)
        assert str(error) == "Generic error"

    def test_check_error_with_real_error_codes(self):
        """Test check_error behavior with actual error code scenarios."""
        def create_mock_error_fn(message):
            def mock_fn(ctx):
                return ffi.new("char[]", message.encode('utf-8'))
            return mock_fn

        check_error(0, create_mock_error_fn("Should not see this"), None)

        with pytest.raises(CardanoError) as exc_info:
            check_error(1, create_mock_error_fn("Generic error"), None)
        assert "Generic error" in str(exc_info.value)

    def test_multiple_error_types(self):
        """Test that different error codes produce different messages."""
        msg1 = cardano_error_to_string(1)
        msg2 = cardano_error_to_string(2)
        msg3 = cardano_error_to_string(3)

        assert msg1 != msg2
        assert msg2 != msg3
        assert msg1 != msg3

    def test_error_string_consistency(self):
        """Test that calling cardano_error_to_string multiple times gives same result."""
        for code in [0, 1, 10, 100, 200, 300]:
            msg1 = cardano_error_to_string(code)
            msg2 = cardano_error_to_string(code)
            assert msg1 == msg2
