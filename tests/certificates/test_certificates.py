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
from cometa import (
    CertificateType,
    MirCertPotType,
    MirCertType,
    StakeRegistrationCert,
    StakeDeregistrationCert,
    StakeDelegationCert,
    PoolRegistrationCert,
    PoolRetirementCert,
    GenesisKeyDelegationCert,
    MirToPotCert,
    MirToStakeCredsCert,
    MirCert,
    RegistrationCert,
    UnregistrationCert,
    VoteDelegationCert,
    StakeVoteDelegationCert,
    StakeRegistrationDelegationCert,
    VoteRegistrationDelegationCert,
    StakeVoteRegistrationDelegationCert,
    AuthCommitteeHotCert,
    ResignCommitteeColdCert,
    RegisterDRepCert,
    UnregisterDRepCert,
    UpdateDRepCert,
    Certificate,
    CertificateSet,
    Credential,
    Blake2bHash,
    Anchor,
    DRep,
    DRepType,
    PoolParams,
    PoolOwners,
    Relays,
    UnitInterval,
    CborWriter,
    CborReader,
)


class TestCertificateType:
    """Tests for CertificateType enum."""

    def test_values(self):
        """Test certificate type enum values."""
        assert CertificateType.STAKE_REGISTRATION == 0
        assert CertificateType.STAKE_DEREGISTRATION == 1
        assert CertificateType.STAKE_DELEGATION == 2
        assert CertificateType.POOL_REGISTRATION == 3
        assert CertificateType.POOL_RETIREMENT == 4
        assert CertificateType.GENESIS_KEY_DELEGATION == 5
        assert CertificateType.MOVE_INSTANTANEOUS_REWARDS == 6
        assert CertificateType.REGISTRATION == 7
        assert CertificateType.UNREGISTRATION == 8
        assert CertificateType.VOTE_DELEGATION == 9
        assert CertificateType.STAKE_VOTE_DELEGATION == 10
        assert CertificateType.STAKE_REGISTRATION_DELEGATION == 11
        assert CertificateType.VOTE_REGISTRATION_DELEGATION == 12
        assert CertificateType.STAKE_VOTE_REGISTRATION_DELEGATION == 13
        assert CertificateType.AUTH_COMMITTEE_HOT == 14
        assert CertificateType.RESIGN_COMMITTEE_COLD == 15
        assert CertificateType.DREP_REGISTRATION == 16
        assert CertificateType.DREP_UNREGISTRATION == 17
        assert CertificateType.UPDATE_DREP == 18

    def test_is_int_enum(self):
        """Test that CertificateType is an IntEnum."""
        assert isinstance(CertificateType.STAKE_REGISTRATION, int)


class TestMirCertPotType:
    """Tests for MirCertPotType enum."""

    def test_values(self):
        """Test MIR pot type enum values."""
        assert MirCertPotType.RESERVE == 0
        assert MirCertPotType.TREASURY == 1

    def test_is_int_enum(self):
        """Test that MirCertPotType is an IntEnum."""
        assert isinstance(MirCertPotType.RESERVE, int)


class TestMirCertType:
    """Tests for MirCertType enum."""

    def test_values(self):
        """Test MIR cert type enum values."""
        assert MirCertType.TO_POT == 0
        assert MirCertType.TO_STAKE_CREDS == 1

    def test_is_int_enum(self):
        """Test that MirCertType is an IntEnum."""
        assert isinstance(MirCertType.TO_POT, int)


class TestStakeRegistrationCert:
    """Tests for StakeRegistrationCert class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    def test_create(self, credential):
        """Test creating a stake registration certificate."""
        cert = StakeRegistrationCert.new(credential)
        assert cert.credential is not None

    def test_set_credential(self, credential):
        """Test setting credential."""
        cert = StakeRegistrationCert.new(credential)
        key_hash2 = Blake2bHash.from_hex("bb" * 28)
        cred2 = Credential.from_key_hash(key_hash2)
        cert.credential = cred2
        assert cert.credential is not None

    def test_cbor_roundtrip(self, credential):
        """Test CBOR serialization/deserialization."""
        cert = StakeRegistrationCert.new(credential)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = StakeRegistrationCert.from_cbor(reader)
        assert cert_restored.credential is not None

    def test_repr(self, credential):
        """Test repr."""
        cert = StakeRegistrationCert.new(credential)
        repr_str = repr(cert)
        assert "StakeRegistrationCert" in repr_str

    def test_context_manager(self, credential):
        """Test context manager support."""
        with StakeRegistrationCert.new(credential) as cert:
            assert cert is not None


class TestStakeDeregistrationCert:
    """Tests for StakeDeregistrationCert class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    def test_create(self, credential):
        """Test creating a stake deregistration certificate."""
        cert = StakeDeregistrationCert.new(credential)
        assert cert.credential is not None

    def test_cbor_roundtrip(self, credential):
        """Test CBOR serialization/deserialization."""
        cert = StakeDeregistrationCert.new(credential)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = StakeDeregistrationCert.from_cbor(reader)
        assert cert_restored.credential is not None


class TestStakeDelegationCert:
    """Tests for StakeDelegationCert class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    @pytest.fixture
    def pool_key_hash(self):
        """Create a test pool key hash."""
        return Blake2bHash.from_hex("bb" * 28)

    def test_create(self, credential, pool_key_hash):
        """Test creating a stake delegation certificate."""
        cert = StakeDelegationCert.new(credential, pool_key_hash)
        assert cert.credential is not None
        assert cert.pool_key_hash is not None

    def test_set_pool_key_hash(self, credential, pool_key_hash):
        """Test setting pool key hash."""
        cert = StakeDelegationCert.new(credential, pool_key_hash)
        new_hash = Blake2bHash.from_hex("cc" * 28)
        cert.pool_key_hash = new_hash
        assert cert.pool_key_hash.to_hex() == "cc" * 28

    def test_cbor_roundtrip(self, credential, pool_key_hash):
        """Test CBOR serialization/deserialization."""
        cert = StakeDelegationCert.new(credential, pool_key_hash)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = StakeDelegationCert.from_cbor(reader)
        assert cert_restored.credential is not None
        assert cert_restored.pool_key_hash is not None


class TestPoolRetirementCert:
    """Tests for PoolRetirementCert class."""

    @pytest.fixture
    def pool_key_hash(self):
        """Create a test pool key hash."""
        return Blake2bHash.from_hex("aa" * 28)

    def test_create(self, pool_key_hash):
        """Test creating a pool retirement certificate."""
        cert = PoolRetirementCert.new(pool_key_hash, epoch=100)
        assert cert.pool_key_hash is not None
        assert cert.epoch == 100

    def test_set_epoch(self, pool_key_hash):
        """Test setting epoch."""
        cert = PoolRetirementCert.new(pool_key_hash, epoch=100)
        cert.epoch = 200
        assert cert.epoch == 200

    def test_cbor_roundtrip(self, pool_key_hash):
        """Test CBOR serialization/deserialization."""
        cert = PoolRetirementCert.new(pool_key_hash, epoch=100)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = PoolRetirementCert.from_cbor(reader)
        assert cert_restored.epoch == 100

    def test_repr(self, pool_key_hash):
        """Test repr."""
        cert = PoolRetirementCert.new(pool_key_hash, epoch=100)
        repr_str = repr(cert)
        assert "PoolRetirementCert" in repr_str
        assert "100" in repr_str


class TestGenesisKeyDelegationCert:
    """Tests for GenesisKeyDelegationCert class."""

    @pytest.fixture
    def genesis_hash(self):
        """Create a test genesis hash."""
        return Blake2bHash.from_hex("aa" * 28)

    @pytest.fixture
    def genesis_delegate_hash(self):
        """Create a test genesis delegate hash."""
        return Blake2bHash.from_hex("bb" * 28)

    @pytest.fixture
    def vrf_key_hash(self):
        """Create a test VRF key hash."""
        return Blake2bHash.from_hex("cc" * 32)

    def test_create(self, genesis_hash, genesis_delegate_hash, vrf_key_hash):
        """Test creating a genesis key delegation certificate."""
        cert = GenesisKeyDelegationCert.new(
            genesis_hash, genesis_delegate_hash, vrf_key_hash
        )
        assert cert.genesis_hash is not None
        assert cert.genesis_delegate_hash is not None
        assert cert.vrf_key_hash is not None

    def test_cbor_roundtrip(self, genesis_hash, genesis_delegate_hash, vrf_key_hash):
        """Test CBOR serialization/deserialization."""
        cert = GenesisKeyDelegationCert.new(
            genesis_hash, genesis_delegate_hash, vrf_key_hash
        )

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = GenesisKeyDelegationCert.from_cbor(reader)
        assert cert_restored.genesis_hash is not None


class TestMirToPotCert:
    """Tests for MirToPotCert class."""

    def test_create_reserve_to_treasury(self):
        """Test creating MIR to pot certificate (reserve to treasury)."""
        cert = MirToPotCert.new(MirCertPotType.TREASURY, 1000000)
        assert cert.pot == MirCertPotType.TREASURY
        assert cert.amount == 1000000

    def test_create_treasury_to_reserve(self):
        """Test creating MIR to pot certificate (treasury to reserve)."""
        cert = MirToPotCert.new(MirCertPotType.RESERVE, 2000000)
        assert cert.pot == MirCertPotType.RESERVE
        assert cert.amount == 2000000

    def test_set_pot(self):
        """Test setting pot."""
        cert = MirToPotCert.new(MirCertPotType.TREASURY, 1000000)
        cert.pot = MirCertPotType.RESERVE
        assert cert.pot == MirCertPotType.RESERVE

    def test_set_amount(self):
        """Test setting amount."""
        cert = MirToPotCert.new(MirCertPotType.TREASURY, 1000000)
        cert.amount = 5000000
        assert cert.amount == 5000000

    def test_cbor_roundtrip(self):
        """Test CBOR serialization/deserialization."""
        cert = MirToPotCert.new(MirCertPotType.TREASURY, 1000000)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = MirToPotCert.from_cbor(reader)
        assert cert_restored.pot == MirCertPotType.TREASURY
        assert cert_restored.amount == 1000000


class TestMirToStakeCredsCert:
    """Tests for MirToStakeCredsCert class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    def test_create(self):
        """Test creating MIR to stake creds certificate."""
        cert = MirToStakeCredsCert.new(MirCertPotType.RESERVE)
        assert cert.pot == MirCertPotType.RESERVE
        assert len(cert) == 0

    def test_insert(self, credential):
        """Test inserting a credential and amount."""
        cert = MirToStakeCredsCert.new(MirCertPotType.RESERVE)
        cert.insert(credential, 1000000)
        assert len(cert) == 1

    def test_get_key_value_at(self, credential):
        """Test getting key and value at index."""
        cert = MirToStakeCredsCert.new(MirCertPotType.RESERVE)
        cert.insert(credential, 1000000)
        cred, amount = cert.get_key_value_at(0)
        assert cred is not None
        assert amount == 1000000

    def test_iteration(self, credential):
        """Test iterating over credentials."""
        cert = MirToStakeCredsCert.new(MirCertPotType.RESERVE)
        cert.insert(credential, 1000000)
        items = list(cert)
        assert len(items) == 1
        cred, amount = items[0]
        assert cred is not None
        assert amount == 1000000

    def test_cbor_roundtrip(self, credential):
        """Test CBOR serialization/deserialization."""
        cert = MirToStakeCredsCert.new(MirCertPotType.RESERVE)
        cert.insert(credential, 1000000)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = MirToStakeCredsCert.from_cbor(reader)
        assert len(cert_restored) == 1


class TestMirCert:
    """Tests for MirCert wrapper class."""

    @pytest.fixture
    def to_pot_cert(self):
        """Create a MirToPotCert."""
        return MirToPotCert.new(MirCertPotType.TREASURY, 1000000)

    @pytest.fixture
    def to_stake_creds_cert(self):
        """Create a MirToStakeCredsCert."""
        cert = MirToStakeCredsCert.new(MirCertPotType.RESERVE)
        key_hash = Blake2bHash.from_hex("aa" * 28)
        credential = Credential.from_key_hash(key_hash)
        cert.insert(credential, 500000)
        return cert

    def test_create_to_pot(self, to_pot_cert):
        """Test creating MirCert from to pot certificate."""
        mir = MirCert.new_to_other_pot(to_pot_cert)
        assert mir.cert_type == MirCertType.TO_POT

    def test_create_to_stake_creds(self, to_stake_creds_cert):
        """Test creating MirCert from to stake creds certificate."""
        mir = MirCert.new_to_stake_creds(to_stake_creds_cert)
        assert mir.cert_type == MirCertType.TO_STAKE_CREDS

    def test_as_to_other_pot(self, to_pot_cert):
        """Test extracting to pot certificate."""
        mir = MirCert.new_to_other_pot(to_pot_cert)
        extracted = mir.as_to_other_pot()
        assert extracted is not None
        assert extracted.pot == MirCertPotType.TREASURY
        assert extracted.amount == 1000000

    def test_as_to_stake_creds(self, to_stake_creds_cert):
        """Test extracting to stake creds certificate."""
        mir = MirCert.new_to_stake_creds(to_stake_creds_cert)
        extracted = mir.as_to_stake_creds()
        assert extracted is not None
        assert len(extracted) == 1

    def test_cbor_roundtrip_to_pot(self, to_pot_cert):
        """Test CBOR roundtrip for to pot certificate."""
        mir = MirCert.new_to_other_pot(to_pot_cert)

        writer = CborWriter()
        mir.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        mir_restored = MirCert.from_cbor(reader)
        assert mir_restored.cert_type == MirCertType.TO_POT


class TestRegistrationCert:
    """Tests for RegistrationCert (Conway era) class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    def test_create(self, credential):
        """Test creating a registration certificate."""
        cert = RegistrationCert.new(credential, deposit=2000000)
        assert cert.credential is not None
        assert cert.deposit == 2000000

    def test_set_deposit(self, credential):
        """Test setting deposit."""
        cert = RegistrationCert.new(credential, deposit=2000000)
        cert.deposit = 3000000
        assert cert.deposit == 3000000

    def test_cbor_roundtrip(self, credential):
        """Test CBOR serialization/deserialization."""
        cert = RegistrationCert.new(credential, deposit=2000000)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = RegistrationCert.from_cbor(reader)
        assert cert_restored.deposit == 2000000


class TestUnregistrationCert:
    """Tests for UnregistrationCert (Conway era) class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    def test_create(self, credential):
        """Test creating an unregistration certificate."""
        cert = UnregistrationCert.new(credential, deposit=2000000)
        assert cert.credential is not None
        assert cert.deposit == 2000000

    def test_cbor_roundtrip(self, credential):
        """Test CBOR serialization/deserialization."""
        cert = UnregistrationCert.new(credential, deposit=2000000)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = UnregistrationCert.from_cbor(reader)
        assert cert_restored.deposit == 2000000


class TestVoteDelegationCert:
    """Tests for VoteDelegationCert class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    @pytest.fixture
    def drep(self):
        """Create a test DRep."""
        return DRep.abstain()

    def test_create(self, credential, drep):
        """Test creating a vote delegation certificate."""
        cert = VoteDelegationCert.new(credential, drep)
        assert cert.credential is not None
        assert cert.drep is not None

    def test_create_with_key_hash_drep(self, credential):
        """Test creating with key hash DRep."""
        drep_key = Blake2bHash.from_hex("bb" * 28)
        drep_cred = Credential.from_key_hash(drep_key)
        drep = DRep.new(DRepType.KEY_HASH, drep_cred)
        cert = VoteDelegationCert.new(credential, drep)
        assert cert.drep is not None

    def test_cbor_roundtrip(self, credential, drep):
        """Test CBOR serialization/deserialization."""
        cert = VoteDelegationCert.new(credential, drep)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = VoteDelegationCert.from_cbor(reader)
        assert cert_restored.credential is not None


class TestStakeVoteDelegationCert:
    """Tests for StakeVoteDelegationCert class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    @pytest.fixture
    def pool_key_hash(self):
        """Create a test pool key hash."""
        return Blake2bHash.from_hex("bb" * 28)

    @pytest.fixture
    def drep(self):
        """Create a test DRep."""
        return DRep.no_confidence()

    def test_create(self, credential, pool_key_hash, drep):
        """Test creating a stake vote delegation certificate."""
        cert = StakeVoteDelegationCert.new(credential, pool_key_hash, drep)
        assert cert.credential is not None
        assert cert.pool_key_hash is not None
        assert cert.drep is not None

    def test_cbor_roundtrip(self, credential, pool_key_hash, drep):
        """Test CBOR serialization/deserialization."""
        cert = StakeVoteDelegationCert.new(credential, pool_key_hash, drep)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = StakeVoteDelegationCert.from_cbor(reader)
        assert cert_restored.credential is not None


class TestStakeRegistrationDelegationCert:
    """Tests for StakeRegistrationDelegationCert class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    @pytest.fixture
    def pool_key_hash(self):
        """Create a test pool key hash."""
        return Blake2bHash.from_hex("bb" * 28)

    def test_create(self, credential, pool_key_hash):
        """Test creating a stake registration delegation certificate."""
        cert = StakeRegistrationDelegationCert.new(
            credential, pool_key_hash, deposit=2000000
        )
        assert cert.credential is not None
        assert cert.pool_key_hash is not None
        assert cert.deposit == 2000000

    def test_cbor_roundtrip(self, credential, pool_key_hash):
        """Test CBOR serialization/deserialization."""
        cert = StakeRegistrationDelegationCert.new(
            credential, pool_key_hash, deposit=2000000
        )

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = StakeRegistrationDelegationCert.from_cbor(reader)
        assert cert_restored.deposit == 2000000


class TestVoteRegistrationDelegationCert:
    """Tests for VoteRegistrationDelegationCert class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    @pytest.fixture
    def drep(self):
        """Create a test DRep."""
        return DRep.abstain()

    def test_create(self, credential, drep):
        """Test creating a vote registration delegation certificate."""
        cert = VoteRegistrationDelegationCert.new(credential, 2000000, drep)
        assert cert.credential is not None
        assert cert.drep is not None
        assert cert.deposit == 2000000

    def test_cbor_roundtrip(self, credential, drep):
        """Test CBOR serialization/deserialization."""
        cert = VoteRegistrationDelegationCert.new(credential, 2000000, drep)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = VoteRegistrationDelegationCert.from_cbor(reader)
        assert cert_restored.deposit == 2000000


class TestStakeVoteRegistrationDelegationCert:
    """Tests for StakeVoteRegistrationDelegationCert class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    @pytest.fixture
    def pool_key_hash(self):
        """Create a test pool key hash."""
        return Blake2bHash.from_hex("bb" * 28)

    @pytest.fixture
    def drep(self):
        """Create a test DRep."""
        return DRep.abstain()

    def test_create(self, credential, pool_key_hash, drep):
        """Test creating a stake vote registration delegation certificate."""
        cert = StakeVoteRegistrationDelegationCert.new(
            credential, 2000000, drep, pool_key_hash
        )
        assert cert.credential is not None
        assert cert.pool_key_hash is not None
        assert cert.drep is not None
        assert cert.deposit == 2000000

    def test_cbor_roundtrip(self, credential, pool_key_hash, drep):
        """Test CBOR serialization/deserialization."""
        cert = StakeVoteRegistrationDelegationCert.new(
            credential, 2000000, drep, pool_key_hash
        )

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = StakeVoteRegistrationDelegationCert.from_cbor(reader)
        assert cert_restored.deposit == 2000000


class TestAuthCommitteeHotCert:
    """Tests for AuthCommitteeHotCert class."""

    @pytest.fixture
    def cold_credential(self):
        """Create a test cold credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    @pytest.fixture
    def hot_credential(self):
        """Create a test hot credential."""
        key_hash = Blake2bHash.from_hex("bb" * 28)
        return Credential.from_key_hash(key_hash)

    def test_create(self, cold_credential, hot_credential):
        """Test creating an auth committee hot certificate."""
        cert = AuthCommitteeHotCert.new(
            committee_cold_cred=cold_credential, committee_hot_cred=hot_credential
        )
        assert cert.committee_cold_credential is not None
        assert cert.committee_hot_credential is not None

    def test_cbor_roundtrip(self, cold_credential, hot_credential):
        """Test CBOR serialization/deserialization."""
        cert = AuthCommitteeHotCert.new(
            committee_cold_cred=cold_credential, committee_hot_cred=hot_credential
        )

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = AuthCommitteeHotCert.from_cbor(reader)
        assert cert_restored.committee_cold_credential is not None


class TestResignCommitteeColdCert:
    """Tests for ResignCommitteeColdCert class."""

    @pytest.fixture
    def cold_credential(self):
        """Create a test cold credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    @pytest.fixture
    def anchor(self):
        """Create a test anchor."""
        hash_val = Blake2bHash.from_hex("cc" * 32)
        return Anchor.new("https://example.com/resign.json", hash_val)

    def test_create_without_anchor(self, cold_credential):
        """Test creating a resign committee cold certificate without anchor."""
        cert = ResignCommitteeColdCert.new(cold_credential)
        assert cert.committee_cold_credential is not None
        assert cert.anchor is None

    def test_create_with_anchor(self, cold_credential, anchor):
        """Test creating a resign committee cold certificate with anchor."""
        cert = ResignCommitteeColdCert.new(cold_credential, anchor=anchor)
        assert cert.committee_cold_credential is not None
        assert cert.anchor is not None

    def test_cbor_roundtrip(self, cold_credential, anchor):
        """Test CBOR serialization/deserialization."""
        cert = ResignCommitteeColdCert.new(cold_credential, anchor=anchor)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = ResignCommitteeColdCert.from_cbor(reader)
        assert cert_restored.committee_cold_credential is not None


class TestRegisterDRepCert:
    """Tests for RegisterDRepCert class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    @pytest.fixture
    def anchor(self):
        """Create a test anchor."""
        hash_val = Blake2bHash.from_hex("cc" * 32)
        return Anchor.new("https://example.com/drep.json", hash_val)

    def test_create_without_anchor(self, credential):
        """Test creating a DRep registration certificate without anchor."""
        cert = RegisterDRepCert.new(credential, deposit=2000000)
        assert cert.credential is not None
        assert cert.deposit == 2000000
        assert cert.anchor is None

    def test_create_with_anchor(self, credential, anchor):
        """Test creating a DRep registration certificate with anchor."""
        cert = RegisterDRepCert.new(credential, deposit=2000000, anchor=anchor)
        assert cert.credential is not None
        assert cert.deposit == 2000000
        assert cert.anchor is not None

    def test_set_deposit(self, credential):
        """Test setting deposit."""
        cert = RegisterDRepCert.new(credential, deposit=2000000)
        cert.deposit = 3000000
        assert cert.deposit == 3000000

    def test_cbor_roundtrip(self, credential, anchor):
        """Test CBOR serialization/deserialization."""
        cert = RegisterDRepCert.new(credential, deposit=2000000, anchor=anchor)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = RegisterDRepCert.from_cbor(reader)
        assert cert_restored.deposit == 2000000


class TestUnregisterDRepCert:
    """Tests for UnregisterDRepCert class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    def test_create(self, credential):
        """Test creating a DRep unregistration certificate."""
        cert = UnregisterDRepCert.new(credential, deposit=2000000)
        assert cert.credential is not None
        assert cert.deposit == 2000000

    def test_set_deposit(self, credential):
        """Test setting deposit."""
        cert = UnregisterDRepCert.new(credential, deposit=2000000)
        cert.deposit = 3000000
        assert cert.deposit == 3000000

    def test_cbor_roundtrip(self, credential):
        """Test CBOR serialization/deserialization."""
        cert = UnregisterDRepCert.new(credential, deposit=2000000)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = UnregisterDRepCert.from_cbor(reader)
        assert cert_restored.deposit == 2000000


class TestUpdateDRepCert:
    """Tests for UpdateDRepCert class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    @pytest.fixture
    def anchor(self):
        """Create a test anchor."""
        hash_val = Blake2bHash.from_hex("cc" * 32)
        return Anchor.new("https://example.com/drep-updated.json", hash_val)

    def test_create_without_anchor(self, credential):
        """Test creating an update DRep certificate without anchor."""
        cert = UpdateDRepCert.new(credential)
        assert cert.credential is not None
        assert cert.anchor is None

    def test_create_with_anchor(self, credential, anchor):
        """Test creating an update DRep certificate with anchor."""
        cert = UpdateDRepCert.new(credential, anchor=anchor)
        assert cert.credential is not None
        assert cert.anchor is not None

    def test_set_anchor(self, credential, anchor):
        """Test setting anchor."""
        cert = UpdateDRepCert.new(credential)
        assert cert.anchor is None
        cert.anchor = anchor
        assert cert.anchor is not None

    def test_cbor_roundtrip(self, credential, anchor):
        """Test CBOR serialization/deserialization."""
        cert = UpdateDRepCert.new(credential, anchor=anchor)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = UpdateDRepCert.from_cbor(reader)
        assert cert_restored.credential is not None


class TestCertificate:
    """Tests for Certificate wrapper class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    @pytest.fixture
    def stake_reg_cert(self, credential):
        """Create a stake registration certificate."""
        return StakeRegistrationCert.new(credential)

    @pytest.fixture
    def stake_dereg_cert(self, credential):
        """Create a stake deregistration certificate."""
        return StakeDeregistrationCert.new(credential)

    def test_new_stake_registration(self, stake_reg_cert):
        """Test creating Certificate from stake registration."""
        cert = Certificate.new_stake_registration(stake_reg_cert)
        assert cert.cert_type == CertificateType.STAKE_REGISTRATION

    def test_new_stake_deregistration(self, stake_dereg_cert):
        """Test creating Certificate from stake deregistration."""
        cert = Certificate.new_stake_deregistration(stake_dereg_cert)
        assert cert.cert_type == CertificateType.STAKE_DEREGISTRATION

    def test_to_stake_registration(self, stake_reg_cert):
        """Test extracting stake registration certificate."""
        cert = Certificate.new_stake_registration(stake_reg_cert)
        extracted = cert.to_stake_registration()
        assert extracted is not None
        assert extracted.credential is not None

    def test_to_stake_deregistration(self, stake_dereg_cert):
        """Test extracting stake deregistration certificate."""
        cert = Certificate.new_stake_deregistration(stake_dereg_cert)
        extracted = cert.to_stake_deregistration()
        assert extracted is not None

    def test_cbor_roundtrip(self, stake_reg_cert):
        """Test CBOR serialization/deserialization."""
        cert = Certificate.new_stake_registration(stake_reg_cert)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = Certificate.from_cbor(reader)
        assert cert_restored.cert_type == CertificateType.STAKE_REGISTRATION

    def test_repr(self, stake_reg_cert):
        """Test repr."""
        cert = Certificate.new_stake_registration(stake_reg_cert)
        repr_str = repr(cert)
        assert "Certificate" in repr_str
        assert "STAKE_REGISTRATION" in repr_str

    def test_auto_conversion_from_stake_registration(self, stake_reg_cert):
        """Test automatic conversion from StakeRegistrationCert."""
        cert = Certificate(stake_reg_cert)
        assert cert.cert_type == CertificateType.STAKE_REGISTRATION

    def test_auto_conversion_from_stake_deregistration(self, stake_dereg_cert):
        """Test automatic conversion from StakeDeregistrationCert."""
        cert = Certificate(stake_dereg_cert)
        assert cert.cert_type == CertificateType.STAKE_DEREGISTRATION

    def test_from_cert_method(self, stake_reg_cert):
        """Test explicit from_cert conversion method."""
        cert = Certificate.from_cert(stake_reg_cert)
        assert cert.cert_type == CertificateType.STAKE_REGISTRATION

    def test_auto_conversion_various_types(self, credential):
        """Test automatic conversion from various certificate types."""
        pool_key_hash = Blake2bHash.from_hex("bb" * 28)

        # Test StakeDelegationCert
        stake_del = StakeDelegationCert.new(credential, pool_key_hash)
        cert1 = Certificate(stake_del)
        assert cert1.cert_type == CertificateType.STAKE_DELEGATION

        # Test PoolRetirementCert
        pool_ret = PoolRetirementCert.new(pool_key_hash, epoch=100)
        cert2 = Certificate(pool_ret)
        assert cert2.cert_type == CertificateType.POOL_RETIREMENT

        # Test RegistrationCert (Conway)
        reg = RegistrationCert.new(credential, deposit=2000000)
        cert3 = Certificate(reg)
        assert cert3.cert_type == CertificateType.REGISTRATION

        # Test VoteDelegationCert
        drep = DRep.abstain()
        vote_del = VoteDelegationCert.new(credential, drep)
        cert4 = Certificate(vote_del)
        assert cert4.cert_type == CertificateType.VOTE_DELEGATION

    def test_invalid_type_raises_error(self):
        """Test that passing an invalid type raises TypeError."""
        with pytest.raises(TypeError):
            Certificate("invalid")

        with pytest.raises(TypeError):
            Certificate(123)


class TestCertificateSet:
    """Tests for CertificateSet class."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("aa" * 28)
        return Credential.from_key_hash(key_hash)

    @pytest.fixture
    def certificate(self, credential):
        """Create a test certificate."""
        stake_reg = StakeRegistrationCert.new(credential)
        return Certificate.new_stake_registration(stake_reg)

    def test_create_empty(self):
        """Test creating an empty certificate set."""
        cert_set = CertificateSet.new()
        assert len(cert_set) == 0

    def test_add(self, certificate):
        """Test adding a certificate."""
        cert_set = CertificateSet.new()
        cert_set.add(certificate)
        assert len(cert_set) == 1

    def test_get(self, certificate):
        """Test getting a certificate."""
        cert_set = CertificateSet.new()
        cert_set.add(certificate)
        cert = cert_set.get(0)
        assert cert is not None
        assert cert.cert_type == CertificateType.STAKE_REGISTRATION

    def test_getitem(self, certificate):
        """Test indexing."""
        cert_set = CertificateSet.new()
        cert_set.add(certificate)
        cert = cert_set[0]
        assert cert is not None

    def test_getitem_negative_index(self, certificate):
        """Test negative indexing."""
        cert_set = CertificateSet.new()
        cert_set.add(certificate)
        cert = cert_set[-1]
        assert cert is not None

    def test_getitem_out_of_range(self):
        """Test index out of range raises error."""
        cert_set = CertificateSet.new()
        with pytest.raises(IndexError):
            _ = cert_set[0]

    def test_iteration(self, certificate):
        """Test iterating over certificates."""
        cert_set = CertificateSet.new()
        cert_set.add(certificate)
        certs = list(cert_set)
        assert len(certs) == 1
        assert certs[0].cert_type == CertificateType.STAKE_REGISTRATION

    def test_multiple_certificates(self, credential):
        """Test multiple certificates."""
        cert_set = CertificateSet.new()

        # Add stake registration
        stake_reg = StakeRegistrationCert.new(credential)
        cert_set.add(Certificate.new_stake_registration(stake_reg))

        # Add stake deregistration
        stake_dereg = StakeDeregistrationCert.new(credential)
        cert_set.add(Certificate.new_stake_deregistration(stake_dereg))

        assert len(cert_set) == 2
        assert cert_set[0].cert_type == CertificateType.STAKE_REGISTRATION
        assert cert_set[1].cert_type == CertificateType.STAKE_DEREGISTRATION

    def test_cbor_roundtrip(self, certificate):
        """Test CBOR serialization/deserialization."""
        cert_set = CertificateSet.new()
        cert_set.add(certificate)

        writer = CborWriter()
        cert_set.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_set_restored = CertificateSet.from_cbor(reader)
        assert len(cert_set_restored) == 1

    def test_repr(self, certificate):
        """Test repr."""
        cert_set = CertificateSet.new()
        cert_set.add(certificate)
        repr_str = repr(cert_set)
        assert "CertificateSet" in repr_str
        assert "len=1" in repr_str

    def test_context_manager(self):
        """Test context manager support."""
        with CertificateSet.new() as cert_set:
            assert cert_set is not None

    def test_add_auto_conversion(self, credential):
        """Test adding specific certificate types directly (auto-conversion)."""
        cert_set = CertificateSet.new()

        # Add specific certificate types directly without wrapping in Certificate
        stake_reg = StakeRegistrationCert.new(credential)
        cert_set.add(stake_reg)

        stake_dereg = StakeDeregistrationCert.new(credential)
        cert_set.add(stake_dereg)

        pool_key_hash = Blake2bHash.from_hex("bb" * 28)
        stake_del = StakeDelegationCert.new(credential, pool_key_hash)
        cert_set.add(stake_del)

        assert len(cert_set) == 3
        assert cert_set[0].cert_type == CertificateType.STAKE_REGISTRATION
        assert cert_set[1].cert_type == CertificateType.STAKE_DEREGISTRATION
        assert cert_set[2].cert_type == CertificateType.STAKE_DELEGATION
