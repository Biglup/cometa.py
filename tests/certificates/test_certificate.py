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
    Certificate,
    CertificateType,
    StakeRegistrationCert,
    StakeDeregistrationCert,
    StakeDelegationCert,
    PoolRegistrationCert,
    PoolRetirementCert,
    GenesisKeyDelegationCert,
    MirToPotCert,
    MirToStakeCredsCert,
    MirCert,
    MirCertPotType,
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
    JsonWriter,
    CardanoError,
)


CBOR_STAKE_REGISTRATION = "82008200581ccb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f"
CBOR_STAKE_DEREGISTRATION = "82018200581ccb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f"
CBOR_STAKE_DELEGATION = "83028200581ccb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f581cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef92"
CBOR_POOL_RETIREMENT = "8304581cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef921903e8"
CBOR_GENESIS_DELEGATION = "8405581c00010001000100010001000100010001000100010001000100010001581c0002000200020002000200020002000200020002000200020002000258200003000300030003000300030003000300030003000300030003000300030003"
CBOR_MIR = "820682001a000f4240"
CBOR_REGISTRATION = "83078200581c0000000000000000000000000000000000000000000000000000000000"
CBOR_UNREGISTRATION = "83088200581c0000000000000000000000000000000000000000000000000000000000"
CBOR_VOTE_DELEGATION = "83098200581c000000000000000000000000000000000000000000000000000000008200581c00000000000000000000000000000000000000000000000000000000"
CBOR_STAKE_VOTE_DELEGATION = "840a8200581c00000000000000000000000000000000000000000000000000000000581c000000000000000000000000000000000000000000000000000000008200581c00000000000000000000000000000000000000000000000000000000"
CBOR_STAKE_REGISTRATION_DELEGATION = "840b8200581c00000000000000000000000000000000000000000000000000000000581c0000000000000000000000000000000000000000000000000000000000"
CBOR_VOTE_REGISTRATION_DELEGATION = "840c8200581c000000000000000000000000000000000000000000000000000000008200581c0000000000000000000000000000000000000000000000000000000000"
CBOR_STAKE_VOTE_REGISTRATION_DELEGATION = "850d8200581c00000000000000000000000000000000000000000000000000000000581c000000000000000000000000000000000000000000000000000000008200581c0000000000000000000000000000000000000000000000000000000000"
CBOR_AUTHORIZE_COMMITTEE_HOT = "830e8200581c000000000000000000000000000000000000000000000000000000008200581c00000000000000000000000000000000000000000000000000000000"
CBOR_RESIGN_COMMITTEE_COLD = "830f8200581c00000000000000000000000000000000000000000000000000000000f6"
CBOR_REGISTER_DREP = "84108200581c0000000000000000000000000000000000000000000000000000000000f6"
CBOR_UNREGISTER_DREP = "83118200581c0000000000000000000000000000000000000000000000000000000000"
CBOR_UPDATE_DREP = "83128200581c00000000000000000000000000000000000000000000000000000000827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"


class TestCertificateFactoryMethods:
    """Tests for Certificate factory methods."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("00" * 28)
        return Credential.from_key_hash(key_hash)

    @pytest.fixture
    def pool_key_hash(self):
        """Create a test pool key hash."""
        return Blake2bHash.from_hex("00" * 28)

    @pytest.fixture
    def drep(self):
        """Create a test DRep."""
        key_hash = Blake2bHash.from_hex("00" * 28)
        cred = Credential.from_key_hash(key_hash)
        return DRep.new(DRepType.KEY_HASH, cred)

    def test_new_stake_registration(self, credential):
        """Test creating Certificate from StakeRegistrationCert."""
        stake_reg = StakeRegistrationCert.new(credential)
        cert = Certificate.new_stake_registration(stake_reg)
        assert cert.cert_type == CertificateType.STAKE_REGISTRATION

    def test_new_stake_deregistration(self, credential):
        """Test creating Certificate from StakeDeregistrationCert."""
        stake_dereg = StakeDeregistrationCert.new(credential)
        cert = Certificate.new_stake_deregistration(stake_dereg)
        assert cert.cert_type == CertificateType.STAKE_DEREGISTRATION

    def test_new_stake_delegation(self, credential, pool_key_hash):
        """Test creating Certificate from StakeDelegationCert."""
        stake_del = StakeDelegationCert.new(credential, pool_key_hash)
        cert = Certificate.new_stake_delegation(stake_del)
        assert cert.cert_type == CertificateType.STAKE_DELEGATION

    def test_new_pool_retirement(self, pool_key_hash):
        """Test creating Certificate from PoolRetirementCert."""
        pool_ret = PoolRetirementCert.new(pool_key_hash, epoch=100)
        cert = Certificate.new_pool_retirement(pool_ret)
        assert cert.cert_type == CertificateType.POOL_RETIREMENT

    def test_new_genesis_key_delegation(self):
        """Test creating Certificate from GenesisKeyDelegationCert."""
        genesis_hash = Blake2bHash.from_hex("00010001000100010001000100010001000100010001000100010001")
        delegate_hash = Blake2bHash.from_hex("00020002000200020002000200020002000200020002000200020002")
        vrf_hash = Blake2bHash.from_hex("00030003000300030003000300030003000300030003000300030003000300030003")
        genesis_cert = GenesisKeyDelegationCert.new(genesis_hash, delegate_hash, vrf_hash)
        cert = Certificate.new_genesis_key_delegation(genesis_cert)
        assert cert.cert_type == CertificateType.GENESIS_KEY_DELEGATION

    def test_new_mir(self):
        """Test creating Certificate from MirCert."""
        mir_to_pot = MirToPotCert.new(MirCertPotType.RESERVE, 1000000)
        mir = MirCert.new_to_other_pot(mir_to_pot)
        cert = Certificate.new_mir(mir)
        assert cert.cert_type == CertificateType.MOVE_INSTANTANEOUS_REWARDS

    def test_new_registration(self, credential):
        """Test creating Certificate from RegistrationCert."""
        reg = RegistrationCert.new(credential, deposit=0)
        cert = Certificate.new_registration(reg)
        assert cert.cert_type == CertificateType.REGISTRATION

    def test_new_unregistration(self, credential):
        """Test creating Certificate from UnregistrationCert."""
        unreg = UnregistrationCert.new(credential, deposit=0)
        cert = Certificate.new_unregistration(unreg)
        assert cert.cert_type == CertificateType.UNREGISTRATION

    def test_new_vote_delegation(self, credential, drep):
        """Test creating Certificate from VoteDelegationCert."""
        vote_del = VoteDelegationCert.new(credential, drep)
        cert = Certificate.new_vote_delegation(vote_del)
        assert cert.cert_type == CertificateType.VOTE_DELEGATION

    def test_new_stake_vote_delegation(self, credential, pool_key_hash, drep):
        """Test creating Certificate from StakeVoteDelegationCert."""
        stake_vote_del = StakeVoteDelegationCert.new(credential, pool_key_hash, drep)
        cert = Certificate.new_stake_vote_delegation(stake_vote_del)
        assert cert.cert_type == CertificateType.STAKE_VOTE_DELEGATION

    def test_new_stake_registration_delegation(self, credential, pool_key_hash):
        """Test creating Certificate from StakeRegistrationDelegationCert."""
        stake_reg_del = StakeRegistrationDelegationCert.new(credential, pool_key_hash, deposit=0)
        cert = Certificate.new_stake_registration_delegation(stake_reg_del)
        assert cert.cert_type == CertificateType.STAKE_REGISTRATION_DELEGATION

    def test_new_vote_registration_delegation(self, credential, drep):
        """Test creating Certificate from VoteRegistrationDelegationCert."""
        vote_reg_del = VoteRegistrationDelegationCert.new(credential, 0, drep)
        cert = Certificate.new_vote_registration_delegation(vote_reg_del)
        assert cert.cert_type == CertificateType.VOTE_REGISTRATION_DELEGATION

    def test_new_stake_vote_registration_delegation(self, credential, pool_key_hash, drep):
        """Test creating Certificate from StakeVoteRegistrationDelegationCert."""
        stake_vote_reg_del = StakeVoteRegistrationDelegationCert.new(
            credential, 0, drep, pool_key_hash
        )
        cert = Certificate.new_stake_vote_registration_delegation(stake_vote_reg_del)
        assert cert.cert_type == CertificateType.STAKE_VOTE_REGISTRATION_DELEGATION

    def test_new_auth_committee_hot(self, credential):
        """Test creating Certificate from AuthCommitteeHotCert."""
        cold_cred = credential
        hot_cred = Credential.from_key_hash(Blake2bHash.from_hex("00" * 28))
        auth_cert = AuthCommitteeHotCert.new(committee_cold_cred=cold_cred, committee_hot_cred=hot_cred)
        cert = Certificate.new_auth_committee_hot(auth_cert)
        assert cert.cert_type == CertificateType.AUTH_COMMITTEE_HOT

    def test_new_resign_committee_cold(self, credential):
        """Test creating Certificate from ResignCommitteeColdCert."""
        resign_cert = ResignCommitteeColdCert.new(credential)
        cert = Certificate.new_resign_committee_cold(resign_cert)
        assert cert.cert_type == CertificateType.RESIGN_COMMITTEE_COLD

    def test_new_register_drep(self, credential):
        """Test creating Certificate from RegisterDRepCert."""
        reg_drep = RegisterDRepCert.new(credential, deposit=0)
        cert = Certificate.new_register_drep(reg_drep)
        assert cert.cert_type == CertificateType.DREP_REGISTRATION

    def test_new_unregister_drep(self, credential):
        """Test creating Certificate from UnregisterDRepCert."""
        unreg_drep = UnregisterDRepCert.new(credential, deposit=0)
        cert = Certificate.new_unregister_drep(unreg_drep)
        assert cert.cert_type == CertificateType.DREP_UNREGISTRATION

    def test_new_update_drep(self, credential):
        """Test creating Certificate from UpdateDRepCert."""
        update_drep = UpdateDRepCert.new(credential)
        cert = Certificate.new_update_drep(update_drep)
        assert cert.cert_type == CertificateType.UPDATE_DREP


class TestCertificateConversionMethods:
    """Tests for Certificate conversion (to_*) methods."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("00" * 28)
        return Credential.from_key_hash(key_hash)

    @pytest.fixture
    def pool_key_hash(self):
        """Create a test pool key hash."""
        return Blake2bHash.from_hex("00" * 28)

    @pytest.fixture
    def drep(self):
        """Create a test DRep."""
        key_hash = Blake2bHash.from_hex("00" * 28)
        cred = Credential.from_key_hash(key_hash)
        return DRep.new(DRepType.KEY_HASH, cred)

    def test_to_stake_registration(self, credential):
        """Test extracting StakeRegistrationCert from Certificate."""
        stake_reg = StakeRegistrationCert.new(credential)
        cert = Certificate.new_stake_registration(stake_reg)
        extracted = cert.to_stake_registration()
        assert extracted is not None
        assert extracted.credential is not None

    def test_to_stake_deregistration(self, credential):
        """Test extracting StakeDeregistrationCert from Certificate."""
        stake_dereg = StakeDeregistrationCert.new(credential)
        cert = Certificate.new_stake_deregistration(stake_dereg)
        extracted = cert.to_stake_deregistration()
        assert extracted is not None
        assert extracted.credential is not None

    def test_to_stake_delegation(self, credential, pool_key_hash):
        """Test extracting StakeDelegationCert from Certificate."""
        stake_del = StakeDelegationCert.new(credential, pool_key_hash)
        cert = Certificate.new_stake_delegation(stake_del)
        extracted = cert.to_stake_delegation()
        assert extracted is not None
        assert extracted.credential is not None
        assert extracted.pool_key_hash is not None

    def test_to_pool_retirement(self, pool_key_hash):
        """Test extracting PoolRetirementCert from Certificate."""
        pool_ret = PoolRetirementCert.new(pool_key_hash, epoch=100)
        cert = Certificate.new_pool_retirement(pool_ret)
        extracted = cert.to_pool_retirement()
        assert extracted is not None
        assert extracted.epoch == 100

    def test_to_genesis_key_delegation(self):
        """Test extracting GenesisKeyDelegationCert from Certificate."""
        genesis_hash = Blake2bHash.from_hex("00010001000100010001000100010001000100010001000100010001")
        delegate_hash = Blake2bHash.from_hex("00020002000200020002000200020002000200020002000200020002")
        vrf_hash = Blake2bHash.from_hex("00030003000300030003000300030003000300030003000300030003000300030003")
        genesis_cert = GenesisKeyDelegationCert.new(genesis_hash, delegate_hash, vrf_hash)
        cert = Certificate.new_genesis_key_delegation(genesis_cert)
        extracted = cert.to_genesis_key_delegation()
        assert extracted is not None
        assert extracted.genesis_hash is not None

    def test_to_mir(self):
        """Test extracting MirCert from Certificate."""
        mir_to_pot = MirToPotCert.new(MirCertPotType.RESERVE, 1000000)
        mir = MirCert.new_to_other_pot(mir_to_pot)
        cert = Certificate.new_mir(mir)
        extracted = cert.to_mir()
        assert extracted is not None

    def test_to_registration(self, credential):
        """Test extracting RegistrationCert from Certificate."""
        reg = RegistrationCert.new(credential, deposit=0)
        cert = Certificate.new_registration(reg)
        extracted = cert.to_registration()
        assert extracted is not None
        assert extracted.credential is not None

    def test_to_unregistration(self, credential):
        """Test extracting UnregistrationCert from Certificate."""
        unreg = UnregistrationCert.new(credential, deposit=0)
        cert = Certificate.new_unregistration(unreg)
        extracted = cert.to_unregistration()
        assert extracted is not None
        assert extracted.credential is not None

    def test_to_vote_delegation(self, credential, drep):
        """Test extracting VoteDelegationCert from Certificate."""
        vote_del = VoteDelegationCert.new(credential, drep)
        cert = Certificate.new_vote_delegation(vote_del)
        extracted = cert.to_vote_delegation()
        assert extracted is not None
        assert extracted.credential is not None

    def test_to_stake_vote_delegation(self, credential, pool_key_hash, drep):
        """Test extracting StakeVoteDelegationCert from Certificate."""
        stake_vote_del = StakeVoteDelegationCert.new(credential, pool_key_hash, drep)
        cert = Certificate.new_stake_vote_delegation(stake_vote_del)
        extracted = cert.to_stake_vote_delegation()
        assert extracted is not None
        assert extracted.credential is not None

    def test_to_stake_registration_delegation(self, credential, pool_key_hash):
        """Test extracting StakeRegistrationDelegationCert from Certificate."""
        stake_reg_del = StakeRegistrationDelegationCert.new(credential, pool_key_hash, deposit=0)
        cert = Certificate.new_stake_registration_delegation(stake_reg_del)
        extracted = cert.to_stake_registration_delegation()
        assert extracted is not None
        assert extracted.credential is not None

    def test_to_vote_registration_delegation(self, credential, drep):
        """Test extracting VoteRegistrationDelegationCert from Certificate."""
        vote_reg_del = VoteRegistrationDelegationCert.new(credential, 0, drep)
        cert = Certificate.new_vote_registration_delegation(vote_reg_del)
        extracted = cert.to_vote_registration_delegation()
        assert extracted is not None
        assert extracted.credential is not None

    def test_to_stake_vote_registration_delegation(self, credential, pool_key_hash, drep):
        """Test extracting StakeVoteRegistrationDelegationCert from Certificate."""
        stake_vote_reg_del = StakeVoteRegistrationDelegationCert.new(
            credential, 0, drep, pool_key_hash
        )
        cert = Certificate.new_stake_vote_registration_delegation(stake_vote_reg_del)
        extracted = cert.to_stake_vote_registration_delegation()
        assert extracted is not None
        assert extracted.credential is not None

    def test_to_auth_committee_hot(self, credential):
        """Test extracting AuthCommitteeHotCert from Certificate."""
        cold_cred = credential
        hot_cred = Credential.from_key_hash(Blake2bHash.from_hex("00" * 28))
        auth_cert = AuthCommitteeHotCert.new(committee_cold_cred=cold_cred, committee_hot_cred=hot_cred)
        cert = Certificate.new_auth_committee_hot(auth_cert)
        extracted = cert.to_auth_committee_hot()
        assert extracted is not None
        assert extracted.committee_cold_credential is not None

    def test_to_resign_committee_cold(self, credential):
        """Test extracting ResignCommitteeColdCert from Certificate."""
        resign_cert = ResignCommitteeColdCert.new(credential)
        cert = Certificate.new_resign_committee_cold(resign_cert)
        extracted = cert.to_resign_committee_cold()
        assert extracted is not None
        assert extracted.committee_cold_credential is not None

    def test_to_register_drep(self, credential):
        """Test extracting RegisterDRepCert from Certificate."""
        reg_drep = RegisterDRepCert.new(credential, deposit=0)
        cert = Certificate.new_register_drep(reg_drep)
        extracted = cert.to_register_drep()
        assert extracted is not None
        assert extracted.credential is not None

    def test_to_unregister_drep(self, credential):
        """Test extracting UnregisterDRepCert from Certificate."""
        unreg_drep = UnregisterDRepCert.new(credential, deposit=0)
        cert = Certificate.new_unregister_drep(unreg_drep)
        extracted = cert.to_unregister_drep()
        assert extracted is not None
        assert extracted.credential is not None

    def test_to_update_drep(self, credential):
        """Test extracting UpdateDRepCert from Certificate."""
        update_drep = UpdateDRepCert.new(credential)
        cert = Certificate.new_update_drep(update_drep)
        extracted = cert.to_update_drep()
        assert extracted is not None
        assert extracted.credential is not None

    def test_conversion_error_on_wrong_type(self, credential):
        """Test that converting to wrong type raises CardanoError."""
        stake_reg = StakeRegistrationCert.new(credential)
        cert = Certificate.new_stake_registration(stake_reg)
        with pytest.raises(CardanoError):
            cert.to_pool_retirement()


class TestCertificateCbor:
    """Tests for Certificate CBOR serialization/deserialization."""

    def test_cbor_stake_registration(self):
        """Test CBOR deserialization of stake registration certificate."""
        reader = CborReader.from_hex(CBOR_STAKE_REGISTRATION)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.STAKE_REGISTRATION

    def test_cbor_stake_deregistration(self):
        """Test CBOR deserialization of stake deregistration certificate."""
        reader = CborReader.from_hex(CBOR_STAKE_DEREGISTRATION)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.STAKE_DEREGISTRATION

    def test_cbor_stake_delegation(self):
        """Test CBOR deserialization of stake delegation certificate."""
        reader = CborReader.from_hex(CBOR_STAKE_DELEGATION)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.STAKE_DELEGATION

    def test_cbor_pool_retirement(self):
        """Test CBOR deserialization of pool retirement certificate."""
        reader = CborReader.from_hex(CBOR_POOL_RETIREMENT)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.POOL_RETIREMENT

    def test_cbor_genesis_key_delegation(self):
        """Test CBOR deserialization of genesis key delegation certificate."""
        reader = CborReader.from_hex(CBOR_GENESIS_DELEGATION)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.GENESIS_KEY_DELEGATION

    def test_cbor_mir(self):
        """Test CBOR deserialization of MIR certificate."""
        reader = CborReader.from_hex(CBOR_MIR)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.MOVE_INSTANTANEOUS_REWARDS

    def test_cbor_registration(self):
        """Test CBOR deserialization of registration certificate."""
        reader = CborReader.from_hex(CBOR_REGISTRATION)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.REGISTRATION

    def test_cbor_unregistration(self):
        """Test CBOR deserialization of unregistration certificate."""
        reader = CborReader.from_hex(CBOR_UNREGISTRATION)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.UNREGISTRATION

    def test_cbor_vote_delegation(self):
        """Test CBOR deserialization of vote delegation certificate."""
        reader = CborReader.from_hex(CBOR_VOTE_DELEGATION)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.VOTE_DELEGATION

    def test_cbor_stake_vote_delegation(self):
        """Test CBOR deserialization of stake vote delegation certificate."""
        reader = CborReader.from_hex(CBOR_STAKE_VOTE_DELEGATION)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.STAKE_VOTE_DELEGATION

    def test_cbor_stake_registration_delegation(self):
        """Test CBOR deserialization of stake registration delegation certificate."""
        reader = CborReader.from_hex(CBOR_STAKE_REGISTRATION_DELEGATION)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.STAKE_REGISTRATION_DELEGATION

    def test_cbor_vote_registration_delegation(self):
        """Test CBOR deserialization of vote registration delegation certificate."""
        reader = CborReader.from_hex(CBOR_VOTE_REGISTRATION_DELEGATION)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.VOTE_REGISTRATION_DELEGATION

    def test_cbor_stake_vote_registration_delegation(self):
        """Test CBOR deserialization of stake vote registration delegation certificate."""
        reader = CborReader.from_hex(CBOR_STAKE_VOTE_REGISTRATION_DELEGATION)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.STAKE_VOTE_REGISTRATION_DELEGATION

    def test_cbor_auth_committee_hot(self):
        """Test CBOR deserialization of auth committee hot certificate."""
        reader = CborReader.from_hex(CBOR_AUTHORIZE_COMMITTEE_HOT)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.AUTH_COMMITTEE_HOT

    def test_cbor_resign_committee_cold(self):
        """Test CBOR deserialization of resign committee cold certificate."""
        reader = CborReader.from_hex(CBOR_RESIGN_COMMITTEE_COLD)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.RESIGN_COMMITTEE_COLD

    def test_cbor_register_drep(self):
        """Test CBOR deserialization of register DRep certificate."""
        reader = CborReader.from_hex(CBOR_REGISTER_DREP)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.DREP_REGISTRATION

    def test_cbor_unregister_drep(self):
        """Test CBOR deserialization of unregister DRep certificate."""
        reader = CborReader.from_hex(CBOR_UNREGISTER_DREP)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.DREP_UNREGISTRATION

    def test_cbor_update_drep(self):
        """Test CBOR deserialization of update DRep certificate."""
        reader = CborReader.from_hex(CBOR_UPDATE_DREP)
        cert = Certificate.from_cbor(reader)
        assert cert.cert_type == CertificateType.UPDATE_DREP

    def test_cbor_roundtrip(self):
        """Test CBOR serialization and deserialization roundtrip."""
        credential = Credential.from_key_hash(Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f"))
        stake_reg = StakeRegistrationCert.new(credential)
        cert = Certificate.new_stake_registration(stake_reg)

        writer = CborWriter()
        cert.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        cert_restored = Certificate.from_cbor(reader)
        assert cert_restored.cert_type == CertificateType.STAKE_REGISTRATION


class TestCertificateAutoConversion:
    """Tests for Certificate automatic conversion from specific certificate types."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("00" * 28)
        return Credential.from_key_hash(key_hash)

    def test_init_with_stake_registration(self, credential):
        """Test __init__ with StakeRegistrationCert."""
        stake_reg = StakeRegistrationCert.new(credential)
        cert = Certificate(stake_reg)
        assert cert.cert_type == CertificateType.STAKE_REGISTRATION

    def test_init_with_stake_deregistration(self, credential):
        """Test __init__ with StakeDeregistrationCert."""
        stake_dereg = StakeDeregistrationCert.new(credential)
        cert = Certificate(stake_dereg)
        assert cert.cert_type == CertificateType.STAKE_DEREGISTRATION

    def test_init_with_registration(self, credential):
        """Test __init__ with RegistrationCert."""
        reg = RegistrationCert.new(credential, deposit=0)
        cert = Certificate(reg)
        assert cert.cert_type == CertificateType.REGISTRATION

    def test_init_with_another_certificate(self, credential):
        """Test __init__ with another Certificate (should ref)."""
        stake_reg = StakeRegistrationCert.new(credential)
        cert1 = Certificate.new_stake_registration(stake_reg)
        cert2 = Certificate(cert1)
        assert cert2.cert_type == CertificateType.STAKE_REGISTRATION

    def test_from_cert_classmethod(self, credential):
        """Test from_cert class method."""
        stake_reg = StakeRegistrationCert.new(credential)
        cert = Certificate.from_cert(stake_reg)
        assert cert.cert_type == CertificateType.STAKE_REGISTRATION


class TestCertificateProperties:
    """Tests for Certificate properties."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("00" * 28)
        return Credential.from_key_hash(key_hash)

    def test_cert_type_property(self, credential):
        """Test cert_type property."""
        stake_reg = StakeRegistrationCert.new(credential)
        cert = Certificate.new_stake_registration(stake_reg)
        assert cert.cert_type == CertificateType.STAKE_REGISTRATION
        assert isinstance(cert.cert_type, CertificateType)


class TestCertificateCip116Json:
    """Tests for Certificate CIP-116 JSON serialization."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("00" * 28)
        return Credential.from_key_hash(key_hash)

    def test_to_cip116_json(self, credential):
        """Test CIP-116 JSON serialization."""
        reg = RegistrationCert.new(credential, deposit=0)
        cert = Certificate.new_registration(reg)

        writer = JsonWriter()
        cert.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str is not None
        assert len(json_str) > 0

    def test_to_cip116_json_with_invalid_writer(self, credential):
        """Test CIP-116 JSON serialization with invalid writer."""
        stake_reg = StakeRegistrationCert.new(credential)
        cert = Certificate.new_stake_registration(stake_reg)

        with pytest.raises(TypeError):
            cert.to_cip116_json("not a writer")


class TestCertificateErrorCases:
    """Tests for Certificate error cases."""

    def test_init_with_invalid_type(self):
        """Test __init__ with invalid type raises TypeError."""
        with pytest.raises(TypeError):
            Certificate("invalid")

    def test_init_with_integer(self):
        """Test __init__ with integer raises TypeError."""
        with pytest.raises(TypeError):
            Certificate(123)

    def test_init_with_none(self):
        """Test __init__ with None raises error."""
        with pytest.raises((TypeError, CardanoError)):
            Certificate(None)


class TestCertificateRepr:
    """Tests for Certificate repr."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("00" * 28)
        return Credential.from_key_hash(key_hash)

    def test_repr(self, credential):
        """Test repr method."""
        stake_reg = StakeRegistrationCert.new(credential)
        cert = Certificate.new_stake_registration(stake_reg)
        repr_str = repr(cert)
        assert "Certificate" in repr_str
        assert "STAKE_REGISTRATION" in repr_str


class TestCertificateContextManager:
    """Tests for Certificate context manager support."""

    @pytest.fixture
    def credential(self):
        """Create a test credential."""
        key_hash = Blake2bHash.from_hex("00" * 28)
        return Credential.from_key_hash(key_hash)

    def test_context_manager(self, credential):
        """Test context manager support."""
        stake_reg = StakeRegistrationCert.new(credential)
        cert = Certificate.new_stake_registration(stake_reg)

        with cert as c:
            assert c is not None
            assert c.cert_type == CertificateType.STAKE_REGISTRATION
