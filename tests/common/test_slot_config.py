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
from cometa import SlotConfig


class TestSlotConfig:
    """Tests for the SlotConfig dataclass."""

    def test_init_valid_arguments(self):
        """Test creating SlotConfig with valid arguments."""
        config = SlotConfig(
            zero_time=1596059091000,
            zero_slot=4492800,
            slot_length=1000
        )
        assert config.zero_time == 1596059091000
        assert config.zero_slot == 4492800
        assert config.slot_length == 1000

    def test_init_zero_values(self):
        """Test creating SlotConfig with zero values."""
        config = SlotConfig(zero_time=0, zero_slot=0, slot_length=1)
        assert config.zero_time == 0
        assert config.zero_slot == 0
        assert config.slot_length == 1

    def test_init_large_values(self):
        """Test creating SlotConfig with large values."""
        config = SlotConfig(
            zero_time=9999999999999,
            zero_slot=999999999,
            slot_length=10000
        )
        assert config.zero_time == 9999999999999
        assert config.zero_slot == 999999999
        assert config.slot_length == 10000

    def test_mainnet_factory(self):
        """Test mainnet factory method returns correct configuration."""
        config = SlotConfig.mainnet()
        assert isinstance(config, SlotConfig)
        assert config.zero_time == 1596059091000
        assert config.zero_slot == 4492800
        assert config.slot_length == 1000

    def test_mainnet_factory_creates_new_instance(self):
        """Test mainnet factory creates independent instances."""
        config1 = SlotConfig.mainnet()
        config2 = SlotConfig.mainnet()
        assert config1 == config2
        assert config1 is not config2

    def test_preview_factory(self):
        """Test preview factory method returns correct configuration."""
        config = SlotConfig.preview()
        assert isinstance(config, SlotConfig)
        assert config.zero_time == 1666656000000
        assert config.zero_slot == 0
        assert config.slot_length == 1000

    def test_preview_factory_creates_new_instance(self):
        """Test preview factory creates independent instances."""
        config1 = SlotConfig.preview()
        config2 = SlotConfig.preview()
        assert config1 == config2
        assert config1 is not config2

    def test_preprod_factory(self):
        """Test preprod factory method returns correct configuration."""
        config = SlotConfig.preprod()
        assert isinstance(config, SlotConfig)
        assert config.zero_time == 1654041600000 + 1728000000
        assert config.zero_slot == 86400
        assert config.slot_length == 1000

    def test_preprod_factory_creates_new_instance(self):
        """Test preprod factory creates independent instances."""
        config1 = SlotConfig.preprod()
        config2 = SlotConfig.preprod()
        assert config1 == config2
        assert config1 is not config2

    def test_equality_same_values(self):
        """Test equality comparison with same values."""
        config1 = SlotConfig(zero_time=1000, zero_slot=100, slot_length=10)
        config2 = SlotConfig(zero_time=1000, zero_slot=100, slot_length=10)
        assert config1 == config2

    def test_equality_different_zero_time(self):
        """Test inequality when zero_time differs."""
        config1 = SlotConfig(zero_time=1000, zero_slot=100, slot_length=10)
        config2 = SlotConfig(zero_time=2000, zero_slot=100, slot_length=10)
        assert config1 != config2

    def test_equality_different_zero_slot(self):
        """Test inequality when zero_slot differs."""
        config1 = SlotConfig(zero_time=1000, zero_slot=100, slot_length=10)
        config2 = SlotConfig(zero_time=1000, zero_slot=200, slot_length=10)
        assert config1 != config2

    def test_equality_different_slot_length(self):
        """Test inequality when slot_length differs."""
        config1 = SlotConfig(zero_time=1000, zero_slot=100, slot_length=10)
        config2 = SlotConfig(zero_time=1000, zero_slot=100, slot_length=20)
        assert config1 != config2

    def test_equality_with_non_slot_config(self):
        """Test inequality when comparing with non-SlotConfig object."""
        config = SlotConfig(zero_time=1000, zero_slot=100, slot_length=10)
        assert config != "not a slot config"
        assert config != 12345
        assert config != None
        assert config != {"zero_time": 1000, "zero_slot": 100, "slot_length": 10}

    def test_repr(self):
        """Test string representation of SlotConfig."""
        config = SlotConfig(zero_time=1000, zero_slot=100, slot_length=10)
        repr_str = repr(config)
        assert "SlotConfig" in repr_str
        assert "zero_time=1000" in repr_str
        assert "zero_slot=100" in repr_str
        assert "slot_length=10" in repr_str

    def test_str(self):
        """Test str conversion of SlotConfig."""
        config = SlotConfig(zero_time=1000, zero_slot=100, slot_length=10)
        str_repr = str(config)
        assert "SlotConfig" in str_repr
        assert "1000" in str_repr
        assert "100" in str_repr
        assert "10" in str_repr

    def test_attribute_modification(self):
        """Test that SlotConfig attributes can be modified."""
        config = SlotConfig(zero_time=1000, zero_slot=100, slot_length=10)
        config.zero_time = 2000
        config.zero_slot = 200
        config.slot_length = 20
        assert config.zero_time == 2000
        assert config.zero_slot == 200
        assert config.slot_length == 20

    def test_is_mutable(self):
        """Test that SlotConfig is mutable and not hashable."""
        config = SlotConfig(zero_time=1000, zero_slot=100, slot_length=10)
        with pytest.raises(TypeError, match="unhashable type"):
            hash(config)
        with pytest.raises(TypeError, match="unhashable type"):
            {config: "value"}
        with pytest.raises(TypeError, match="unhashable type"):
            {config}

    def test_network_configs_are_different(self):
        """Test that different network configs have different values."""
        mainnet = SlotConfig.mainnet()
        preview = SlotConfig.preview()
        preprod = SlotConfig.preprod()
        assert mainnet != preview
        assert mainnet != preprod
        assert preview != preprod

    def test_negative_zero_time(self):
        """Test creating SlotConfig with negative zero_time."""
        config = SlotConfig(zero_time=-1000, zero_slot=100, slot_length=10)
        assert config.zero_time == -1000

    def test_negative_zero_slot(self):
        """Test creating SlotConfig with negative zero_slot."""
        config = SlotConfig(zero_time=1000, zero_slot=-100, slot_length=10)
        assert config.zero_slot == -100

    def test_negative_slot_length(self):
        """Test creating SlotConfig with negative slot_length."""
        config = SlotConfig(zero_time=1000, zero_slot=100, slot_length=-10)
        assert config.slot_length == -10

    def test_init_with_keyword_arguments(self):
        """Test creating SlotConfig with keyword arguments."""
        config = SlotConfig(
            slot_length=1000,
            zero_slot=4492800,
            zero_time=1596059091000
        )
        assert config.zero_time == 1596059091000
        assert config.zero_slot == 4492800
        assert config.slot_length == 1000

    def test_init_with_positional_arguments(self):
        """Test creating SlotConfig with positional arguments."""
        config = SlotConfig(1596059091000, 4492800, 1000)
        assert config.zero_time == 1596059091000
        assert config.zero_slot == 4492800
        assert config.slot_length == 1000

    def test_init_with_mixed_arguments(self):
        """Test creating SlotConfig with mixed positional and keyword arguments."""
        config = SlotConfig(1596059091000, zero_slot=4492800, slot_length=1000)
        assert config.zero_time == 1596059091000
        assert config.zero_slot == 4492800
        assert config.slot_length == 1000

    def test_init_missing_arguments(self):
        """Test that creating SlotConfig without required arguments raises TypeError."""
        with pytest.raises(TypeError):
            SlotConfig()
        with pytest.raises(TypeError):
            SlotConfig(zero_time=1000)
        with pytest.raises(TypeError):
            SlotConfig(zero_time=1000, zero_slot=100)

    def test_init_invalid_type_zero_time(self):
        """Test that invalid type for zero_time is accepted by dataclass."""
        config = SlotConfig(zero_time="invalid", zero_slot=100, slot_length=10)
        assert config.zero_time == "invalid"

    def test_init_invalid_type_zero_slot(self):
        """Test that invalid type for zero_slot is accepted by dataclass."""
        config = SlotConfig(zero_time=1000, zero_slot="invalid", slot_length=10)
        assert config.zero_slot == "invalid"

    def test_init_invalid_type_slot_length(self):
        """Test that invalid type for slot_length is accepted by dataclass."""
        config = SlotConfig(zero_time=1000, zero_slot=100, slot_length="invalid")
        assert config.slot_length == "invalid"

    def test_dataclass_features(self):
        """Test that SlotConfig has dataclass features."""
        config = SlotConfig(zero_time=1000, zero_slot=100, slot_length=10)
        assert hasattr(config, "__dataclass_fields__")
        assert "zero_time" in config.__dataclass_fields__
        assert "zero_slot" in config.__dataclass_fields__
        assert "slot_length" in config.__dataclass_fields__

    def test_fields_order(self):
        """Test that fields are in the expected order."""
        config = SlotConfig(zero_time=1000, zero_slot=100, slot_length=10)
        field_names = list(config.__dataclass_fields__.keys())
        assert field_names == ["zero_time", "zero_slot", "slot_length"]

    def test_copy_and_modify(self):
        """Test copying and modifying a SlotConfig."""
        original = SlotConfig.mainnet()
        modified = SlotConfig(
            zero_time=original.zero_time,
            zero_slot=original.zero_slot + 1000,
            slot_length=original.slot_length
        )
        assert modified.zero_slot == original.zero_slot + 1000
        assert modified.zero_time == original.zero_time
        assert modified.slot_length == original.slot_length
        assert modified != original

    def test_mainnet_values_match_documentation(self):
        """Test mainnet configuration matches expected Cardano values."""
        mainnet = SlotConfig.mainnet()
        assert mainnet.zero_time == 1596059091000
        assert mainnet.zero_slot == 4492800
        assert mainnet.slot_length == 1000

    def test_preview_values_match_documentation(self):
        """Test preview configuration matches expected Cardano values."""
        preview = SlotConfig.preview()
        assert preview.zero_time == 1666656000000
        assert preview.zero_slot == 0
        assert preview.slot_length == 1000

    def test_preprod_values_match_documentation(self):
        """Test preprod configuration matches expected Cardano values."""
        preprod = SlotConfig.preprod()
        expected_zero_time = 1654041600000 + 1728000000
        assert preprod.zero_time == expected_zero_time
        assert preprod.zero_slot == 86400
        assert preprod.slot_length == 1000

    def test_slot_length_consistency(self):
        """Test that all network configs use 1000ms slot length."""
        mainnet = SlotConfig.mainnet()
        preview = SlotConfig.preview()
        preprod = SlotConfig.preprod()
        assert mainnet.slot_length == 1000
        assert preview.slot_length == 1000
        assert preprod.slot_length == 1000
