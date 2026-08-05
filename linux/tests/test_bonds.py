import json
import stat

import pytest

from blekeyboard.bonds import BondStore, default_bond_path
from blekeyboard.smp import BondKeys


@pytest.fixture
def store_path(tmp_path):
    return tmp_path / "state" / "bonds.json"


def sc_bond(ltk_byte=0xAA):
    """A Secure Connections bond: resumed with a zero EDIV/Rand."""
    return BondKeys(ltk=bytes([ltk_byte]) * 16, ediv=0, rand=bytes(8))


def legacy_bond(rand_start=1, ltk_byte=0xBB):
    """A legacy bond: carries a unique random EDIV/Rand."""
    return BondKeys(ltk=bytes([ltk_byte]) * 16, ediv=0x1234,
                    rand=bytes(range(rand_start, rand_start + 8)))


def test_loading_a_missing_file_yields_no_bonds(store_path):
    assert BondStore(store_path).load() == []


def test_a_saved_bond_round_trips(store_path):
    store = BondStore(store_path)
    bond = sc_bond()
    store.add(bond)

    loaded = BondStore(store_path).load()
    assert len(loaded) == 1
    assert loaded[0].ltk == bond.ltk
    assert loaded[0].ediv == bond.ediv
    assert loaded[0].rand == bond.rand


def test_a_new_bond_replaces_one_resumed_the_same_way(store_path):
    # Two SC bonds both resume with a zero EDIV/Rand, so the newer must
    # supersede the older rather than both lingering ambiguously.
    store = BondStore(store_path)
    store.add(sc_bond(ltk_byte=0x11))
    store.add(sc_bond(ltk_byte=0x22))

    loaded = store.load()
    assert len(loaded) == 1
    assert loaded[0].ltk == bytes([0x22]) * 16


def test_legacy_bonds_with_distinct_rands_coexist(store_path):
    store = BondStore(store_path)
    store.add(legacy_bond(rand_start=1))
    store.add(legacy_bond(rand_start=100))

    assert len(store.load()) == 2


def test_a_legacy_and_an_sc_bond_coexist(store_path):
    store = BondStore(store_path)
    store.add(sc_bond())
    store.add(legacy_bond())

    assert len(store.load()) == 2


def test_the_bond_file_is_owner_readable_only(store_path):
    store = BondStore(store_path)
    store.add(sc_bond())

    mode = stat.S_IMODE(store_path.stat().st_mode)
    assert mode == 0o600


def test_a_corrupt_file_loads_as_empty_rather_than_raising(store_path):
    store_path.parent.mkdir(parents=True)
    store_path.write_text("this is not json {")
    assert BondStore(store_path).load() == []


def test_a_malformed_record_is_skipped_without_losing_the_rest(store_path):
    store_path.parent.mkdir(parents=True)
    good = {"ltk": ("cc" * 16), "ediv": 0, "rand": ("00" * 8)}
    store_path.write_text(json.dumps([{"ltk": "nothex"}, good]))

    loaded = BondStore(store_path).load()
    assert len(loaded) == 1
    assert loaded[0].ltk == bytes([0xCC]) * 16


def test_default_path_follows_xdg_state_home(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert default_bond_path() == tmp_path / "blekeyboard" / "bonds.json"
