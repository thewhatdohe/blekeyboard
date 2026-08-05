"""
Persistence for the Long Term Keys a bond is built on.

A bond is meant to outlive the process that formed it: once a host has
paired, it expects to reconnect and resume the encrypted session straight
from the key it was given, without pairing again. iOS in particular never
re-pairs on its own - it keeps asking to resume, and a peripheral that has
forgotten the key can only refuse, leaving the two stuck in a reconnect
loop. Writing the key to disk lets a fresh run answer that resume request.

A resume request names the bond it wants by its EDIV/Rand, not by address,
which matters because iOS reconnects from a rotating random address. Secure
Connections always resumes with a zero EDIV/Rand, so there is only ever one
such bond and the rotating address is irrelevant to finding it.

The file holds Long Term Keys, which are secrets: anyone with both the file
and radio proximity could impersonate the paired host to this device. It is
written owner-readable only for that reason, and kept under the user's XDG
state directory rather than the working tree.
"""

import json
import os
from pathlib import Path

from blekeyboard.smp import BondKeys


def default_bond_path() -> Path:
    """The bond file location, honouring XDG_STATE_HOME when it is set."""
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(base) / "blekeyboard" / "bonds.json"


class BondStore:
    """Loads and saves the bonds a reconnecting host can resume from."""

    def __init__(self, path=None):
        self._path = Path(path) if path is not None else default_bond_path()

    def load(self) -> list:
        """Returns the stored bonds, or an empty list if there are none."""
        try:
            records = json.loads(self._path.read_text())
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return []

        bonds = []
        for record in records:
            try:
                bonds.append(BondKeys(
                    ltk=bytes.fromhex(record["ltk"]),
                    ediv=int(record["ediv"]),
                    rand=bytes.fromhex(record["rand"]),
                ))
            except (KeyError, ValueError, TypeError):
                # A malformed record is skipped rather than aborting the load,
                # so one bad entry cannot lock out every other bond.
                continue
        return bonds

    def add(self, bond: BondKeys):
        """
        Records a bond, replacing any earlier one a host would resume the
        same way.

        Two bonds sharing an EDIV/Rand are indistinguishable to the resume
        request that names them, so the newer supersedes the older. A Secure
        Connections bond always carries a zero EDIV/Rand, so this keeps a
        single, current SC bond; legacy bonds carry a random Rand and coexist.
        """
        kept = [b for b in self.load()
                if not (b.ediv == bond.ediv and b.rand == bond.rand)]
        kept.append(bond)
        self._write(kept)

    def _write(self, bonds):
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        records = [
            {"ltk": b.ltk.hex(), "ediv": b.ediv, "rand": b.rand.hex()}
            for b in bonds
        ]

        # Write to a sibling file and swap it in, so an interrupted write can
        # never leave a half-written bond file behind.
        tmp = self._path.with_name(self._path.name + ".tmp")
        tmp.write_text(json.dumps(records, indent=2))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._path)
