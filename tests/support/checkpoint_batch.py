"""A Check Point batch with its envelopes back on the nodes.

The collector writes each rule's, layer's, package's and object's API
envelope to the `checkpoint_envelopes` side-store table and keeps only the
digest on the node. A graph load puts the envelope back
(analysis_model/checkpoint_envelopes.py `hydrate`); `normalize` does the same
for a batch a test indexes as a GraphInventory directly.
"""

from __future__ import annotations

from typing import Any

from hst.analysis_model.checkpoint_envelopes import ENVELOPE_PROPERTY, SHA_PROPERTY
from hst.collectors.checkpoint import normalize_checkpoint
from hst.core.model import Batch


def normalize(raw: dict[str, Any], **kwargs: Any) -> Batch:
    """`normalize_checkpoint(raw, **kwargs)` with every node that carries an
    envelope digest given its envelope, as a graph load gives it."""
    rows: list[dict[str, str]] = []
    batch = normalize_checkpoint(raw, envelope_rows=rows, **kwargs)
    envelopes = {row["uid"]: row["envelope"] for row in rows}
    for node in batch.nodes:
        if node.props.get(SHA_PROPERTY) is not None and node.uid in envelopes:
            node.props[ENVELOPE_PROPERTY] = envelopes[node.uid]
    return batch
