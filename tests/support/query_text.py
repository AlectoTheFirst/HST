"""The query text the test fakes match against."""


def unpinned(query: str) -> str:
    """The query without its run index anchors (`:Obj`, `collection_ts: $snap`
    in a node pattern), the text the fakes' substring matches were written
    against."""
    query = query.replace(", collection_ts: $snap}", "}").replace(" {collection_ts: $snap}", "")
    return query.replace(":Obj", "")
