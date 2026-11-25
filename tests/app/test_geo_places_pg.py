"""HST_TEST_PG_DSN names a disposable database."""

import asyncio
import os

import pytest

pytestmark = pytest.mark.pg
DSN = os.environ.get("HST_TEST_PG_DSN")
if not DSN:
    pytest.skip("HST_TEST_PG_DSN not set", allow_module_level=True)

from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402
from tests.app.test_geo_places import _places  # noqa: E402

from hst.app.store.pg import PgStore, geo_places, upgrade_to_head  # noqa: E402


@pytest.fixture
async def store():
    await asyncio.to_thread(upgrade_to_head, DSN)
    engine = create_async_engine(DSN)
    async with engine.begin() as conn:
        await conn.execute(geo_places.delete())
    await engine.dispose()
    st = PgStore(DSN)
    yield st
    await st.dispose()


async def test_search_matches_prefixes_folds_places_and_replaces_the_table(store):
    empty = await store.search_geo_places("ber", "", 10)
    assert empty.items == [] and empty.available is False

    assert await store.replace_geo_places(_places()) == 5
    found = await store.search_geo_places("frankfurt", "", 10)
    assert [(p.name, p.postal_code) for p in found.items] == [
        ("Frankfurt (Oder)", None),
        ("Frankfurt am Main", None),
    ]
    assert (round(found.items[1].lat, 4), round(found.items[1].lon, 4)) == (50.1137, 8.6842)
    assert [p.postal_code for p in (await store.search_geo_places("", "6031", 10)).items] == [
        "60311",
        "60313",
    ]
    both = await store.search_geo_places("berli", "10115", 10)
    assert [(p.name, p.postal_code, p.lat, p.lon) for p in both.items] == [
        ("Berlin", "10115", 52.5323, 13.3846)
    ]
    assert [p.name for p in (await store.search_geo_places("munch", "", 10)).items] == ["München"]
    assert len((await store.search_geo_places("frankfurt", "", 1)).items) == 1

    assert await store.replace_geo_places(_places()[:1]) == 1
    assert (await store.search_geo_places("frankfurt", "", 10)).items == []
