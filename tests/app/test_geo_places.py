"""The site address lookup: the GeoNames reader, the query rules and the
route over the fake store. The Postgres search is in test_geo_places_pg.py."""

import zipfile

import pytest
from tests.app.conftest import login

from hst.app.geo_places import name_key, parse_query, read_geonames
from hst.app.store import GeoPlace

# country, postal, place, admin1, admin1 code, admin2, admin2 code, admin3, admin3 code, lat, lon, accuracy
ROWS = [
    "\t".join(row)
    for row in (
        ("DE", "10115", "Berlin", "Berlin", "BE", "", "00", "", "", "52.5323", "13.3846", "4"),
        (
            "DE",
            "60311",
            "Frankfurt am Main",
            "Hessen",
            "05",
            "Regierungsbezirk Darmstadt",
            "064",
            "",
            "",
            "50.1127",
            "8.6832",
            "4",
        ),
        (
            "DE",
            "60313",
            "Frankfurt am Main",
            "Hessen",
            "05",
            "Regierungsbezirk Darmstadt",
            "064",
            "",
            "",
            "50.1147",
            "8.6852",
            "4",
        ),
        ("DE", "15230", "Frankfurt (Oder)", "Brandenburg", "BB", "", "00", "", "", "52.3471", "14.5506", "4"),
        ("DE", "80331", "München", "Bayern", "BY", "Oberbayern", "091", "", "", "48.1372", "11.5755", "4"),
        ("DE", "99999", "Nowhere", "Bayern", "BY", "", "", "", "", "", "", ""),
    )
]


def _places() -> list[GeoPlace]:
    return [
        GeoPlace(r[0], r[1], r[2], r[3], r[5], float(r[9]), float(r[10]))
        for r in (line.split("\t") for line in ROWS)
        if r[9]
    ]


def test_name_key_folds_case_accents_and_punctuation():
    assert name_key("München") == "munchen"
    assert name_key("Frankfurt (Oder)") == "frankfurt oder"
    assert name_key("  Saint-Étienne ") == "saint etienne"


def test_a_token_with_a_digit_is_the_postal_code_and_the_rest_the_name():
    assert parse_query("Berli") == parse_query("berli")
    q = parse_query("10115 Berli")
    assert q is not None and (q.name, q.postal) == ("berli", "10115")
    q = parse_query("sw1a")
    assert q is not None and (q.name, q.postal) == ("", "SW1A")
    q = parse_query("80%_1")
    assert q is not None and q.postal == "801"
    assert parse_query("e") is None and parse_query("  ") is None


@pytest.mark.parametrize("zipped", [True, False])
def test_the_reader_takes_the_zip_or_the_text_and_skips_rows_without_a_point(tmp_path, zipped):
    text = tmp_path / "DE.txt"
    text.write_text("\n".join(ROWS) + "\n", encoding="utf-8")
    path = text
    if zipped:
        path = tmp_path / "DE.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.write(text, "DE.txt")
            archive.writestr("readme.txt", "not data")
    places = list(read_geonames(path))
    assert places == _places()
    assert places[0] == GeoPlace("DE", "10115", "Berlin", "Berlin", "", 52.5323, 13.3846)


async def test_the_route_folds_postal_codes_of_one_place_without_a_postal_query(client, store):
    await login(client, "vera")
    r = await client.get("/api/geo-places?q=ber")
    assert r.status_code == 200 and r.json() == {"items": [], "available": False}

    await store.replace_geo_places(_places())
    body = (await client.get("/api/geo-places?q=frankfurt")).json()
    assert body["available"] is True
    assert [(p["name"], p["postal_code"]) for p in body["items"]] == [
        ("Frankfurt (Oder)", None),
        ("Frankfurt am Main", None),
    ]
    main = body["items"][1]
    assert (main["lat"], main["lon"]) == (50.1137, 8.6842)

    body = (await client.get("/api/geo-places?q=6031")).json()
    assert [p["postal_code"] for p in body["items"]] == ["60311", "60313"]
    body = (await client.get("/api/geo-places?q=10115 berli")).json()
    assert body["items"] == [
        {
            "country_code": "DE",
            "postal_code": "10115",
            "name": "Berlin",
            "admin1": "Berlin",
            "admin2": "",
            "lat": 52.5323,
            "lon": 13.3846,
        }
    ]
    assert [p["name"] for p in (await client.get("/api/geo-places?q=munch")).json()["items"]] == ["München"]
    assert (await client.get("/api/geo-places?q=e")).json() == {"items": [], "available": True}
    assert (await client.get("/api/geo-places?q=fra&limit=21")).status_code == 422
