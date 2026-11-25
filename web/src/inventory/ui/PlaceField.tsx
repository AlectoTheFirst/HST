import { useId, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { searchGeoPlaces, type GeoPlace } from "../../api/geoPlaces";
import { useDebounced } from "./SitePicker";

export interface SitePoint {
  lat: number;
  lon: number;
}

let regions: Intl.DisplayNames | null | undefined;

function countryName(code: string): string {
  if (regions === undefined) {
    try { regions = new Intl.DisplayNames(["en"], { type: "region" }); } catch { regions = null; }
  }
  try { return regions?.of(code) ?? code; } catch { return code; }
}

/** The text a chosen place writes into the geography field. */
export function placeLabel(place: GeoPlace): string {
  const head = place.postal_code ? `${place.postal_code} ${place.name}` : place.name;
  return [head, place.admin1, countryName(place.country_code)].filter(Boolean).join(", ");
}

const formatPoint = (point: SitePoint) => `${point.lat.toFixed(4)}, ${point.lon.toFixed(4)}`;

/** A coordinate typed into one of the two fields, or null when the text is not
 * a number in [-limit, limit]. */
function coordinate(text: string, limit: number): number | null {
  const value = Number(text.trim());
  return text.trim() !== "" && Number.isFinite(value) && Math.abs(value) <= limit ? value : null;
}

/** The geography text of a site, with suggestions from the offline place table
 * (GeoNames postal codes). A chosen suggestion writes the text and the site's
 * point on the site map. */
export function PlaceField({ label, value, onChange, point, onPoint }: {
  label: string; value: string; onChange: (text: string) => void;
  point: SitePoint | null; onPoint: (point: SitePoint | null) => void;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [latText, setLatText] = useState(point ? String(point.lat) : "");
  const [lonText, setLonText] = useState(point ? String(point.lon) : "");
  // A point set from outside the fields (a chosen place, a cleared position)
  // replaces their text. A point the fields set themselves leaves it as typed.
  const [seen, setSeen] = useState(point);
  if (seen?.lat !== point?.lat || seen?.lon !== point?.lon) {
    setSeen(point);
    if (coordinate(latText, 90) !== (point?.lat ?? null)) setLatText(point ? String(point.lat) : "");
    if (coordinate(lonText, 180) !== (point?.lon ?? null)) setLonText(point ? String(point.lon) : "");
  }
  const typed = (nextLat: string, nextLon: string) => {
    setLatText(nextLat);
    setLonText(nextLon);
    if (!nextLat.trim() && !nextLon.trim()) { if (point) onPoint(null); return; }
    const lat = coordinate(nextLat, 90);
    const lon = coordinate(nextLon, 180);
    if (lat !== null && lon !== null && (lat !== point?.lat || lon !== point?.lon)) onPoint({ lat, lon });
  };
  const latInvalid = latText.trim() !== "" && coordinate(latText, 90) === null;
  const lonInvalid = lonText.trim() !== "" && coordinate(lonText, 180) === null;
  const q = useDebounced(value.trim());
  const results = useQuery({
    queryKey: ["geo-places", q],
    queryFn: () => searchGeoPlaces(q),
    enabled: open && q.length >= 2,
    placeholderData: keepPreviousData,
    staleTime: Infinity,
  });
  const options = open && q.length >= 2 ? results.data?.items ?? [] : [];
  const choose = (place: GeoPlace) => {
    onChange(placeLabel(place));
    onPoint({ lat: place.lat, lon: place.lon });
    setOpen(false);
  };
  const listId = `${id}-list`;
  const showList = open && q.length >= 2 && (results.data !== undefined || results.isFetching || results.isError);
  return (
    <div className="inv-place">
      <div className="inv-field inv-picker">
        <label htmlFor={id}><span className="inv-field-label">{label}</span></label>
        <input id={id} role="combobox" aria-expanded={showList} aria-controls={listId} aria-autocomplete="list"
          aria-activedescendant={showList && options[active] ? `${id}-opt-${active}` : undefined}
          autoComplete="off" value={value} placeholder="City, postal code or address"
          onBlur={() => setOpen(false)}
          onChange={e => { onChange(e.target.value); setOpen(true); setActive(0); }}
          onKeyDown={e => {
            if (e.key === "ArrowDown") { e.preventDefault(); setOpen(true); setActive(Math.min(active + 1, Math.max(options.length - 1, 0))); }
            else if (e.key === "ArrowUp") { e.preventDefault(); setActive(Math.max(active - 1, 0)); }
            else if (e.key === "Enter" && showList && options[active]) { e.preventDefault(); choose(options[active]); }
            else if (e.key === "Escape" && open) { e.stopPropagation(); setOpen(false); }
          }} />
        {showList && (
          <ul id={listId} role="listbox" className="inv-picker-list" aria-label={`${label} suggestions`}>
            {options.map((place, index) => (
              // The input keeps focus; mouse-down chooses before the input's blur closes the list.
              <li key={`${place.country_code}:${place.postal_code ?? ""}:${place.name}:${place.admin1}:${place.admin2}`}
                id={`${id}-opt-${index}`} role="option" aria-selected={index === active}
                className={index === active ? "active" : undefined}
                onMouseDown={e => { e.preventDefault(); choose(place); }}>
                {placeLabel(place)}
              </li>
            ))}
            {results.isError && <li className="inv-picker-note" role="option" aria-selected="false" aria-disabled="true">Places not loaded</li>}
            {results.data && !results.data.available && <li className="inv-picker-note" role="option" aria-selected="false" aria-disabled="true">No place data</li>}
            {results.data?.available && options.length === 0 && <li className="inv-picker-note" role="option" aria-selected="false" aria-disabled="true">No matching places</li>}
            {results.data?.available && <li className="inv-picker-note" role="option" aria-selected="false" aria-disabled="true">Place data: GeoNames, CC BY 4.0</li>}
          </ul>
        )}
      </div>
      <div className="inv-place-coords">
        <label className="inv-field"><span className="inv-field-label">Latitude</span>
          <input inputMode="decimal" autoComplete="off" placeholder="-90 to 90" value={latText} aria-invalid={latInvalid}
            onChange={e => typed(e.target.value, lonText)} />
        </label>
        <label className="inv-field"><span className="inv-field-label">Longitude</span>
          <input inputMode="decimal" autoComplete="off" placeholder="-180 to 180" value={lonText} aria-invalid={lonInvalid}
            onChange={e => typed(latText, e.target.value)} />
        </label>
      </div>
      <div className="inv-place-point hint">
        {point
          ? <>Map position {formatPoint(point)} <button type="button" className="secondary" onClick={() => onPoint(null)}>Clear map position</button></>
          : "No map position"}
      </div>
    </div>
  );
}
