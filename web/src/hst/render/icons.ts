/**
 * Line icons for the area cards, drawn for HST: the inner markup of a 24 by 24 SVG in `currentColor`, keyed by
 * block kind, with `site` for a site card and `region` for a country block card.
 */
const S = 'fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"';

export const AREA_ICONS: Readonly<Record<string, string>> = {
  region: `<path ${S} d="M12 21s-6.5-5.6-6.5-11a6.5 6.5 0 0 1 13 0c0 5.4-6.5 11-6.5 11z"/><circle ${S} cx="12" cy="10" r="2.3"/>`,
  site: `<path ${S} d="M4 20V9l8-5 8 5v11M9 20v-6h6v6"/>`,
  campus: `<path ${S} d="M3 20h18M5 20V8h6v12M13 20V4h6v16M7.5 11h1M7.5 14h1M15.5 7h1M15.5 10h1M15.5 13h1"/>`,
  dc: `<path ${S} d="M5 4h14v5H5zM5 9h14v5H5zM5 14h14v6H5zM8 6.5h.5M8 11.5h.5M8 17h.5"/>`,
  firewall: `<path ${S} d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"/>`,
  "internet-edge": `<circle ${S} cx="12" cy="12" r="8.5"/><path ${S} d="M3.5 12h17M12 3.5c2.5 2.5 3.5 5.5 3.5 8.5s-1 6-3.5 8.5c-2.5-2.5-3.5-5.5-3.5-8.5s1-6 3.5-8.5z"/>`,
  "wan-edge": `<circle ${S} cx="6" cy="17" r="2.5"/><circle ${S} cx="18" cy="17" r="2.5"/><circle ${S} cx="12" cy="6" r="2.5"/><path ${S} d="M8 15.5l3-7.5M16 15.5l-3-7.5M8.5 17h7"/>`,
  other: `<rect ${S} x="4" y="4" width="16" height="16" rx="3"/><path ${S} d="M8 12h8"/>`,
  role: `<rect ${S} x="4" y="4" width="16" height="16" rx="3"/><path ${S} d="M8 12h8"/>`,
};

/** The icon markup of an area kind; an unknown kind takes the icon of `other`. */
export function areaIcon(kind: string | undefined): string {
  return kind !== undefined && Object.hasOwn(AREA_ICONS, kind) ? AREA_ICONS[kind] : AREA_ICONS.other;
}
