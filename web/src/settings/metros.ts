/**
 * Each Equinix metro code maps to a city centre point.
 */

export interface Metro {
  name: string;
  lat: number;
  lon: number;
}

export const METROS: Readonly<Record<string, Metro>> = {
  AB: { name: "Abu Dhabi", lat: 24.45, lon: 54.65 },
  AM: { name: "Amsterdam", lat: 52.37, lon: 4.9 },
  AT: { name: "Atlanta", lat: 33.75, lon: -84.39 },
  BA: { name: "Barcelona", lat: 41.39, lon: 2.17 },
  BG: { name: "Bogota", lat: 4.71, lon: -74.07 },
  BL: { name: "Bordeaux", lat: 44.84, lon: -0.58 },
  BX: { name: "Brussels", lat: 50.85, lon: 4.35 },
  CA: { name: "Canberra", lat: -35.28, lon: 149.13 },
  CH: { name: "Chicago", lat: 41.88, lon: -87.63 },
  CL: { name: "Calgary", lat: 51.05, lon: -114.07 },
  CN: { name: "Chennai", lat: 13.08, lon: 80.27 },
  CU: { name: "Culpeper", lat: 38.47, lon: -78.0 },
  DA: { name: "Dallas", lat: 32.78, lon: -96.8 },
  DB: { name: "Dublin", lat: 53.35, lon: -6.26 },
  DC: { name: "Washington DC", lat: 39.04, lon: -77.49 },
  DE: { name: "Denver", lat: 39.74, lon: -104.99 },
  DU: { name: "Dubai", lat: 25.2, lon: 55.27 },
  DX: { name: "Dusseldorf", lat: 51.23, lon: 6.78 },
  FR: { name: "Frankfurt", lat: 50.11, lon: 8.68 },
  GV: { name: "Geneva", lat: 46.2, lon: 6.14 },
  HE: { name: "Helsinki", lat: 60.17, lon: 24.94 },
  HH: { name: "Hamburg", lat: 53.55, lon: 9.99 },
  HK: { name: "Hong Kong", lat: 22.32, lon: 114.17 },
  HY: { name: "Hyderabad", lat: 17.39, lon: 78.49 },
  IL: { name: "Istanbul", lat: 41.01, lon: 28.98 },
  JK: { name: "Jakarta", lat: -6.21, lon: 106.85 },
  JN: { name: "Johannesburg", lat: -26.2, lon: 28.05 },
  KL: { name: "Kuala Lumpur", lat: 3.14, lon: 101.69 },
  LA: { name: "Los Angeles", lat: 34.05, lon: -118.24 },
  LD: { name: "London", lat: 51.51, lon: -0.13 },
  LG: { name: "Lagos", lat: 6.52, lon: 3.38 },
  LS: { name: "Lisbon", lat: 38.72, lon: -9.14 },
  MA: { name: "Manchester", lat: 53.48, lon: -2.24 },
  MB: { name: "Mumbai", lat: 19.08, lon: 72.88 },
  MD: { name: "Madrid", lat: 40.42, lon: -3.7 },
  ME: { name: "Melbourne", lat: -37.81, lon: 144.96 },
  MI: { name: "Miami", lat: 25.76, lon: -80.19 },
  ML: { name: "Milan", lat: 45.46, lon: 9.19 },
  MO: { name: "Montreal", lat: 45.5, lon: -73.57 },
  MS: { name: "Muscat", lat: 23.59, lon: 58.41 },
  MU: { name: "Munich", lat: 48.14, lon: 11.58 },
  MX: { name: "Mexico City", lat: 19.43, lon: -99.13 },
  NY: { name: "New York", lat: 40.71, lon: -74.01 },
  OS: { name: "Osaka", lat: 34.69, lon: 135.5 },
  PA: { name: "Paris", lat: 48.86, lon: 2.35 },
  PE: { name: "Perth", lat: -31.95, lon: 115.86 },
  PH: { name: "Philadelphia", lat: 39.95, lon: -75.17 },
  RJ: { name: "Rio de Janeiro", lat: -22.91, lon: -43.17 },
  SE: { name: "Seattle", lat: 47.61, lon: -122.33 },
  SG: { name: "Singapore", lat: 1.35, lon: 103.82 },
  SK: { name: "Stockholm", lat: 59.33, lon: 18.07 },
  SL: { name: "Seoul", lat: 37.57, lon: 126.98 },
  SO: { name: "Sofia", lat: 42.7, lon: 23.32 },
  SP: { name: "Sao Paulo", lat: -23.55, lon: -46.63 },
  SV: { name: "Silicon Valley", lat: 37.34, lon: -121.89 },
  SY: { name: "Sydney", lat: -33.87, lon: 151.21 },
  TK: { name: "Tokyo", lat: 35.68, lon: 139.69 },
  TR: { name: "Toronto", lat: 43.65, lon: -79.38 },
  WA: { name: "Warsaw", lat: 52.23, lon: 21.01 },
  ZH: { name: "Zurich", lat: 47.38, lon: 8.54 },
};

const IBX = /^([A-Z]{2})\d{1,2}$/i;

/** The metro an IBX-shaped site code names, or null. `fr2` and `FR2` both
 *  match; `hq` and `DEU-FRA-1` do not. */
export function metroOf(code: string): Metro | null {
  const m = IBX.exec(code);
  return m ? (METROS[m[1].toUpperCase()] ?? null) : null;
}
