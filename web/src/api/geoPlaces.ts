import { api } from "./client";

/** One place of the offline address lookup. Without `postal_code` it stands
 *  for every postal code of the place, at the mean of their centroids. */
export interface GeoPlace {
  country_code: string;
  postal_code: string | null;
  name: string;
  admin1: string;
  admin2: string;
  lat: number;
  lon: number;
}

export interface GeoPlaceSearch {
  items: GeoPlace[];
  /** False while no place file is loaded. */
  available: boolean;
}

export const searchGeoPlaces = (q: string, limit = 10) =>
  api<GeoPlaceSearch>(`/geo-places?${new URLSearchParams({ q, limit: String(limit) })}`);
