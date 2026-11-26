import { apiDownload } from "../api/client";

/** Downloads the YAML export of an application, of the latest revision without `revision`. */
export async function downloadApplication(id: string, revision?: number): Promise<void> {
  const download = await apiDownload(
    `/business-applications/${encodeURIComponent(id)}/export${revision ? `?revision=${revision}` : ""}`,
  );
  const url = URL.createObjectURL(download.blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = download.filename;
  link.click();
  URL.revokeObjectURL(url);
}
