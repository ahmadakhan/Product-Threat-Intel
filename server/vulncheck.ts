/** Adapt both the v3 index envelope and the documented NVD-compatible API. */
export function vulncheckNvdItems(page: any): any[] {
  const records = Array.isArray(page?.data) ? page.data : page?.vulnerabilities;
  if (!Array.isArray(records)) throw new Error('Invalid VulnCheck NVD++ response');
  return records.map((record: any) => record?.cve ? record : { cve: record });
}

export function bearerHeaders(token?: string): Record<string, string> {
  return { Accept: 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) };
}
