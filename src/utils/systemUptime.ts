interface SystemUptime {
  upSince: string;
  uptime: string;
  loadAverage: number[];
}

export const getSystemUptime = async (): Promise<SystemUptime> => {
  const response = await fetch('/api/system-uptime', {
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json' },
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error(`Uptime request failed (HTTP ${response.status})`);
  const data: unknown = await response.json();
  if (!data || typeof data !== 'object' ||
    !('systemUptime' in data) || typeof data.systemUptime !== 'string' || !data.systemUptime ||
    !('startedAt' in data) || typeof data.startedAt !== 'string' || !Number.isFinite(Date.parse(data.startedAt)))
    throw new Error('Invalid application uptime response');
  return {
    upSince: data.startedAt,
    uptime: data.systemUptime,
    loadAverage: [0, 0, 0],
  };
};