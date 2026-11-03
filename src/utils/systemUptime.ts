interface SystemUptime {
  upSince: string;
  uptime: string;
  loadAverage: number[];
}

export const getSystemUptime = async (): Promise<SystemUptime> => {
  try {
    const response = await fetch('/api/system-uptime', {
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
    });
    const data = await response.json().catch(() => ({ systemUptime: 'unknown' }));
    const uptime = (response.ok && data?.systemUptime) || 'unknown';

    return {
      upSince: uptime,
      uptime,
      loadAverage: [0, 0, 0]
    };
  } catch (error) {
    return {
      upSince: 'unknown',
      uptime: 'unknown',
      loadAverage: [0, 0, 0]
    };
  }
};