/** Read-only deployment checks by default; --exercise restarts the single app instance. */
import { execFileSync } from 'node:child_process';
import { request } from 'node:https';
import { rootCertificates } from 'node:tls';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { writeFile } from 'node:fs/promises';
const appName = 'vulnstream-enterprise-app-1';
const proxy = 'vulnstream-enterprise-proxy-1';
const exercise = process.argv.includes('--exercise');
if (!process.env.APP_ORIGIN) throw new Error('APP_ORIGIN required');
const origin = new URL(process.env.APP_ORIGIN);
if (origin.protocol !== 'https:') throw new Error('HTTPS origin required');
const docker = (args: string[]) =>
  execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000 });
let additionalCa = '';
try {
  additionalCa = docker(['exec', proxy, 'cat', '/data/caddy/pki/authorities/local/root.crt']);
} catch {
  /* Public certificates use system roots. */
}
async function probe(): Promise<number> {
  const started = performance.now();
  return new Promise((resolve, reject) => {
    const req = request(
      {
        hostname: origin.hostname,
        port: Number(origin.port || 443),
        path: '/ready',
        method: 'GET',
        family: 4,
        lookup: (_name, _options, callback) => callback(null, '127.0.0.1', 4),
        ca: additionalCa ? [...rootCertificates, additionalCa] : undefined,
        headers: { Host: origin.host },
        agent: false,
      },
      (res) => {
        res.resume();
        res.once('end', () =>
          res.statusCode === 200
            ? resolve(performance.now() - started)
            : reject(new Error('PROXY_READINESS_FAILED')),
        );
      },
    );
    req.setTimeout(10000, () => req.destroy(new Error('PROXY_TIMEOUT')));
    req.once('error', reject);
    req.end();
  });
}
function appHealthy(): boolean {
  let data: {
    State: { Health?: { Status: string } };
    Config: { Labels: Record<string, string> };
  };
  try {
    data = JSON.parse(docker(['inspect', appName]))[0];
  } catch {
    return false;
  }
  if (
    data.Config.Labels['com.docker.compose.project'] !== 'vulnstream-enterprise' ||
    data.Config.Labels['com.docker.compose.service'] !== 'app'
  )
    throw new Error('UNEXPECTED_CONTAINER_OWNERSHIP');
  return data.State.Health?.Status === 'healthy';
}
async function waitForApp(attempts: number): Promise<boolean> {
  for (let i = 0; i < attempts; i++) {
    if (appHealthy()) return true;
    await delay(500);
  }
  return false;
}
const latencies: number[] = [];
let restarted = false;
try {
  if (!appHealthy()) throw new Error('APP_MUST_BE_HEALTHY');
  // Warm the proxy before the restart so the first probe is not confused with
  // a cold upstream connection.
  latencies.push(await probe());
  if (exercise) {
    docker(['stop', '--time', '20', appName]);
    docker(['start', appName]);
    restarted = await waitForApp(240);
    if (!restarted) throw new Error('APP_DID_NOT_RECOVER');
  }
  for (let i = 0; i < 10; i++) latencies.push(await probe());
} finally {
  // A failed exercise must leave the service running, not stopped.
  if (exercise && !restarted) {
    try {
      docker(['start', appName]);
    } catch {
      /* the operator still has the failing status in the thrown error */
    }
  }
}
const report = {
  proxyRequests: latencies.length,
  proxyFailures: 0,
  maxProxyLatencyMs: Math.max(...latencies),
  singleAppRestartExercised: exercise,
  appRestored: exercise ? restarted : null,
};
console.log(JSON.stringify(report, null, 2));
if (process.env.CORRELATION_DEPLOYMENT_REPORT)
  await writeFile(process.env.CORRELATION_DEPLOYMENT_REPORT, JSON.stringify(report, null, 2) + '\n');
