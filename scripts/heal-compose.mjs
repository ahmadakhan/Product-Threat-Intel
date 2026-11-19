#!/usr/bin/env node
/**
 * Host-side reconciler for the Compose deployment.
 *
 * Docker restart policies repair exited containers, but they deliberately do
 * not act on a container that is still running while its healthcheck reports
 * `unhealthy`. This script closes that gap: it starts a stopped long-running
 * service and restarts one whose healthcheck has failed for consecutive runs.
 * It never touches the one-shot `migrate` job.
 *
 * Run it from a systemd timer on the Docker host (see
 * deploy/vulnstream-compose-heal.service and .timer). It uses only the Docker
 * CLI and the labels Compose already writes onto each container, so it does
 * not need the Compose environment file or any deployment secret.
 *
 * Environment:
 *   HEAL_PROJECT                 Compose project name (default: vulnstream-enterprise)
 *   HEAL_SERVICES                comma-separated long-running services (default: db,app,proxy)
 *   HEAL_STATE_FILE              persisted failure counters (default: /var/lib/vulnstream-compose-heal/state.json)
 *   HEAL_UNHEALTHY_THRESHOLD     consecutive unhealthy observations before restart (default: 2)
 *   HEAL_RESTART_COOLDOWN_MS     minimum delay between restarts of one service (default: 300000)
 *   DOCKER_BIN                   Docker CLI path (default: docker)
 */

import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { pathToFileURL } from 'node:url';

const DEFAULT_SERVICES = ['db', 'app', 'proxy'];
/** Start dependencies before dependants when more than one is stopped. */
const SERVICE_ORDER = ['db', 'app', 'proxy'];

const log = (level, event, extra = {}) =>
  console.log(JSON.stringify({ level, event, timestamp: new Date().toISOString(), ...extra }));

/** Parse a positive integer, returning null when set but invalid. */
export function parsePositiveInt(raw, fallback) {
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : null;
}

/**
 * Decide what one container needs.
 *
 * `previous` is the persisted entry for the service, `container` is the
 * observed state, and the result is the action plus the entry to persist.
 * A restart requires `unhealthyThreshold` consecutive unhealthy observations
 * and a cooldown after the previous restart, so a container that is still
 * starting does not get restarted in a loop.
 */
export function decideAction(previous, container, now, options) {
  const prior = previous && typeof previous === 'object' ? previous : {};
  const threshold = options.unhealthyThreshold;
  const cooldownMs = options.restartCooldownMs;

  // Docker is already repairing a crash loop; do not interrupt the backoff.
  if (container.restarting) {
    return { action: 'none', state: { ...prior, unhealthyCount: 0 } };
  }
  if (!container.running) {
    return { action: 'start', state: { ...prior, unhealthyCount: 0 } };
  }
  if (container.health !== 'unhealthy') {
    return { action: 'none', state: { ...prior, unhealthyCount: 0 } };
  }

  const unhealthyCount = (Number(prior.unhealthyCount) || 0) + 1;
  const lastRestartAt = Number.isFinite(prior.lastRestartAt) ? prior.lastRestartAt : 0;
  if (unhealthyCount >= threshold && now - lastRestartAt >= cooldownMs) {
    return {
      action: 'restart',
      state: { unhealthyCount: 0, lastRestartAt: now },
    };
  }
  return {
    action: 'none',
    state: { ...prior, unhealthyCount, lastRestartAt },
  };
}

export function readState(file) {
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeState(file, state) {
  try {
    mkdirSync(dirname(file), { recursive: true });
    const temporary = `${file}.tmp`;
    writeFileSync(temporary, JSON.stringify(state), { mode: 0o600 });
    renameSync(temporary, file);
  } catch (error) {
    log('warning', 'heal.state_write_failed', { code: error?.code || 'UNKNOWN' });
  }
}

function docker(args) {
  return execFileSync(process.env.DOCKER_BIN || 'docker', args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30_000,
  });
}

function inspectProject(project) {
  const ids = docker(['ps', '-aq', '--filter', `label=com.docker.compose.project=${project}`])
    .split('\n')
    .map((id) => id.trim())
    .filter(Boolean);
  if (!ids.length) return [];
  return JSON.parse(docker(['inspect', ...ids]));
}

function serviceName(container) {
  return container?.Config?.Labels?.['com.docker.compose.service'] || '';
}

function containerName(container) {
  return String(container?.Name || container?.Id || 'unknown').replace(/^\//, '');
}

async function main() {
  const project = process.env.HEAL_PROJECT || 'vulnstream-enterprise';
  const stateFile = process.env.HEAL_STATE_FILE || '/var/lib/vulnstream-compose-heal/state.json';
  const configuredServices = (process.env.HEAL_SERVICES || DEFAULT_SERVICES.join(','))
    .split(',')
    .map((service) => service.trim())
    .filter(Boolean);
  const services = new Set(configuredServices);
  const unhealthyThreshold = parsePositiveInt(process.env.HEAL_UNHEALTHY_THRESHOLD, 2);
  const restartCooldownMs = parsePositiveInt(process.env.HEAL_RESTART_COOLDOWN_MS, 300_000);

  const misconfigured = [];
  if (unhealthyThreshold === null) misconfigured.push('HEAL_UNHEALTHY_THRESHOLD must be a positive integer');
  if (restartCooldownMs === null) misconfigured.push('HEAL_RESTART_COOLDOWN_MS must be a positive integer');
  if (misconfigured.length) {
    log('error', 'heal.misconfigured', { reason: misconfigured.join('; ') });
    process.exitCode = 2;
    return;
  }

  let containers;
  try {
    containers = inspectProject(project);
  } catch (error) {
    log('error', 'heal.docker_unavailable', {
      project,
      message: String(error?.stderr || error?.message || error).slice(0, 300),
    });
    process.exitCode = 1;
    return;
  }

  if (!containers.length) {
    log('info', 'heal.no_containers', { project });
    return;
  }

  const now = Date.now();
  const state = readState(stateFile);
  const ordered = containers
    .filter((container) => services.has(serviceName(container)))
    .sort(
      (left, right) =>
        SERVICE_ORDER.indexOf(serviceName(left)) - SERVICE_ORDER.indexOf(serviceName(right)),
    );

  let failed = false;
  for (const container of ordered) {
    const service = serviceName(container);
    const current = {
      running: Boolean(container?.State?.Running),
      restarting: container?.State?.Status === 'restarting',
      health: container?.State?.Health?.Status || 'none',
    };
    const decision = decideAction(state[service], current, now, {
      unhealthyThreshold,
      restartCooldownMs,
    });
    state[service] = decision.state;
    if (decision.action === 'none') continue;

    const name = containerName(container);
    try {
      if (decision.action === 'start') docker(['start', container.Id]);
      else docker(['restart', '--time', '35', container.Id]);
      log('warning', `heal.${decision.action}`, {
        project,
        service,
        name,
        health: current.health,
      });
    } catch (error) {
      failed = true;
      log('error', 'heal.action_failed', {
        project,
        service,
        name,
        action: decision.action,
        message: String(error?.stderr || error?.message || error).slice(0, 300),
      });
    }
  }

  writeState(stateFile, state);
  if (failed) process.exitCode = 1;
}

function isMain() {
  return Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMain()) await main();
