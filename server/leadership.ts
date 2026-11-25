import type pg from 'pg';
import { acquireSessionClassLock, put, safeAdvisoryUnlock } from './db.ts';

/** Advisory-lock class for worker leadership (see LOCK_CLASS_RANK in db.ts). */
const LEADERSHIP_LOCK_CLASS = 784921;
/**
 * The leadership session key. Deliberately `hashtext(current_schema())`, which is
 * what earlier releases used: during a rolling upgrade the key must keep matching
 * an older replica's sessions, or two leaders would be elected for one schema.
 */
const LEADERSHIP_LOCK_KEY = 'hashtext(current_schema())';

/** A session lock is retained on a dedicated client until step-down. */
export class WorkerLeadership {
  private client?: pg.PoolClient;
  private checking?: Promise<void>;
  private timer?: ReturnType<typeof setInterval>;
  private stopped = false;
  private acquiredAt = '';
  constructor(private pool: pg.Pool, private id: string, private onLost: () => void = () => {}) {}
  get isLeader() { return Boolean(this.client) && !this.stopped; }

  private lost = () => {
    const client = this.client;
    this.client = undefined;
    clearInterval(this.timer);
    if (client) {
      client.removeListener('error', this.lost);
      client.removeListener('end', this.lost);
      client.release(true);
      this.onLost();
    }
  };

  check(): Promise<void> {
    if (this.stopped || this.client) return Promise.resolve();
    return this.checking ??= this.acquire().finally(() => { this.checking = undefined; });
  }

  private async acquire() {
    const client = await this.pool.connect();
    let retained = false;
    try {
      // Acquired through the documented class-order guard rather than inline SQL,
      // so this session cannot take the leadership class out of order.
      const locked = await acquireSessionClassLock(client, LEADERSHIP_LOCK_CLASS, LEADERSHIP_LOCK_KEY);
      if (!locked || this.stopped) return;
      // Re-check stopped after acquiring the lock: close() may have run in
      // the meantime and released this client. Never attach a released client
      // as the leader's session.
      if (this.stopped) return;
      this.client = client;
      retained = true;
      this.acquiredAt = new Date().toISOString();
      client.on('error', this.lost);
      client.on('end', this.lost);
      await this.heartbeat();
      if (!this.client) return;
      this.timer = setInterval(() => void this.heartbeat().catch(this.lost), 10_000);
      this.timer.unref();
    } catch (error) {
      if (retained) this.lost();
      throw error;
    } finally {
      // Destroy losing clients too: a concurrent shutdown can occur just after
      // the lock was acquired, and no lock may leak back into the shared pool.
      if (!retained) client.release(true);
    }
  }

  private async heartbeat() {
    const client = this.client;
    if (!client) return;
    await put(client, 'systemState', 'leader-election', {
      leaderId: this.id, acquiredAt: this.acquiredAt,
      heartbeatAt: new Date().toISOString(), ttlMs: 30_000,
    });
  }

  async close() {
    this.stopped = true;
    clearInterval(this.timer);
    await this.checking;
    const client = this.client;
    this.client = undefined;
    if (!client) return;
    client.removeListener('error', this.lost);
    client.removeListener('end', this.lost);
    try {
      // Inspect the release result: the same shared helper unlocks every other
      // session class and reports a lock this session did not actually hold.
      if (!(await safeAdvisoryUnlock(client, LEADERSHIP_LOCK_CLASS, LEADERSHIP_LOCK_KEY, 'worker-leadership')))
        console.error(JSON.stringify({ level: 'error', event: 'leadership.unlock_not_held', lockId: this.id }));
    } finally { client.release(true); }
  }
}
