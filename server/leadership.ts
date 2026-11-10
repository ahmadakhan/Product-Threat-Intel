import type pg from 'pg';
import { put } from './db.ts';

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
      const result = await client.query(
        'SELECT pg_try_advisory_lock(784921, hashtext(current_schema())) AS locked',
      );
      if (!result.rows[0]?.locked || this.stopped) return;
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
      await client.query('SELECT pg_advisory_unlock(784921, hashtext(current_schema()))');
    } finally { client.release(true); }
  }
}
