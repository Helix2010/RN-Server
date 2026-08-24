import { Injectable, OnModuleInit } from '@nestjs/common';
import type { PoolConnection, RowDataPacket } from 'mysql2/promise';
import type { ExecuteValues } from 'mysql2';
import { MysqlService } from '../../platform/database/mysql.service';
import { AuditService } from '../audit/audit.service';
import type {
  AppRelease,
  Artifact,
  AuditEvent,
  Rollout,
} from './app-release.types';

type ReleaseRow = RowDataPacket & {
  id: string;
  application_id: string;
  platform: AppRelease['platform'];
  version: string;
  build_number: number;
  runtime_version: string;
  channel: AppRelease['channel'];
  status: AppRelease['status'];
  release_notes: string | string[];
  artifact: string | Artifact | null;
  rollout: string | Rollout;
  activated_at: Date | null;
  last_action: string | null;
  created_at: Date;
  updated_at: Date;
};

@Injectable()
export class AppReleaseRepository implements OnModuleInit {
  private releases: AppRelease[] = [];

  constructor(
    private readonly database: MysqlService,
    private readonly audit: AuditService,
  ) {}

  async onModuleInit(): Promise<void> {
    await this.reload();
  }

  list(filters: { platform?: string; status?: string }): AppRelease[] {
    return this.releases.filter(
      (release) =>
        (!filters.platform || release.platform === filters.platform) &&
        (!filters.status || release.status === filters.status),
    );
  }

  findById(id: string): AppRelease | undefined {
    return this.releases.find((release) => release.id === id);
  }

  findActive(
    platform: 'android' | 'ios',
    channel: string,
  ): AppRelease | undefined {
    return this.releases.find(
      (release) =>
        release.platform === platform &&
        release.channel === channel &&
        release.status === 'active',
    );
  }

  async insert(release: AppRelease, event: AuditEvent): Promise<AppRelease> {
    await this.database.transaction(async (connection) => {
      await connection.execute(
        `INSERT INTO app_releases
         (id, application_id, platform, version, build_number, runtime_version, channel, status,
          release_notes, artifact, rollout, activated_at, last_action, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        this.releaseParameters(release),
      );
      await this.audit.recordInTransaction(connection, event);
    });
    this.releases.unshift(release);
    this.audit.commit(event);
    return release;
  }

  async applyTransition(input: {
    release: AppRelease;
    previous?: AppRelease;
    events: AuditEvent[];
  }): Promise<void> {
    await this.database.transaction(async (connection) => {
      if (input.previous) await this.updateRelease(connection, input.previous);
      await this.updateRelease(connection, input.release);
      for (const event of input.events)
        await this.audit.recordInTransaction(connection, event);
    });
    this.replaceCached(input.release);
    if (input.previous) this.replaceCached(input.previous);
    this.audit.commit(...input.events);
  }

  async addAudit(event: AuditEvent): Promise<void> {
    await this.audit.record(event);
  }

  listAudits(): AuditEvent[] {
    return this.audit.list();
  }

  private async reload(): Promise<void> {
    const releases = await this.database.query<ReleaseRow[]>(
      'SELECT * FROM app_releases ORDER BY updated_at DESC',
    );
    this.releases = releases.map((row) => this.mapRelease(row));
  }

  private async updateRelease(
    connection: PoolConnection,
    release: AppRelease,
  ): Promise<void> {
    await connection.execute(
      `UPDATE app_releases SET application_id=?, platform=?, version=?, build_number=?, runtime_version=?,
       channel=?, status=?, release_notes=?, artifact=?, rollout=?, activated_at=?, last_action=?, created_at=?, updated_at=?
       WHERE id=?`,
      [...this.releaseParameters(release).slice(1), release.id],
    );
  }

  private replaceCached(release: AppRelease): void {
    const index = this.releases.findIndex((item) => item.id === release.id);
    if (index >= 0) this.releases[index] = release;
  }

  private releaseParameters(release: AppRelease): ExecuteValues[] {
    return [
      release.id,
      release.applicationId,
      release.platform,
      release.version,
      release.buildNumber,
      release.runtimeVersion,
      release.channel,
      release.status,
      JSON.stringify(release.releaseNotes),
      release.artifact ? JSON.stringify(release.artifact) : null,
      JSON.stringify(release.rollout),
      release.activatedAt ? new Date(release.activatedAt) : null,
      release.lastAction,
      new Date(release.createdAt),
      new Date(release.updatedAt),
    ];
  }

  private mapRelease(row: ReleaseRow): AppRelease {
    return {
      id: row.id,
      applicationId: row.application_id,
      platform: row.platform,
      version: row.version,
      buildNumber: row.build_number,
      runtimeVersion: row.runtime_version,
      channel: row.channel,
      status: row.status,
      releaseNotes: this.json<string[]>(row.release_notes),
      artifact:
        row.artifact === null ? null : this.json<Artifact>(row.artifact),
      rollout: this.json<Rollout>(row.rollout),
      createdAt: this.iso(row.created_at),
      updatedAt: this.iso(row.updated_at),
      activatedAt: row.activated_at ? this.iso(row.activated_at) : null,
      lastAction: row.last_action,
    };
  }

  private json<T>(value: string | T): T {
    return typeof value === 'string' ? (JSON.parse(value) as T) : value;
  }
  private iso(value: Date | string): string {
    return (value instanceof Date ? value : new Date(value)).toISOString();
  }
}
