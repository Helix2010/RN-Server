import { Injectable, OnModuleInit } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { ExecuteValues } from 'mysql2';
import type { PoolConnection, RowDataPacket } from 'mysql2/promise';
import { MysqlService } from '../../platform/database/mysql.service';
import type { AuditEvent } from '../app-release/app-release.types';

type AuditRow = RowDataPacket & {
  id: string;
  actor_id: string;
  action: string;
  target_type: string;
  target_id: string;
  reason: string;
  request_id: string;
  summary: string | AuditEvent['summary'];
  created_at: Date;
};

export type NewAuditEvent = Omit<AuditEvent, 'id' | 'createdAt'>;

@Injectable()
export class AuditService implements OnModuleInit {
  private events: AuditEvent[] = [];

  constructor(private readonly database: MysqlService) {}

  async onModuleInit(): Promise<void> {
    const rows = await this.database.query<AuditRow[]>(
      'SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 1000',
    );
    this.events = rows.map((row) => this.map(row));
  }

  create(input: NewAuditEvent, createdAt = new Date()): AuditEvent {
    return {
      id: `audit_${randomUUID()}`,
      createdAt: createdAt.toISOString(),
      ...input,
    };
  }

  async record(event: AuditEvent): Promise<void> {
    await this.database.execute(
      `INSERT INTO audit_events
       (id, actor_id, action, target_type, target_id, reason, request_id, summary, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      this.parameters(event),
    );
    this.commit(event);
  }

  async recordInTransaction(
    connection: PoolConnection,
    event: AuditEvent,
  ): Promise<void> {
    await connection.execute(
      `INSERT INTO audit_events
       (id, actor_id, action, target_type, target_id, reason, request_id, summary, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      this.parameters(event),
    );
  }

  commit(...events: AuditEvent[]): void {
    this.events.unshift(...[...events].reverse());
    if (this.events.length > 1000) this.events.length = 1000;
  }

  list(): AuditEvent[] {
    return structuredClone(this.events);
  }

  private parameters(event: AuditEvent): ExecuteValues[] {
    return [
      event.id,
      event.actorId,
      event.action,
      event.targetType,
      event.targetId,
      event.reason,
      event.requestId,
      JSON.stringify(event.summary),
      new Date(event.createdAt),
    ];
  }

  private map(row: AuditRow): AuditEvent {
    return {
      id: row.id,
      actorId: row.actor_id,
      action: row.action,
      targetType: row.target_type,
      targetId: row.target_id,
      reason: row.reason,
      requestId: row.request_id,
      createdAt: this.iso(row.created_at),
      summary: this.json<AuditEvent['summary']>(row.summary),
    };
  }

  private json<T>(value: string | T): T {
    return typeof value === 'string' ? (JSON.parse(value) as T) : value;
  }

  private iso(value: Date | string): string {
    return (value instanceof Date ? value : new Date(value)).toISOString();
  }
}
