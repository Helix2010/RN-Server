import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import {
  createConnection,
  createPool,
  type Pool,
  type PoolConnection,
  type ResultSetHeader,
  type RowDataPacket,
} from 'mysql2/promise';
import type { ExecuteValues } from 'mysql2';
import { getEnvironment } from '../config/env';

@Injectable()
export class MysqlService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(MysqlService.name);
  private pool?: Pool;

  async onModuleInit(): Promise<void> {
    const environment = getEnvironment();
    const databaseName =
      environment.NODE_ENV === 'test' &&
      !environment.MYSQL_DATABASE.endsWith('_test')
        ? `${environment.MYSQL_DATABASE}_test`
        : environment.MYSQL_DATABASE;
    const bootstrapConnection = await createConnection({
      host: environment.MYSQL_HOST,
      port: environment.MYSQL_PORT,
      user: environment.MYSQL_USER,
      password: environment.MYSQL_PASSWORD,
      charset: environment.MYSQL_CHARSET,
      timezone: environment.MYSQL_TIMEZONE,
      dateStrings: !environment.MYSQL_PARSE_TIME,
    });
    try {
      await bootstrapConnection.query(
        `CREATE DATABASE IF NOT EXISTS \`${databaseName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci`,
      );
    } finally {
      await bootstrapConnection.end();
    }

    this.pool = createPool({
      host: environment.MYSQL_HOST,
      port: environment.MYSQL_PORT,
      user: environment.MYSQL_USER,
      password: environment.MYSQL_PASSWORD,
      database: databaseName,
      connectionLimit: environment.MYSQL_CONNECTION_LIMIT,
      charset: environment.MYSQL_CHARSET,
      timezone: environment.MYSQL_TIMEZONE,
      dateStrings: !environment.MYSQL_PARSE_TIME,
      decimalNumbers: true,
    });
    await this.migrate();
    this.logger.log(
      `MySQL ready host=${environment.MYSQL_HOST}:${environment.MYSQL_PORT} database=${databaseName}`,
    );
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool?.end();
  }

  async query<T extends RowDataPacket[]>(
    sql: string,
    parameters: ExecuteValues[] = [],
  ): Promise<T> {
    const [rows] = await this.getPool().execute<T>(sql, parameters);
    return rows;
  }

  async execute(
    sql: string,
    parameters: ExecuteValues[] = [],
  ): Promise<ResultSetHeader> {
    const [result] = await this.getPool().execute<ResultSetHeader>(
      sql,
      parameters,
    );
    return result;
  }

  async ping(): Promise<void> {
    const connection = await this.getPool().getConnection();
    try {
      await connection.ping();
    } finally {
      connection.release();
    }
  }

  async transaction<T>(
    work: (connection: PoolConnection) => Promise<T>,
  ): Promise<T> {
    const connection = await this.getPool().getConnection();
    try {
      await connection.beginTransaction();
      const result = await work(connection);
      await connection.commit();
      return result;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  private getPool(): Pool {
    if (!this.pool) throw new Error('MySQL pool is not initialized');
    return this.pool;
  }

  private async migrate(): Promise<void> {
    const pool = this.getPool();
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_releases (
        id VARCHAR(80) PRIMARY KEY,
        application_id VARCHAR(120) NOT NULL,
        platform ENUM('android','ios') NOT NULL,
        version VARCHAR(40) NOT NULL,
        build_number INT UNSIGNED NOT NULL,
        runtime_version VARCHAR(120) NOT NULL,
        channel ENUM('store','direct','mdm','ota') NOT NULL,
        status ENUM('draft','uploaded','verified','staged','active','paused','completed','rejected','rolled_back') NOT NULL,
        release_notes JSON NOT NULL,
        artifact JSON NULL,
        rollout JSON NOT NULL,
        activated_at DATETIME(3) NULL,
        last_action VARCHAR(80) NULL,
        created_at DATETIME(3) NOT NULL,
        updated_at DATETIME(3) NOT NULL,
        UNIQUE KEY uq_release_build (application_id, platform, channel, build_number),
        KEY ix_release_active (platform, channel, status),
        KEY ix_release_updated (updated_at)
      ) ENGINE=InnoDB
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_events (
        id VARCHAR(80) PRIMARY KEY,
        actor_id VARCHAR(120) NOT NULL,
        action VARCHAR(100) NOT NULL,
        target_type VARCHAR(80) NOT NULL,
        target_id VARCHAR(120) NOT NULL,
        reason VARCHAR(500) NOT NULL,
        request_id VARCHAR(120) NOT NULL,
        summary JSON NOT NULL,
        created_at DATETIME(3) NOT NULL,
        KEY ix_audit_target (target_type, target_id, created_at),
        KEY ix_audit_created (created_at)
      ) ENGINE=InnoDB
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_configs (
        config_key VARCHAR(100) PRIMARY KEY,
        config_value JSON NOT NULL,
        version INT UNSIGNED NOT NULL DEFAULT 1,
        updated_by VARCHAR(120) NOT NULL,
        updated_at DATETIME(3) NOT NULL
      ) ENGINE=InnoDB
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_sessions (
        token_hash CHAR(64) PRIMARY KEY,
        actor_id VARCHAR(120) NOT NULL,
        expires_at DATETIME(3) NOT NULL,
        created_at DATETIME(3) NOT NULL,
        KEY ix_admin_session_expiry (expires_at)
      ) ENGINE=InnoDB
    `);
  }
}
