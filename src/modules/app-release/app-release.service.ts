import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { lt, valid } from 'semver';
import { randomUUID } from 'node:crypto';
import { AppReleaseRepository } from './app-release.repository';
import type {
  AppRelease,
  AuditEvent,
  ReleaseStatus,
} from './app-release.types';

const transitions: Record<ReleaseStatus, ReleaseStatus[]> = {
  draft: ['uploaded', 'rejected'],
  uploaded: ['verified', 'rejected'],
  verified: ['staged', 'rejected'],
  staged: ['active', 'rejected'],
  active: ['paused', 'completed', 'rolled_back'],
  paused: ['active', 'rolled_back'],
  completed: [],
  rejected: [],
  rolled_back: [],
};

@Injectable()
export class AppReleaseService {
  constructor(private readonly repository: AppReleaseRepository) {}

  list(filters: { platform?: string; status?: string }): AppRelease[] {
    return this.repository.list(filters);
  }

  get(id: string): AppRelease {
    const release = this.repository.findById(id);
    if (!release) throw new NotFoundException('Release not found');
    return release;
  }

  async create(
    input: {
      applicationId: string;
      platform: 'android' | 'ios';
      version: string;
      buildNumber: number;
      runtimeVersion: string;
      channel: AppRelease['channel'];
      releaseNotes: string[];
      artifact?: AppRelease['artifact'];
      rollout?: Partial<AppRelease['rollout']>;
    },
    actorId = 'unknown',
    requestId = 'admin-request',
  ): Promise<AppRelease> {
    if (!valid(input.version))
      throw new BadRequestException('version must be valid semver');
    if (input.buildNumber < 1)
      throw new BadRequestException('buildNumber must be positive');
    const duplicate = this.repository
      .list({ platform: input.platform })
      .some(
        (item) =>
          item.buildNumber === input.buildNumber &&
          item.channel === input.channel,
      );
    if (duplicate)
      throw new ConflictException(
        'A release with this build and channel already exists',
      );
    const now = new Date().toISOString();
    const release: AppRelease = {
      id: `rel_${randomUUID().replaceAll('-', '')}`,
      applicationId: input.applicationId,
      platform: input.platform,
      version: input.version,
      buildNumber: input.buildNumber,
      runtimeVersion: input.runtimeVersion,
      channel: input.channel,
      status: input.artifact ? 'uploaded' : 'draft',
      releaseNotes: input.releaseNotes,
      artifact: input.artifact ?? null,
      rollout: {
        percentage: input.rollout?.percentage ?? 0,
        audience: input.rollout?.audience ?? 'all',
        startsAt: input.rollout?.startsAt ?? null,
        stopRule: input.rollout?.stopRule ?? null,
      },
      createdAt: now,
      updatedAt: now,
      activatedAt: null,
      lastAction: 'create',
    };
    return this.repository.insert(release, {
      id: `audit_${randomUUID()}`,
      actorId,
      action: 'create',
      targetType: 'release',
      targetId: release.id,
      reason: 'Created release',
      requestId,
      createdAt: now,
      summary: {
        version: release.version,
        platform: release.platform,
        status: release.status,
      },
    });
  }

  async transition(
    id: string,
    target: ReleaseStatus,
    actorId: string,
    reason: string,
    requestId: string,
    operation: string = target,
  ): Promise<AppRelease> {
    const release = structuredClone(this.get(id));
    if (!reason.trim()) throw new BadRequestException('reason is required');
    if (!transitions[release.status].includes(target))
      throw new ConflictException(
        `Cannot transition ${release.status} to ${target}`,
      );
    if (
      (target === 'active' || target === 'rolled_back') &&
      release.rollout.percentage === 0
    )
      throw new BadRequestException(
        'Configure a rollout percentage before activation',
      );
    const now = new Date().toISOString();
    let previous: AppRelease | undefined;
    const events: AuditEvent[] = [];
    if (target === 'active') {
      const currentPrevious = this.repository
        .list({ platform: release.platform })
        .find(
          (item) =>
            item.id !== release.id &&
            item.channel === release.channel &&
            item.status === 'active',
        );
      if (currentPrevious) {
        previous = structuredClone(currentPrevious);
        previous.status = 'completed';
        previous.updatedAt = now;
        previous.lastAction = 'completed';
        events.push({
          id: `audit_${randomUUID()}`,
          actorId,
          action: 'complete_previous',
          targetType: 'release',
          targetId: previous.id,
          reason: `Superseded by ${release.id}`,
          requestId,
          createdAt: now,
          summary: {
            version: previous.version,
            platform: previous.platform,
            status: 'completed',
          },
        });
      }
    }
    release.status = target;
    release.updatedAt = now;
    release.lastAction = target;
    release.activatedAt = target === 'active' ? now : release.activatedAt;
    events.push({
      id: `audit_${randomUUID()}`,
      actorId,
      action: operation,
      targetType: 'release',
      targetId: id,
      reason,
      requestId,
      createdAt: now,
      summary: {
        version: release.version,
        platform: release.platform,
        status: target,
      },
    });
    await this.repository.applyTransition({ release, previous, events });
    return release;
  }

  overview(): {
    current: Record<string, AppRelease | null>;
    counts: Record<ReleaseStatus, number>;
    rollout: number;
  } {
    const releases = this.repository.list({});
    const current = {
      android:
        releases.find(
          (release) =>
            release.platform === 'android' &&
            release.channel !== 'ota' &&
            release.status === 'active',
        ) ?? null,
      ios:
        releases.find(
          (release) =>
            release.platform === 'ios' &&
            release.channel !== 'ota' &&
            release.status === 'active',
        ) ?? null,
    };
    const counts = releases.reduce<Record<ReleaseStatus, number>>(
      (result, release) => {
        result[release.status] += 1;
        return result;
      },
      {
        draft: 0,
        uploaded: 0,
        verified: 0,
        staged: 0,
        active: 0,
        paused: 0,
        completed: 0,
        rejected: 0,
        rolled_back: 0,
      },
    );
    const active = releases.filter((release) => release.status === 'active');
    return {
      current,
      counts,
      rollout: active.length
        ? Math.round(
            active.reduce(
              (sum, release) => sum + release.rollout.percentage,
              0,
            ) / active.length,
          )
        : 0,
    };
  }

  audits() {
    return this.repository.listAudits();
  }

  async recordAudit(event: {
    actorId: string;
    action: string;
    targetType: string;
    targetId: string;
    reason: string;
    requestId: string;
    summary: Record<string, string | number | null>;
  }): Promise<void> {
    await this.repository.addAudit({
      id: `audit_${randomUUID()}`,
      createdAt: new Date().toISOString(),
      ...event,
    });
  }

  current(
    platform: 'android' | 'ios',
    channel: string,
  ): AppRelease | undefined {
    return this.repository.findActive(platform, channel);
  }

  isVersionBelow(version: string, minimum: string): boolean {
    return Boolean(valid(version) && valid(minimum) && lt(version, minimum));
  }
}
