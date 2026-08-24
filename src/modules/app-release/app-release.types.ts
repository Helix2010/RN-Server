export type ReleasePlatform = 'android' | 'ios';
export type ReleaseChannel = 'store' | 'direct' | 'mdm' | 'ota';
export type ReleaseStatus =
  | 'draft'
  | 'uploaded'
  | 'verified'
  | 'staged'
  | 'active'
  | 'paused'
  | 'completed'
  | 'rejected'
  | 'rolled_back';

export type Artifact = {
  id: string;
  fileName: string;
  downloadUrl: string | null;
  size: number;
  sha256: string;
  signingFingerprint: string | null;
  minOsVersion: string;
};

export type Rollout = {
  percentage: number;
  audience: string;
  startsAt: string | null;
  stopRule: string | null;
};

export type AppRelease = {
  id: string;
  applicationId: string;
  platform: ReleasePlatform;
  version: string;
  buildNumber: number;
  runtimeVersion: string;
  channel: ReleaseChannel;
  status: ReleaseStatus;
  releaseNotes: string[];
  artifact: Artifact | null;
  rollout: Rollout;
  createdAt: string;
  updatedAt: string;
  activatedAt: string | null;
  lastAction: string | null;
};

export type AuditEvent = {
  id: string;
  actorId: string;
  action: string;
  targetType: string;
  targetId: string;
  reason: string;
  requestId: string;
  createdAt: string;
  summary: Record<string, string | number | null>;
};
