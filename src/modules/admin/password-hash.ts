import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

const KEY_LENGTH = 64;
const DEFAULT_COST = 32768;
const DEFAULT_BLOCK_SIZE = 8;
const DEFAULT_PARALLELIZATION = 1;
const MAX_MEMORY = 64 * 1024 * 1024;

function derive(
  password: string,
  salt: Buffer,
  cost: number,
  blockSize: number,
  parallelization: number,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(
      password,
      salt,
      KEY_LENGTH,
      { cost, blockSize, parallelization, maxmem: MAX_MEMORY },
      (error, key) => (error ? reject(error) : resolve(key)),
    );
  });
}

export async function hashAdminPassword(password: string): Promise<string> {
  if (password.length < 12) {
    throw new Error('Admin password must contain at least 12 characters');
  }
  const salt = randomBytes(16);
  const key = await derive(
    password,
    salt,
    DEFAULT_COST,
    DEFAULT_BLOCK_SIZE,
    DEFAULT_PARALLELIZATION,
  );
  return [
    'scrypt',
    DEFAULT_COST,
    DEFAULT_BLOCK_SIZE,
    DEFAULT_PARALLELIZATION,
    salt.toString('base64url'),
    key.toString('base64url'),
  ].join('$');
}

export async function verifyAdminPassword(
  password: string,
  encodedHash: string,
): Promise<boolean> {
  const [algorithm, costText, blockSizeText, parallelizationText, salt, hash] =
    encodedHash.split('$');
  if (algorithm !== 'scrypt' || !salt || !hash) return false;

  const cost = Number(costText);
  const blockSize = Number(blockSizeText);
  const parallelization = Number(parallelizationText);
  if (
    !Number.isInteger(cost) ||
    cost < 16384 ||
    cost > DEFAULT_COST ||
    !Number.isInteger(blockSize) ||
    blockSize < 8 ||
    blockSize > 16 ||
    !Number.isInteger(parallelization) ||
    parallelization < 1 ||
    parallelization > 4
  ) {
    return false;
  }

  try {
    const expected = Buffer.from(hash, 'base64url');
    const actual = await derive(
      password,
      Buffer.from(salt, 'base64url'),
      cost,
      blockSize,
      parallelization,
    );
    return (
      expected.length === actual.length && timingSafeEqual(expected, actual)
    );
  } catch {
    return false;
  }
}
