import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { Writable } from 'node:stream';
import { hashAdminPassword } from '../src/modules/admin/password-hash';

async function main(): Promise<void> {
  if (!stdin.isTTY || !stdout.isTTY) {
    throw new Error('Run this command in an interactive terminal');
  }
  let muted = false;
  const hiddenOutput = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      if (!muted) stdout.write(chunk);
      callback();
    },
  });
  const prompt = createInterface({
    input: stdin,
    output: hiddenOutput,
    terminal: true,
  });
  try {
    stdout.write('Admin password: ');
    muted = true;
    const password = await prompt.question('');
    muted = false;
    stdout.write('\nConfirm password: ');
    muted = true;
    const confirmation = await prompt.question('');
    muted = false;
    stdout.write('\n');
    if (password !== confirmation) throw new Error('Passwords do not match');
    stdout.write(`${await hashAdminPassword(password)}\n`);
  } finally {
    prompt.close();
  }
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unknown error';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
