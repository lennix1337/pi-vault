/**
 * Runs one shell command with a given environment, capturing its output as
 * bytes so the caller can mask secrets before any of it is kept or shown.
 */
import { spawn, spawnSync } from 'node:child_process';
import { getShellConfig } from '@earendil-works/pi-coding-agent';

/** Raw output kept per stream. Beyond this the capture stops and the tail is dropped. */
export const CAPTURE_LIMIT_BYTES = 8 * 1024 * 1024;

/**
 * How long the output may stay open after the shell exits or is killed. A process the command left in the
 * background (`nohup deploy &`) can inherit the pipes and hold them for as long as it runs; past this the
 * call returns with what the shell wrote instead of waiting for it.
 */
const DRAIN_MS = 500;

export interface ProcessOptions {
  readonly command: string;
  readonly cwd: string;
  readonly env: NodeJS.ProcessEnv;
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
}

export interface ProcessResult {
  readonly status: 'ok' | 'failed' | 'timeout' | 'aborted' | 'error';
  readonly exitCode: number | null;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
  readonly truncated: boolean;
}

export function runShell(options: ProcessOptions): Promise<ProcessResult> {
  const shell = getShellConfig();
  const viaStdin = shell.commandTransport === 'stdin';
  const args = viaStdin ? shell.args : [...shell.args, options.command];
  const posix = process.platform !== 'win32';

  return new Promise<ProcessResult>(resolve => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(shell.shell, args, { cwd: options.cwd, env: options.env, windowsHide: true, detached: posix, stdio: ['pipe', 'pipe', 'pipe'] });
    } catch {
      resolve({ status: 'error', exitCode: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), truncated: false });
      return;
    }

    const out = new Capture();
    const err = new Capture();
    let stopReason: 'timeout' | 'aborted' | undefined;
    let exitCode: number | null = null;
    let settled = false;
    let drain: ReturnType<typeof setTimeout> | undefined;
    const settle = (status?: ProcessResult['status']) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(drain);
      options.signal?.removeEventListener('abort', onAbort);
      child.stdout?.destroy();
      child.stderr?.destroy();
      const stdout = out.finish();
      const stderr = err.finish();
      if (status === 'error') {
        resolve({ status, exitCode: null, stdout: stdout.bytes, stderr: stderr.bytes, truncated: false });
        return;
      }
      resolve({ status: stopReason ?? (exitCode === 0 ? 'ok' : 'failed'), exitCode, stdout: stdout.bytes, stderr: stderr.bytes, truncated: stdout.truncated || stderr.truncated });
    };
    const drainThenSettle = () => {
      if (!drain) drain = setTimeout(settle, DRAIN_MS);
    };
    const stop = (reason: 'timeout' | 'aborted') => {
      if (stopReason) return;
      stopReason = reason;
      killTree(child.pid, posix);
      drainThenSettle();
    };
    const timer = setTimeout(() => stop('timeout'), options.timeoutMs);
    const onAbort = () => stop('aborted');
    if (options.signal?.aborted) onAbort();
    else options.signal?.addEventListener('abort', onAbort, { once: true });

    child.stdout?.on('data', (chunk: Buffer) => out.push(chunk));
    child.stderr?.on('data', (chunk: Buffer) => err.push(chunk));
    child.on('error', () => settle('error'));
    child.on('exit', (code: number | null) => {
      exitCode = code;
      drainThenSettle();
    });
    child.on('close', (code: number | null) => {
      exitCode = code;
      settle();
    });

    child.stdin?.on('error', () => undefined);
    if (viaStdin) child.stdin?.end(options.command);
    else child.stdin?.end();
  });
}

/** Keeps the first CAPTURE_LIMIT_BYTES of a stream. The display window is far smaller, so a cut here never reaches the model. */
class Capture {
  private readonly chunks: Buffer[] = [];
  private size = 0;
  private truncated = false;

  push(chunk: Buffer): void {
    if (this.truncated) return;
    const room = CAPTURE_LIMIT_BYTES - this.size;
    if (chunk.length <= room) {
      this.chunks.push(chunk);
      this.size += chunk.length;
    } else {
      this.chunks.push(chunk.subarray(0, room));
      this.size = CAPTURE_LIMIT_BYTES;
      this.truncated = true;
    }
  }

  finish(): { bytes: Buffer; truncated: boolean } {
    return { bytes: Buffer.concat(this.chunks, this.size), truncated: this.truncated };
  }
}

function killTree(pid: number | undefined, posix: boolean): void {
  if (pid === undefined) return;
  if (posix) {
    try {
      process.kill(-pid, 'SIGKILL');
    } catch {
      // The group already exited.
    }
  } else {
    spawnSync('taskkill', ['/pid', String(pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
  }
}
