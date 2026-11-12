import { spawn } from 'node:child_process';
import { isAbsolute } from 'node:path';

export interface ProcessRequest {
  executable: string;
  args: readonly string[];
  cwd: string;
  timeoutMs: number;
  outputLimit: number;
  /** Optional caller cancellation: stops the whole supervised group. */
  signal?: AbortSignal;
  /** Opt in to a fixed system PATH (`/usr/bin:/bin`) for engines that spawn base tools. */
  systemPath?: boolean;
}
export type ProcessOutcome =
  | { state: 'exited'; code: number; stdout: Buffer }
  | {
      state:
        | 'failed'
        | 'timed-out'
        | 'output-limit'
        | 'unsupported'
        | 'cancelled'
        | 'cleanup-uncertain';
    };

// Trusted anchor stays alive until killing ITS OWN group. The parent never
// kills a group by a stale/reaped child PID. Not a sandbox: trusted scanners
// must not deliberately escape their group or interfere with the supervisor.
const supervisor = `
const {spawn} = require('node:child_process');
const [timeout, executable, ...args] = process.argv.slice(1);
let finishing = false;
const finish = (result) => {
  if (finishing) return;
  finishing = true;
  const kill = () => {
    try { process.kill(-process.pid, 'SIGKILL'); }
    catch { process.exit(125); }
  };
  if (process.connected) process.send(result, kill);
  else kill();
};
setTimeout(() => finish({state:'timed-out'}), Number(timeout));
process.on('message', () => finish({state:'output-limit'}));
process.on('disconnect', () => finish({state:'failed'}));
const tool = spawn(executable, args, {shell:false, stdio:['ignore',1,2], env:process.env});
tool.on('error', () => finish({state:'failed'}));
tool.on('exit', (code) => finish(code === null ? {state:'failed'} : {state:'exited',code}));
`;

/** Internal transport only: never publish raw stdout/stderr. Linux-only process
 * groups, explicit executable and fixed argv, scrubbed environment, bounded IO.
 */
export async function runScannerProcess(
  request: ProcessRequest,
): Promise<ProcessOutcome> {
  if (process.platform !== 'linux') return { state: 'unsupported' };
  if (
    !isAbsolute(request.executable) ||
    !isAbsolute(request.cwd) ||
    !Number.isSafeInteger(request.timeoutMs) ||
    request.timeoutMs < 1 ||
    request.timeoutMs > 120000 ||
    !Number.isSafeInteger(request.outputLimit) ||
    request.outputLimit < 1 ||
    request.outputLimit > 16777216
  )
    return { state: 'failed' };
  if (request.signal?.aborted) return { state: 'cancelled' };
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      [
        '--max-old-space-size=32',
        '-e',
        supervisor,
        String(request.timeoutMs),
        request.executable,
        ...request.args,
      ],
      {
        cwd: request.cwd,
        detached: true,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
        env: {
          ...(request.systemPath ? { PATH: '/usr/bin:/bin' } : {}),
          LANG: 'C',
          LC_ALL: 'C',
          TZ: 'UTC',
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_CONFIG_GLOBAL: '/dev/null',
          GIT_NO_REPLACE_OBJECTS: '1',
          GIT_TERMINAL_PROMPT: '0',
          GIT_NO_LAZY_FETCH: '1',
          GIT_ALLOW_PROTOCOL: '',
          GIT_OPTIONAL_LOCKS: '0',
          GIT_CONFIG_COUNT: '2',
          GIT_CONFIG_KEY_0: 'core.fsmonitor',
          GIT_CONFIG_VALUE_0: 'false',
          GIT_CONFIG_KEY_1: 'core.hooksPath',
          GIT_CONFIG_VALUE_1: '/dev/null',
        },
      },
    );
    let result: ProcessOutcome | undefined;
    let size = 0;
    let oversized = false;
    let cancelled = false;
    let settled = false;
    let supervisorExited = false;
    const chunks: Buffer[] = [];
    const finish = (outcome: ProcessOutcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      request.signal?.removeEventListener('abort', onAbort);
      child.stdout?.destroy();
      child.stderr?.destroy();
      if (child.connected) child.disconnect();
      resolve(outcome);
    };
    const onAbort = () => {
      cancelled = true;
      if (!oversized && child.connected) child.send('stop', () => {});
    };
    request.signal?.addEventListener('abort', onAbort, { once: true });
    if (request.signal?.aborted) onAbort();
    const timer = setTimeout(() => {
      // No group kill here. A broken supervisor is explicitly uncertain.
      if (!supervisorExited) child.kill('SIGKILL');
      finish({ state: 'cleanup-uncertain' });
    }, request.timeoutMs + 2000);
    child.on('message', (message: unknown) => {
      if (
        typeof message !== 'object' ||
        message === null ||
        !('state' in message)
      )
        return;
      if (
        message.state === 'exited' &&
        'code' in message &&
        typeof message.code === 'number'
      )
        result = {
          state: 'exited',
          code: message.code,
          stdout: Buffer.alloc(0),
        };
      else if (
        message.state === 'failed' ||
        message.state === 'timed-out' ||
        message.state === 'output-limit'
      )
        result = { state: message.state };
    });
    const receive = (chunk: Buffer, stdout: boolean) => {
      size += chunk.length;
      if (size > request.outputLimit) {
        if (!oversized && child.connected) child.send('stop', () => {});
        oversized = true;
      } else if (stdout && !oversized) chunks.push(chunk);
    };
    child.stdout?.on('data', (chunk: Buffer) => receive(chunk, true));
    child.stderr?.on('data', (chunk: Buffer) => receive(chunk, false));
    child.on('error', () => {
      if (child.pid === undefined) supervisorExited = true;
      result = { state: 'failed' };
    });
    child.on('exit', () => {
      supervisorExited = true;
    });
    child.on('close', (_code, signal) => {
      if (result === undefined || signal !== 'SIGKILL')
        return finish({ state: 'cleanup-uncertain' });
      if (cancelled) return finish({ state: 'cancelled' });
      if (oversized) return finish({ state: 'output-limit' });
      finish(
        result.state === 'exited'
          ? { ...result, stdout: Buffer.concat(chunks) }
          : result,
      );
    });
  });
}
