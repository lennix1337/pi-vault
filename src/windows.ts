/**
 * Windows backends: DPAPI-protected values and Windows Credential Manager
 * generic credentials, both reached through one Windows PowerShell process.
 *
 * All traffic with the script is ASCII: values travel base64-encoded in both
 * directions, so no console code page can corrupt a secret, and no plaintext
 * ever appears on a command line. Stdout carries plaintext only to this module.
 */
import { spawn } from 'node:child_process';
import { join } from 'node:path';

export interface WindowsReadRequest {
  readonly name: string;
  readonly source: 'dpapi' | 'credman';
  /** DPAPI blob (hex) for dpapi; credential target for credman. */
  readonly locator: string;
}

export type WindowsReadResult = { readonly ok: true; readonly value: string } | { readonly ok: false; readonly code: 'missing' | 'decrypt' | 'unsupported' };

const CREDMAN_USER = 'pi-vault';
const SCRIPT_TIMEOUT_MS = 60_000;

const CREDMAN_CSHARP = String.raw`using System;
using System.Runtime.InteropServices;
public static class PiVaultCredMan {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct CREDENTIAL {
    public int Flags; public int Type; public IntPtr TargetName; public IntPtr Comment;
    public long LastWritten; public int CredentialBlobSize; public IntPtr CredentialBlob;
    public int Persist; public int AttributeCount; public IntPtr Attributes;
    public IntPtr TargetAlias; public IntPtr UserName;
  }
  [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredRead(string target, int type, int reserved, out IntPtr credential);
  [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredWrite(ref CREDENTIAL credential, int flags);
  [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredDelete(string target, int type, int flags);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern void CredFree(IntPtr credential);
  public static byte[] Read(string target) {
    IntPtr found;
    if (!CredRead(target, 1, 0, out found)) return null;
    try {
      CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(found, typeof(CREDENTIAL));
      byte[] bytes = new byte[c.CredentialBlobSize];
      if (c.CredentialBlobSize > 0) Marshal.Copy(c.CredentialBlob, bytes, 0, c.CredentialBlobSize);
      return bytes;
    } finally { CredFree(found); }
  }
  public static void Write(string target, string user, byte[] blob) {
    CREDENTIAL c = new CREDENTIAL();
    c.Type = 1; c.Persist = 2;
    c.TargetName = Marshal.StringToCoTaskMemUni(target);
    c.UserName = Marshal.StringToCoTaskMemUni(user);
    c.CredentialBlobSize = blob.Length;
    c.CredentialBlob = Marshal.AllocCoTaskMem(blob.Length);
    Marshal.Copy(blob, 0, c.CredentialBlob, blob.Length);
    try {
      if (!CredWrite(ref c, 0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    } finally {
      Marshal.FreeCoTaskMem(c.TargetName); Marshal.FreeCoTaskMem(c.UserName); Marshal.FreeCoTaskMem(c.CredentialBlob);
    }
  }
  public static bool Delete(string target) { return CredDelete(target, 1, 0); }
}
`;

const READ_BODY = String.raw`
foreach ($line in [Console]::In.ReadToEnd().Split([char]10)) {
  $line = $line.Trim()
  if ($line.Length -eq 0) { continue }
  $parts = $line.Split([char]9)
  $name = $parts[0]
  try {
    if ($parts[1] -eq 'dpapi') {
      $bytes = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($parts[2]), $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    } elseif ($parts[1] -eq 'credman') {
      $bytes = [PiVaultCredMan]::Read($parts[2])
      if ($null -eq $bytes) { [Console]::Out.WriteLine("$name ERR missing"); continue }
    } else { [Console]::Out.WriteLine("$name ERR unsupported"); continue }
    [Console]::Out.WriteLine("$name OK " + [Convert]::ToBase64String($bytes))
  } catch { [Console]::Out.WriteLine("$name ERR decrypt") }
}
exit 0
`;

const PROTECT_BODY = String.raw`
$bytes = [Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())
$protected = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Out.WriteLine([BitConverter]::ToString($protected).Replace('-', ''))
exit 0
`;

const WRITE_CREDMAN_BODY = String.raw`
$bytes = [Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())
[PiVaultCredMan]::Write($env:PI_VAULT_TARGET, '${CREDMAN_USER}', $bytes)
exit 0
`;

const DELETE_CREDMAN_BODY = String.raw`
if ([PiVaultCredMan]::Delete($env:PI_VAULT_TARGET)) { exit 0 }
exit 3
`;

type Operation = 'read' | 'protect-dpapi' | 'write-credman' | 'delete-credman';

function buildScript(operation: Operation): string {
  const body = { read: READ_BODY, 'protect-dpapi': PROTECT_BODY, 'write-credman': WRITE_CREDMAN_BODY, 'delete-credman': DELETE_CREDMAN_BODY }[operation];
  const needsCredman = operation !== 'protect-dpapi';
  const header = "$ErrorActionPreference = 'Stop'\nAdd-Type -AssemblyName System.Security\n$utf8 = [Text.Encoding]::UTF8\n";
  const addType = needsCredman ? `$cs = @'\n${CREDMAN_CSHARP}'@\nAdd-Type -TypeDefinition $cs -Language CSharp\n` : '';
  return header + addType + body;
}

function powershellPath(): string {
  const root = process.env.SystemRoot ?? process.env.windir;
  return root ? join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe') : 'powershell.exe';
}

interface ScriptRun {
  readonly exitCode: number | null;
  readonly stdout: string;
}

function runScript(operation: Operation, stdin: string, target?: string): Promise<ScriptRun> {
  const encoded = Buffer.from(buildScript(operation), 'utf16le').toString('base64');
  const env = { ...process.env, PI_VAULT_TARGET: target ?? '' };
  return new Promise<ScriptRun>((resolve, reject) => {
    const child = spawn(powershellPath(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], { env, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'] });
    let stdout = '';
    const timer = setTimeout(() => child.kill(), SCRIPT_TIMEOUT_MS);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => { stdout += chunk; });
    child.on('error', () => { clearTimeout(timer); reject(new Error('Windows PowerShell could not be started')); });
    child.on('close', exitCode => { clearTimeout(timer); resolve({ exitCode, stdout }); });
    child.stdin.end(stdin, 'ascii');
  });
}

/** Decrypts DPAPI and Credential Manager entries in one PowerShell process. Entries that fail are reported by code, never by value. */
export async function readWindowsSecrets(requests: readonly WindowsReadRequest[]): Promise<Map<string, WindowsReadResult>> {
  const results = new Map<string, WindowsReadResult>();
  if (requests.length === 0) return results;
  if (process.platform !== 'win32') {
    for (const request of requests) results.set(request.name, { ok: false, code: 'unsupported' });
    return results;
  }
  // DPAPI blobs travel as base64 so each line is plain ASCII with tab separators.
  const input = requests.map(request => `${request.name}\t${request.source}\t${request.source === 'dpapi' ? Buffer.from(request.locator, 'hex').toString('base64') : request.locator}`).join('\n');
  const run = await runScript('read', input);
  if (run.exitCode !== 0) throw new Error(`Windows PowerShell read failed (exit ${run.exitCode})`);
  for (const line of run.stdout.split('\n')) {
    const match = /^([A-Za-z_][A-Za-z0-9_]{0,63}) (OK|ERR)(?: (.*))?$/.exec(line.replace(/\r$/, ''));
    if (!match) continue;
    const [, name, status, payload = ''] = match;
    if (status === 'OK') results.set(name, { ok: true, value: Buffer.from(payload, 'base64').toString('utf8') });
    else results.set(name, { ok: false, code: payload === 'missing' ? 'missing' : 'decrypt' });
  }
  for (const request of requests) if (!results.has(request.name)) results.set(request.name, { ok: false, code: 'decrypt' });
  return results;
}

/** Protects a value for the current Windows user (DPAPI). Returns the hex blob to store in vault.json. */
export async function protectDpapi(value: string): Promise<string> {
  if (process.platform !== 'win32') throw new Error('DPAPI storage is available only on Windows; use --source credman or --source env elsewhere');
  const run = await runScript('protect-dpapi', Buffer.from(value, 'utf8').toString('base64'));
  const blob = run.stdout.trim();
  if (run.exitCode !== 0 || !/^[0-9a-fA-F]+$/.test(blob)) throw new Error('DPAPI protection failed');
  return blob;
}

/** Writes a generic Credential Manager entry for the current user. */
export async function writeCredman(target: string, value: string): Promise<void> {
  if (process.platform !== 'win32') throw new Error('Credential Manager storage is available only on Windows');
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.length > 2048) throw new Error('value is too large for a Credential Manager entry (2048 bytes max)');
  const run = await runScript('write-credman', bytes.toString('base64'), target);
  if (run.exitCode !== 0) throw new Error(`Credential Manager write failed (exit ${run.exitCode})`);
}

/** Deletes a generic Credential Manager entry. Returns false when no entry existed. */
export async function deleteCredman(target: string): Promise<boolean> {
  if (process.platform !== 'win32') throw new Error('Credential Manager is available only on Windows');
  const run = await runScript('delete-credman', '', target);
  if (run.exitCode === 0) return true;
  if (run.exitCode === 3) return false;
  throw new Error(`Credential Manager delete failed (exit ${run.exitCode})`);
}
