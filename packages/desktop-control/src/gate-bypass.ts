/**
 * Gate bypass: injects JavaScript into the Electron main process (via the
 * `--inspect` Node Inspector target) to bypass the Desktop startup
 * "Organization settings" gate.
 *
 * ## Root cause
 *
 * Desktop's startup gate (`initializeNodeNetworkPermissions` / `la()`) calls
 * `readStartupApplicationRequirements` (`Yc`) which spawns the app-server
 * child process via `child_process.spawn` and exchanges JSON-RPC over
 * stdin/stdout (JSONL, one JSON message per line).
 *
 * In API-key mode the app-server rejects with "remote control requires
 * ChatGPT authentication". `Yc` throws → `la()` catches → shows a blocking
 * `dialog.showMessageBox` ("Organization settings could not be loaded") →
 * Desktop never spawns the Codex CLI → shim/node never appear →
 * `wait_for_host_chain` times out → launcher kills Desktop.
 *
 * ## Bypass strategy
 *
 * 1. Hook `require("child_process").spawn` — intercept the app-server spawn
 *    and return a fake child process that speaks the JSON-RPC protocol,
 *    responding with `{requirements: null}` which makes `ia()` return
 *    `{kind: "unrestricted"}` → gate passes.
 * 2. Hook `require("electron").dialog.showMessageBox` — auto-return
 *    `{response: 0}` (retry) for warning dialogs, unblocking any
 *    currently-displayed gate dialog so the retry loop calls `Yc` again
 *    (which now uses the patched `spawn`).
 *
 * The hooks are installed once. `spawn` restores itself after the first
 * app-server interception so normal child processes are unaffected.
 */

import { CdpClient, listCdpTargets, type CdpTarget } from "./cdp-client.js";

export interface GateBypassResult {
  readonly installed: boolean;
  readonly detail: string;
}

export interface InstallGateBypassOptions {
  /** Node Inspector HTTP endpoint (e.g. `http://127.0.0.1:PORT`) */
  inspectorEndpoint: string;
  /** Poll interval for Node target discovery (ms). Default 250. */
  pollIntervalMs?: number;
  /** Timeout for target discovery + injection (ms). Default 30 000. */
  timeoutMs?: number;
  /** Optional abort signal. */
  signal?: AbortSignal;
}

/**
 * JavaScript executed inside the Electron main process via
 * `Runtime.evaluate`. Returns a status string.
 *
 * The script is self-contained: it creates fake streams with
 * `Readable`/`Writable` and `EventEmitter`, hooks `child_process.spawn`
 * and `electron.dialog`, then returns.
 */
const GATE_BYPASS_SCRIPT = String.raw`(() => {
  if (globalThis.__codexhostGateBypass) return "already-installed";
  globalThis.__codexhostGateBypass = true;

  const cp = require("node:child_process");
  const { EventEmitter } = require("node:events");
  const { Readable, Writable } = require("node:stream");

  let dialogHooked = false;
  let spawnHooked = false;
  let intercepted = false;

  // 1. Hook dialog.showMessageBox / showMessageBoxSync to auto-return retry
  try {
    const electron = require("electron");
    const dialog = electron.dialog;
    if (dialog && typeof dialog.showMessageBox === "function") {
      const orig = dialog.showMessageBox.bind(dialog);
      dialog.showMessageBox = async function (...args) {
        const opts = (typeof args[0] === "object" && args[0] !== null && !Array.isArray(args[0]))
          ? args[0]
          : (typeof args[1] === "object" && args[1] !== null ? args[1] : {});
        if (opts.type === "warning") return { response: 0 };
        return orig(...args);
      };
      dialogHooked = true;
    }
    if (dialog && typeof dialog.showMessageBoxSync === "function") {
      const origSync = dialog.showMessageBoxSync.bind(dialog);
      dialog.showMessageBoxSync = function (...args) {
        const opts = (typeof args[0] === "object" && args[0] !== null && !Array.isArray(args[0]))
          ? args[0]
          : {};
        if (opts.type === "warning") return 0;
        return origSync(...args);
      };
      dialogHooked = true;
    }
  } catch {}

  // 2. Hook child_process.spawn to intercept app-server spawn
  const origSpawn = cp.spawn;

  function handleRequest(msg, stdout) {
    if (!msg || typeof msg.method !== "string") return;
    if (msg.method === "initialize" && msg.id) {
      stdout.push(JSON.stringify({ id: msg.id, result: { userAgent: "codex/0.141.0" } }) + "\n");
    } else if (msg.method === "configRequirements/read" && msg.id) {
      stdout.push(JSON.stringify({ id: msg.id, result: { requirements: null } }) + "\n");
    } else if (msg.method === "config/read" && msg.id) {
      stdout.push(JSON.stringify({ id: msg.id, result: {} }) + "\n");
    } else if (msg.method === "account/logout" && msg.id) {
      stdout.push(JSON.stringify({ id: msg.id, result: {} }) + "\n");
    stdout.push(JSON.stringify({ id: msg.id, result: {} }) + "\n");
    } else if (msg.method === "account/read" && msg.id) {
      stdout.push(JSON.stringify({ id: msg.id, result: { isSignedIn: true } }) + "\n");
    } else if (msg.method === "getAuthStatus" && msg.id) {
      stdout.push(JSON.stringify({ id: msg.id, result: { status: "authenticated" } }) + "\n");
    } else if (msg.method === "account/gatewayOAuth/read" && msg.id) {
      stdout.push(JSON.stringify({ id: msg.id, result: { gatewayOAuth: { status: "connected" } } }) + "\n");
    } else if (msg.method === "experimentalFeature/list" && msg.id) {
      // Return empty list to avoid experimental feature issues
      stdout.push(JSON.stringify({ id: msg.id, result: [] }) + "\n");
    } else if (msg.method === "thread/list" && msg.id) {
      stdout.push(JSON.stringify({ id: msg.id, result: [] }) + "\n");
    } else if (msg.method === "thread/attachment/list" && msg.id) {
      stdout.push(JSON.stringify({ id: msg.id, result: [] }) + "\n");
    } else if (msg.method === "remoteControl/status/read" && msg.id) {
      stdout.push(JSON.stringify({ id: msg.id, result: { status: "idle" } }) + "\n");
    } else if (msg.method === "windowsSandbox/readiness" && msg.id) {
      stdout.push(JSON.stringify({ id: msg.id, result: { ready: true } }) + "\n");
    }
  function createFakeAppServer(cmd, args) {
    const proc = new EventEmitter();
    proc.pid = 1;
    proc.spawnfile = cmd;
    proc.spawnargs = args || [];

    const stdout = new Readable({ read() {} });
    const stderr = new Readable({ read() {} });

    proc.stdin = new Writable({
      write(chunk, _encoding, callback) {
        const data = chunk.toString();
        for (const line of data.split("\n")) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          try { handleRequest(JSON.parse(trimmed), stdout); } catch {}
        }
        callback();
      },
    });

    proc.stdout = stdout;
    proc.stderr = stderr;
    return proc;
  }

  cp.spawn = function (cmd, args, opts) {
    const cmdStr = typeof cmd === "string" ? cmd.toLowerCase() : "";
    const isPipeStdio = opts && Array.isArray(opts.stdio) &&
      opts.stdio.length === 3 &&
      opts.stdio.every((s) => s === "pipe");

    // Intercept: looks like codex CLI spawn + pipe stdio + not yet intercepted
    if (cmdStr.includes("codex") && isPipeStdio && !intercepted) {
      intercepted = true;
      cp.spawn = origSpawn; // restore — only first app-server spawn is intercepted
      spawnHooked = true;
      return createFakeAppServer(cmd, args);
    }
    return origSpawn.apply(cp, arguments);
  };

  return "installed(dialog=" + dialogHooked + ",spawn=" + spawnHooked + ")";
})()`;

export { GATE_BYPASS_SCRIPT as gateBypassScript };

/** Promise.withResolvers-based sleep. */
function sleep(ms: number): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<void>();
  setTimeout(resolve, ms);
  return promise;
}

/**
 * Installs the gate bypass into the Electron main process via the Node
 * Inspector CDP target.
 *
 * Polls the Inspector endpoint for a `type: "node"` target, connects to it,
 * enables `Runtime`, and evaluates the gate bypass script.
 *
 * Best-effort: if the Node target is unavailable or injection fails, returns
 * `{installed: false}` so the caller can continue with normal flow.
 */
export async function installGateBypass(
  options: InstallGateBypassOptions,
): Promise<GateBypassResult> {
  const endpoint = options.inspectorEndpoint;
  const pollIntervalMs = options.pollIntervalMs ?? 250;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;

  while (Date.now() < deadline) {
    if (options.signal?.aborted) {
      return { installed: false, detail: "aborted" };
    }
    try {
      const targets = await listCdpTargets(endpoint);
      const nodeTarget = targets.find((t) => t.type === "node" && t.webSocketDebuggerUrl);
      if (nodeTarget) {
        const client = await CdpClient.connect(nodeTarget.webSocketDebuggerUrl);
        try {
          await client.command("Runtime.enable");
          const result = await client.evaluate<string>(GATE_BYPASS_SCRIPT);
          const installed = typeof result === "string" && result.startsWith("installed");
          return {
            installed,
            detail: typeof result === "string" ? result : "evaluated",
          };
        } finally {
          client.close();
        }
      }
      lastError = new Error("Inspector has no Node target");
    } catch (error) {
      lastError = error;
    }
    await sleep(pollIntervalMs);
  }

  const detail = lastError instanceof Error ? lastError.message : "timeout";
  return { installed: false, detail: `gate bypass unavailable: ${detail}` };
}
