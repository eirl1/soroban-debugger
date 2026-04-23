import * as fs from 'fs';
import * as path from 'path';
import * as vscode_api from 'vscode';

export enum LogLevel {
  Debug = 'DEBUG',
  Info = 'INFO',
  Warn = 'WARN',
  Error = 'ERROR'
}

export enum LogPhase {
  Lifecycle = 'LIFECYCLE',
  Spawn = 'SPAWN',
  Connect = 'CONNECT',
  Auth = 'AUTH',
  Load = 'LOAD',
  DAP = 'DAP',
  Backend = 'BACKEND',
  Teardown = 'TEARDOWN'
}

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  phase: LogPhase;
  message: string;
  correlationId?: string;
}

type OutputChannelLike = {
  appendLine: (msg: string) => void;
  dispose: () => void;
};

type StorageUriLike = {
  fsPath: string;
};

type ExtensionContextLike = {
  globalStorageUri: StorageUriLike;
};

type VscodeModuleLike = {
  window?: {
    createOutputChannel: (name: string) => OutputChannelLike;
  };
};

function loadVscodeModule(): VscodeModuleLike | undefined {
  try {
    return require('vscode') as VscodeModuleLike;
  } catch {
    return undefined;
  }
}

export class LogManager {
  private outputChannel: OutputChannelLike;
  private logFile: string;
  private maxLogSizeBytes = 10 * 1024 * 1024; // 10MB
  private telemetryEnabled: boolean = false;

  constructor(context: ExtensionContextLike) {
    const vscode = loadVscodeModule();

    if (vscode?.window) {
      this.outputChannel = vscode.window.createOutputChannel('Soroban Debugger');
    } else {
      this.outputChannel = {
        appendLine: (msg: string) => console.log(msg),
        dispose: () => {}
      };
    }
    this.logFile = path.join(context.globalStorageUri.fsPath, 'debug.log');
    this.ensureLogDirectory();
    this.updateTelemetryStatus();
  }

  private updateTelemetryStatus(): void {
    const vscode = loadVscodeModule() as any;
    if (vscode?.workspace) {
      this.telemetryEnabled = vscode.workspace.getConfiguration('soroban-debugger').get('telemetry.enabled', false);
    }
  }

  private ensureLogDirectory(): void {
    const dir = path.dirname(this.logFile);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  public log(level: LogLevel, phase: LogPhase, message: string, correlationId?: string): void {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      phase,
      message: this.redact(message),
      correlationId
    };

    const formatted = this.formatEntry(entry);
    this.outputChannel.appendLine(formatted);
    this.persistEntry(formatted);

    if (this.telemetryEnabled && level === LogLevel.Error) {
      this.sendTelemetry(entry);
    }
  }

  private sendTelemetry(entry: LogEntry): void {
    // In a real implementation, this would send to a telemetry endpoint.
    // For now, we log that telemetry was "sent" to the output channel in debug mode.
    const vscode = loadVscodeModule() as any;
    if (vscode?.env?.sessionId) {
      // Simulated telemetry submission
      console.log(`[TELEMETRY] Sending failure signal: ${entry.phase} - ${entry.message.substring(0, 100)}`);
    }
  }

  private formatEntry(entry: LogEntry): string {
    const cid = entry.correlationId ? ` [CID:${entry.correlationId}]` : '';
    return `[${entry.timestamp}] [${entry.level}] [${entry.phase}]${cid} ${entry.message}`;
  }

  private persistEntry(line: string): void {
    try {
      this.rotateLogIfNecessary();
      fs.appendFileSync(this.logFile, line + '\n', 'utf8');
    } catch (err) {
      // Fallback if file logging fails
      console.error('Failed to write to log file:', err);
    }
  }

  private rotateLogIfNecessary(): void {
    try {
      if (fs.existsSync(this.logFile) && fs.statSync(this.logFile).size > this.maxLogSizeBytes) {
        const backup = `${this.logFile}.old`;
        if (fs.existsSync(backup)) {
          fs.unlinkSync(backup);
        }
        fs.renameSync(this.logFile, backup);
      }
    } catch (err) {
      console.error('Log rotation failed:', err);
    }
  }

  private redact(message: string): string {
    // Redact --token <token>
    return message.replace(/(--token\s+)(\S+)/g, '$1[REDACTED]');
  }

  public dispose(): void {
    this.outputChannel.dispose();
  }
}
