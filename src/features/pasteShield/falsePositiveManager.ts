/**
 * PasteShield - False Positive Manager
 *
 * Persists false-positive reports to a workspace-local JSON file.
 * Data is stored locally only and never transmitted.
 */

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

const FALSE_POSITIVE_LOG_FILE = '.pasteshield-fp.json';

export interface FalsePositiveEntry {
  patternName: string;
  reportedAt: string;
  context?: string;
}

export interface FalsePositiveLog {
  falsePositives: FalsePositiveEntry[];
}

export interface FalsePositiveStats {
  total: number;
  byPattern: Record<string, number>;
  topPatterns: Array<{ patternName: string; count: number }>;
}

export class FalsePositiveManager {
  private static instance: FalsePositiveManager | undefined;

  private constructor(private readonly context: vscode.ExtensionContext) {
    void this.context; // Reserved for future use.
  }

  public static getInstance(context: vscode.ExtensionContext): FalsePositiveManager {
    if (!FalsePositiveManager.instance) {
      FalsePositiveManager.instance = new FalsePositiveManager(context);
    }
    return FalsePositiveManager.instance;
  }

  public async recordFalsePositives(
    patternNames: string[],
    contextUri?: vscode.Uri,
  ): Promise<number> {
    const uniqueNames = [...new Set(patternNames.filter(Boolean))];
    if (uniqueNames.length === 0) {
      return 0;
    }

    const workspaceFolder = this.getWorkspaceFolderForUri(contextUri) ?? this.getDefaultWorkspaceFolder();
    if (!workspaceFolder) {
      vscode.window.showWarningMessage('PasteShield: No workspace folder found to store false positives.');
      return 0;
    }

    const log = await this.readLog(workspaceFolder);
    const now = new Date().toISOString();
    const contextPath = this.buildContextPath(workspaceFolder, contextUri);

    for (const patternName of uniqueNames) {
      log.falsePositives.push({
        patternName,
        reportedAt: now,
        context: contextPath,
      });
    }

    await this.writeLog(workspaceFolder, log);
    await this.ensureGitignoreEntry(workspaceFolder);

    return uniqueNames.length;
  }

  public async getStats(): Promise<FalsePositiveStats> {
    const workspaceFolders = vscode.workspace.workspaceFolders ?? [];
    const byPattern: Record<string, number> = {};
    let total = 0;

    for (const folder of workspaceFolders) {
      const log = await this.readLog(folder);
      for (const entry of log.falsePositives) {
        byPattern[entry.patternName] = (byPattern[entry.patternName] || 0) + 1;
        total++;
      }
    }

    const topPatterns = Object.entries(byPattern)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([patternName, count]) => ({ patternName, count }));

    return {
      total,
      byPattern,
      topPatterns,
    };
  }

  public async exportLog(): Promise<void> {
    const workspaceFolder = this.getDefaultWorkspaceFolder();
    if (!workspaceFolder) {
      vscode.window.showWarningMessage('PasteShield: No workspace folder found to export false positives.');
      return;
    }

    const log = await this.readLog(workspaceFolder);
    const payload = {
      generatedAt: new Date().toISOString(),
      falsePositives: log.falsePositives,
    };

    const defaultFileName = `pasteshield-false-positives-${new Date().toISOString().split('T')[0]}.json`;
    const uri = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file(defaultFileName),
      filters: { JSON: ['json'] },
    });

    if (uri) {
      await vscode.workspace.fs.writeFile(uri, Buffer.from(JSON.stringify(payload, null, 2), 'utf8'));
      vscode.window.showInformationMessage(`False positive log exported to ${uri.fsPath}`);
    }
  }

  private getWorkspaceFolderForUri(uri?: vscode.Uri): vscode.WorkspaceFolder | undefined {
    if (!uri) return undefined;
    return vscode.workspace.getWorkspaceFolder(uri) ?? undefined;
  }

  private getDefaultWorkspaceFolder(): vscode.WorkspaceFolder | undefined {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
      return undefined;
    }
    return workspaceFolders[0];
  }

  private buildContextPath(
    workspaceFolder: vscode.WorkspaceFolder,
    contextUri?: vscode.Uri,
  ): string | undefined {
    if (!contextUri) return undefined;

    if (contextUri.scheme !== 'file') {
      return contextUri.toString();
    }

    const relative = path.relative(workspaceFolder.uri.fsPath, contextUri.fsPath);
    if (!relative || relative.startsWith('..')) {
      return path.basename(contextUri.fsPath);
    }

    return relative.split(path.sep).join('/');
  }

  private getLogPath(workspaceFolder: vscode.WorkspaceFolder): string {
    return path.join(workspaceFolder.uri.fsPath, FALSE_POSITIVE_LOG_FILE);
  }

  private async readLog(workspaceFolder: vscode.WorkspaceFolder): Promise<FalsePositiveLog> {
    const logPath = this.getLogPath(workspaceFolder);

    try {
      if (!fs.existsSync(logPath)) {
        return { falsePositives: [] };
      }

      const content = await fs.promises.readFile(logPath, 'utf8');
      const parsed = JSON.parse(content) as FalsePositiveLog;
      if (!parsed || !Array.isArray(parsed.falsePositives)) {
        return { falsePositives: [] };
      }
      return parsed;
    } catch (error) {
      console.error('PasteShield: failed to read false positive log', error);
      return { falsePositives: [] };
    }
  }

  private async writeLog(
    workspaceFolder: vscode.WorkspaceFolder,
    log: FalsePositiveLog,
  ): Promise<void> {
    const logPath = this.getLogPath(workspaceFolder);
    const content = JSON.stringify(log, null, 2);
    await fs.promises.writeFile(logPath, content, 'utf8');
  }

  private async ensureGitignoreEntry(workspaceFolder: vscode.WorkspaceFolder): Promise<void> {
    const gitignorePath = path.join(workspaceFolder.uri.fsPath, '.gitignore');
    if (!fs.existsSync(gitignorePath)) {
      return;
    }

    try {
      const content = await fs.promises.readFile(gitignorePath, 'utf8');
      const lines = content.split(/\r?\n/).map(line => line.trim());
      if (lines.includes(FALSE_POSITIVE_LOG_FILE)) {
        return;
      }

      const updated = content.replace(/\s*$/, '') + `\n\n# PasteShield logs\n${FALSE_POSITIVE_LOG_FILE}\n`;
      await fs.promises.writeFile(gitignorePath, updated, 'utf8');
    } catch (error) {
      console.error('PasteShield: failed to update .gitignore', error);
    }
  }
}
