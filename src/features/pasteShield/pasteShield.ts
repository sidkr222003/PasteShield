/**
 * PasteShield
 *
 * Intercepts clipboard paste operations in the editor, scans the content
 * for secrets / risky patterns, and surfaces a non-blocking warning with
 * actionable choices before the text is committed to the document.
 *
 * Architecture:
 *  • Overrides the default `editor.action.clipboardPasteAction` keybinding
 *    via a dedicated `pasteShield.paste` command (registered in package.json).
 *  • If no issues are found → delegates to the original paste immediately.
 *  • If issues are found → shows a warning with "Paste Anyway / Cancel / Details".
 *  • Inline decorations mark the insertion point for warned pastes (optional).
 *  • CodeLens providers display warnings above detected secrets in open files.
 *
 * Exceptions:
 *  • .env and .env.local files are excluded from paste interception entirely.
 *    (These files are intentionally used to store secrets locally.)
 *  • CodeLens scanning still runs on all file types including .env files.
 */

import * as vscode from 'vscode';
import * as path from 'path';
import { scanContent, DetectionResult, Severity } from './patternDetector';
import { getConfig, meetsSeverityThreshold, CONFIG_SECTION } from './pasteShieldConfig';
import { createLogger } from '../../utils/logger';
import { debounce } from '../../utils/debounce';
import { HistoryManager, ScanHistoryEntry } from '../../utils/historyManager';
import { HistoryViewProvider, HistoryItem } from './historyViewProvider';
import { StatisticsManager } from './statisticsManager';
import { IgnorePatternsManager } from './ignorePatternsManager';
import { FalsePositiveManager } from './falsePositiveManager';

const logger = createLogger('PasteShield');

// ─── Constants ───────────────────────────────────────────────────────────────

const COMMAND_ID = 'pasteShield.paste';
const TOGGLE_COMMAND_ID = 'pasteShield.toggle';
const SHOW_REPORT_COMMAND_ID = 'pasteShield.showLastReport';
const CODELENS_FIX_COMMAND_ID = 'pasteShield.codeLensFix';
const CODELENS_IGNORE_COMMAND_ID = 'pasteShield.codeLensIgnore';
const CODELENS_DETAILS_COMMAND_ID = 'pasteShield.codeLensDetails';
const CODELENS_FALSE_POSITIVE_COMMAND_ID = 'pasteShield.codeLensFalsePositive';
const SHOW_DETECTION_DETAILS_COMMAND_ID = 'pasteShield.showDetectionDetails';
const SHOW_HISTORY_COMMAND_ID = 'pasteShield.showHistory';
const CLEAR_HISTORY_COMMAND_ID = 'pasteShield.clearHistory';
const EXPORT_HISTORY_JSON_COMMAND_ID = 'pasteShield.exportHistoryJson';
const EXPORT_HISTORY_TEXT_COMMAND_ID = 'pasteShield.exportHistoryText';
const REFRESH_HISTORY_COMMAND_ID = 'pasteShield.refreshHistory';
const SHOW_STATISTICS_COMMAND_ID = 'pasteShield.showStatistics';
const EXPORT_AUDIT_LOG_COMMAND_ID = 'pasteShield.exportAuditLog';
const SHOW_ROTATION_REMINDERS_COMMAND_ID = 'pasteShield.showRotationReminders';
const ADD_TO_WORKSPACE_IGNORE_COMMAND_ID = 'pasteShield.addToWorkspaceIgnore';
const EXPORT_FALSE_POSITIVES_COMMAND_ID = 'pasteShield.exportFalsePositiveLog';

/**
 * File names (basename only, case-insensitive) that are excluded from
 * paste interception. Secrets in these files are intentional and managed
 * locally — PasteShield should not block pasting into them.
 *
 * NOTE: CodeLens still scans these files so existing secrets are surfaced.
 */
const PASTE_EXCLUDED_FILENAMES = new Set(['.env', '.env.local']);

// Use VS Code theme colors instead of hardcoded colors for better responsiveness
const SEVERITY_THEME_COLORS: Record<Severity, vscode.ThemeColor> = {
  critical: new vscode.ThemeColor('editorError.foreground'),
  high:     new vscode.ThemeColor('editorWarning.foreground'),
  medium:   new vscode.ThemeColor('editorInfo.foreground'),
  low:      new vscode.ThemeColor('descriptionForeground'),
};

// ─── Utilities ────────────────────────────────────────────────────────────────

/**
 * Returns true if the document's filename is in the paste-exclusion list.
 * Comparison is case-insensitive so `.ENV` also matches on Windows.
 */
function isPasteExcludedFile(document: vscode.TextDocument): boolean {
  const basename = path.basename(document.fileName).toLowerCase();
  for (const excluded of PASTE_EXCLUDED_FILENAMES) {
    if (basename === excluded.toLowerCase()) {
      return true;
    }
  }
  return false;
}

// ─── Decoration Types ─────────────────────────────────────────────────────────

function createDecorationTypes(): {
  critical: vscode.TextEditorDecorationType;
  high: vscode.TextEditorDecorationType;
  medium: vscode.TextEditorDecorationType;
  low: vscode.TextEditorDecorationType;
} {
  const make = (themeColor: vscode.ThemeColor, glyph: string) =>
    vscode.window.createTextEditorDecorationType({
      after: {
        contentText: ` ${glyph} PasteShield`,
        color: new vscode.ThemeColor('editorWarning.foreground'),
        fontStyle: 'italic',
        margin: '0 0 0 8px',
      },
      overviewRulerColor: themeColor,
      overviewRulerLane: vscode.OverviewRulerLane.Right,
      light: { borderColor: themeColor, borderStyle: 'dashed', borderWidth: '1px' },
      dark:  { borderColor: themeColor, borderStyle: 'dashed', borderWidth: '1px' },
    });

  return {
    critical: make(SEVERITY_THEME_COLORS.critical, '$(error)'),
    high:     make(SEVERITY_THEME_COLORS.high,     '$(shield)'),
    medium:   make(SEVERITY_THEME_COLORS.medium,   '$(warning)'),
    low:      make(SEVERITY_THEME_COLORS.low,      '$(info)'),
  };
}

// ─── CodeLens Provider ────────────────────────────────────────────────────────

/**
 * One CodeLens "block" per detected issue — renders above the matched line
 * with four lenses side-by-side: severity badge | view details | ignore | false positive.
 */
class PasteShieldCodeLensProvider implements vscode.CodeLensProvider {
  private readonly _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

  /** Called by refresh() when a document is re-scanned. */
  refresh(): void {
    this._onDidChangeCodeLenses.fire();
  }

  provideCodeLenses(
    document: vscode.TextDocument,
    _token: vscode.CancellationToken,
  ): vscode.CodeLens[] {
    const config = getConfig();
    if (!config.enabled) {
      return [];
    }

    const text = document.getText();
    const detections = scanContent(text, {
      ignoredPatterns: config.ignoredPatterns,
    });

    const filtered = detections.filter(d =>
      meetsSeverityThreshold(d.severity, config.minimumSeverity),
    );

    const lenses: vscode.CodeLens[] = [];

    for (const det of filtered) {
      // det.line is 1-indexed; vscode lines are 0-indexed
      const lineIndex = (det.line ?? 1) - 1;
      const lineCount = document.lineCount;
      const safeLine = Math.min(Math.max(lineIndex, 0), lineCount - 1);
      const lineLength = document.lineAt(safeLine).text.length;
      const range = new vscode.Range(safeLine, 0, safeLine, lineLength);

      const severityIcon = severityToIcon(det.severity);
      const severityLabel = det.severity.toUpperCase();

      // Lens 1 — severity + type badge (non-interactive label)
      lenses.push(
        new vscode.CodeLens(range, {
          title: `${severityIcon} PasteShield [${severityLabel}]: ${det.type}`,
          command: CODELENS_DETAILS_COMMAND_ID,
          arguments: [[det]],
          tooltip: det.description,
        }),
      );

      // Lens 2 — "View details" action
      lenses.push(
        new vscode.CodeLens(range, {
          title: '$(info) View Details',
          command: CODELENS_DETAILS_COMMAND_ID,
          arguments: [[det]],
          tooltip: 'Open the full security report for this detection',
        }),
      );

      // Lens 3 — "Ignore this pattern" action
      lenses.push(
        new vscode.CodeLens(range, {
          title: '$(mute) Ignore Pattern',
          command: CODELENS_IGNORE_COMMAND_ID,
          arguments: [det.type],
          tooltip: `Add "${det.type}" to pasteShield.ignoredPatterns`,
        }),
      );

      // Lens 4 — "Mark as false positive" action
      lenses.push(
        new vscode.CodeLens(range, {
          title: '$(report) Mark as false positive',
          command: CODELENS_FALSE_POSITIVE_COMMAND_ID,
          arguments: [[det], document.uri],
          tooltip: 'Log this detection as a false positive locally',
        }),
      );
    }

    return lenses;
  }
}

function severityToIcon(severity: Severity): string {
  switch (severity) {
    case 'critical': return '$(error)';
    case 'high':     return '$(shield)';
    case 'medium':   return '$(warning)';
    case 'low':      return '$(info)';
  }
}

// ─── State ────────────────────────────────────────────────────────────────────

let decorationTypes: ReturnType<typeof createDecorationTypes> | undefined;
let lastReport: DetectionResult[] = [];
let statusBarItem: vscode.StatusBarItem | undefined;
let activeDecorations: Array<{
  editor: vscode.TextEditor;
  type: vscode.TextEditorDecorationType;
}> = [];
let codeLensProvider: PasteShieldCodeLensProvider | undefined;
let historyManager: HistoryManager | undefined;
let historyViewProvider: HistoryViewProvider | undefined;
let historyTreeView: vscode.TreeView<HistoryItem> | undefined;
let statisticsManager: StatisticsManager | undefined;
let statisticsPanel: vscode.WebviewPanel | undefined;
let detailsPanel: vscode.WebviewPanel | undefined;
let ignorePatternsManager: IgnorePatternsManager | undefined;
let falsePositiveManager: FalsePositiveManager | undefined;
let extensionContext: vscode.ExtensionContext | undefined;

/**
 * Debounced so rapid editor-tab switching (e.g. Ctrl+Tab held down) doesn't
 * thrash the visible-editors Set rebuild on every intermediate event.
 */
const debouncedPruneDecorations = debounce(pruneStaleDecorations, 150);

/**
 * Debounced CodeLens refresh — avoids hammering the provider on every keystroke.
 */
const debouncedRefreshCodeLens = debounce(() => {
  codeLensProvider?.refresh();
}, 500);

// ─── Activation ───────────────────────────────────────────────────────────────

export function registerPasteShield(context: vscode.ExtensionContext): void {
  extensionContext = context;
  decorationTypes  = createDecorationTypes();
  codeLensProvider = new PasteShieldCodeLensProvider();

  // Initialize History Manager
  historyManager = HistoryManager.getInstance(context);
  historyViewProvider = new HistoryViewProvider(historyManager);

  // Initialize Statistics Manager
  statisticsManager = StatisticsManager.getInstance(historyManager);

  // Initialize Ignore Patterns Manager
  ignorePatternsManager = IgnorePatternsManager.getInstance(context);

  // Initialize False Positive Manager
  falsePositiveManager = FalsePositiveManager.getInstance(context);

  // Register History Tree View in sidebar
  historyTreeView = vscode.window.createTreeView('pasteShieldHistory', {
    treeDataProvider: historyViewProvider,
    showCollapseAll: true,
  });
  context.subscriptions.push(historyTreeView);

  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    90,
  );
  updateStatusBar(true);

  // ── CodeLens registration ──────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.languages.registerCodeLensProvider(
      { scheme: 'file' }, // all files
      codeLensProvider,
    ),
  );

  // CodeLens commands
  context.subscriptions.push(
    vscode.commands.registerCommand(
      CODELENS_DETAILS_COMMAND_ID,
      async (detections: DetectionResult[]) => {
        lastReport = detections;
        await showDetailsPanel(detections);
      },
    ),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(
      CODELENS_IGNORE_COMMAND_ID,
      async (patternName: string) => {
        await addToIgnoredPatterns(patternName);
        codeLensProvider?.refresh();
      },
    ),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(
      CODELENS_FALSE_POSITIVE_COMMAND_ID,
      async (detections: DetectionResult[], documentUri?: vscode.Uri) => {
        await reportFalsePositive(detections, documentUri);
        codeLensProvider?.refresh();
      },
    ),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(
      CODELENS_FIX_COMMAND_ID,
      async (_patternName: string) => {
        // Placeholder: open settings or guide user to rotate the credential
        await vscode.commands.executeCommand(
          'workbench.action.openSettings',
          'pasteShield.ignoredPatterns',
        );
      },
    ),
  );

  // Show detection details from history view
  context.subscriptions.push(
    vscode.commands.registerCommand(
      SHOW_DETECTION_DETAILS_COMMAND_ID,
      async (detection: { type: string; severity: string; category?: string }) => {
        await vscode.window.showInformationMessage(
          `Detection Details\nType: ${detection.type}\nSeverity: ${detection.severity.toUpperCase()}${detection.category ? `\nCategory: ${detection.category}` : ''}`,
          { modal: true }
        );
      },
    ),
  );

  // ── Paste intercept command ────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand(COMMAND_ID, handlePaste),
  );

  // Toggle on/off from status bar or command palette
  context.subscriptions.push(
    vscode.commands.registerCommand(TOGGLE_COMMAND_ID, togglePasteShield),
  );

  // Show last scan report
  context.subscriptions.push(
    vscode.commands.registerCommand(SHOW_REPORT_COMMAND_ID, showLastReport),
  );

  // ── History commands ───────────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand(SHOW_HISTORY_COMMAND_ID, () => {
      if (historyTreeView) {
        historyTreeView.reveal(undefined as unknown as HistoryItem, { focus: true, select: true });
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(CLEAR_HISTORY_COMMAND_ID, async () => {
      const confirm = await vscode.window.showWarningMessage(
        'Are you sure you want to clear all scan history?',
        { modal: true },
        'Clear',
      );
      if (confirm === 'Clear' && historyManager) {
        await historyManager.clearHistory();
        historyViewProvider?.refresh();
        vscode.window.showInformationMessage('PasteShield history cleared.');
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(EXPORT_HISTORY_JSON_COMMAND_ID, async () => {
      if (!historyManager) return;
      await exportHistory('json');
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(EXPORT_HISTORY_TEXT_COMMAND_ID, async () => {
      if (!historyManager) return;
      await exportHistory('text');
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(REFRESH_HISTORY_COMMAND_ID, () => {
      historyViewProvider?.refresh();
    }),
  );

  // Statistics Dashboard command
  context.subscriptions.push(
    vscode.commands.registerCommand(SHOW_STATISTICS_COMMAND_ID, async () => {
      if (!statisticsManager) {
        vscode.window.showWarningMessage('Statistics manager not initialized.');
        return;
      }
      await showStatisticsDashboard();
    }),
  );

  // Export Audit Log command
  context.subscriptions.push(
    vscode.commands.registerCommand(EXPORT_AUDIT_LOG_COMMAND_ID, async () => {
      if (!historyManager) {
        vscode.window.showWarningMessage('History manager not initialized.');
        return;
      }
      await exportAuditLog();
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(EXPORT_FALSE_POSITIVES_COMMAND_ID, async () => {
      if (!falsePositiveManager) {
        vscode.window.showWarningMessage('False positive manager not initialized.');
        return;
      }
      await falsePositiveManager.exportLog();
    }),
  );

  // Show Rotation Reminders command
  context.subscriptions.push(
    vscode.commands.registerCommand(SHOW_ROTATION_REMINDERS_COMMAND_ID, async () => {
      await showRotationReminders();
    }),
  );

  // Add to Workspace Ignore command
  context.subscriptions.push(
    vscode.commands.registerCommand(ADD_TO_WORKSPACE_IGNORE_COMMAND_ID, async (pattern?: string) => {
      if (!ignorePatternsManager) {
        vscode.window.showWarningMessage('Ignore patterns manager not initialized.');
        return;
      }
      
      if (pattern) {
        await ignorePatternsManager.addToWorkspaceIgnore(pattern);
      } else {
        // Prompt user for pattern
        const input = await vscode.window.showInputBox({
          prompt: 'Enter the pattern name to add to workspace ignore list',
          placeHolder: 'e.g., AWS Access Key ID',
        });
        if (input) {
          await ignorePatternsManager.addToWorkspaceIgnore(input);
        }
      }
    }),
  );

  // Watch for workspace file changes to refresh ignore patterns
  const fileWatcher = vscode.workspace.createFileSystemWatcher('**/{.pasteshieldignore,.gitignore}');
  context.subscriptions.push(
    fileWatcher.onDidChange(() => {
      ignorePatternsManager?.refresh();
    }),
    fileWatcher.onDidCreate(() => {
      ignorePatternsManager?.refresh();
    }),
    fileWatcher.onDidDelete(() => {
      ignorePatternsManager?.refresh();
    }),
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration(CONFIG_SECTION)) {
        updateStatusBar(getConfig().enabled);
        codeLensProvider?.refresh();
        historyViewProvider?.refresh();
        ignorePatternsManager?.refresh();
      }
    }),
  );

  // Re-scan open documents when they change (debounced)
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(() => {
      debouncedRefreshCodeLens();
    }),
  );

  // Refresh CodeLens when a new editor becomes active
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(() => {
      debouncedRefreshCodeLens();
    }),
  );

  // Clear decorations when editor closes
  context.subscriptions.push(
    vscode.window.onDidChangeVisibleTextEditors(() => {
      debouncedPruneDecorations();
    }),
  );

  context.subscriptions.push(statusBarItem);
  Object.values(decorationTypes).forEach(dt => context.subscriptions.push(dt));

  statusBarItem.show();
  logger.info('PasteShield: activated');
}

// ─── Core Paste Handler ────────────────────────────────────────────────────────

async function handlePaste(): Promise<void> {
  const config = getConfig();

  // Fast path: feature disabled → delegate immediately
  if (!config.enabled) {
    await executeFallbackPaste();
    return;
  }

  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    await executeFallbackPaste();
    return;
  }

  // ── .env / .env.local exception ───────────────────────────────────────────
  // These files are intentionally used to store secrets locally. PasteShield
  // should not intercept paste operations in them. CodeLens still runs on
  // existing file content to surface any secrets that are already present.
  if (isPasteExcludedFile(editor.document)) {
    logger.info(
      `PasteShield: paste interception skipped for excluded file "${path.basename(editor.document.fileName)}"`,
    );
    await executeFallbackPaste();
    return;
  }

  // Respect ignored languages
  if (config.ignoredLanguages.includes(editor.document.languageId)) {
    await executeFallbackPaste();
    return;
  }

  // Read clipboard
  let clipboardText: string;
  try {
    clipboardText = await vscode.env.clipboard.readText();
  } catch (err) {
    logger.error('PasteShield: clipboard read failed', err);
    await executeFallbackPaste();
    return;
  }

  if (!clipboardText || clipboardText.trim().length === 0) {
    await executeFallbackPaste();
    return;
  }

  // Scan asynchronously to avoid blocking the UI thread
  const detections = await runScanAsync(clipboardText, {
    ignoredPatterns: config.ignoredPatterns,
  });

  // Filter by minimum severity
  const filtered = detections.filter(d =>
    meetsSeverityThreshold(d.severity, config.minimumSeverity),
  );

  if (filtered.length === 0) {
    await executeFallbackPaste();
    return;
  }

  // Persist report for "Show Details" / status bar command
  lastReport = filtered;

  // Silent mode: log to history without blocking paste
  if (config.silentMode) {
    logger.info(`PasteShield: silent mode - logged ${filtered.length} issue(s) to history`);
    
    // Add to history silently
    if (historyManager) {
      await historyManager.addEntry({
        fileName: editor.document.fileName,
        detections: filtered.map(d => ({ type: d.type, severity: d.severity, category: d.category })),
        actionTaken: 'pasted_silent',
      });
      historyViewProvider?.refresh();
    }
    
    // Still paste the content without blocking
    const insertRange = await insertText(editor, clipboardText);
    if (insertRange && config.showInlineDecorations) {
      applyDecoration(editor, insertRange, filtered[0].severity);
    }
    debouncedRefreshCodeLens();
    return;
  }

  // Build warning
  const topSeverity = filtered[0].severity; // already sorted by severity

  const summary = buildSummaryMessage(filtered);

  const choice = await vscode.window.showWarningMessage(
    `PasteShield: ${summary}`,
    'Paste Anyway',
    'Show Details',
    'Mark as false positive',
    'Cancel',
  );

  if (choice === 'Paste Anyway') {
    const insertRange = await insertText(editor, clipboardText);
    if (insertRange && config.showInlineDecorations) {
      applyDecoration(editor, insertRange, topSeverity);
    }
    // Trigger a CodeLens refresh so the pasted secrets are highlighted
    debouncedRefreshCodeLens();
    logger.info(`PasteShield: user bypassed warning (${filtered.length} issue(s))`);
    
    // Add to history
    if (historyManager) {
      await historyManager.addEntry({
        fileName: editor.document.fileName,
        detections: filtered.map(d => ({ type: d.type, severity: d.severity, category: d.category })),
        actionTaken: 'pasted',
      });
      historyViewProvider?.refresh();
    }
    return;
  }

  if (choice === 'Mark as false positive') {
    await reportFalsePositive(filtered, editor.document.uri);
    // After reporting, paste the content
    const insertRange = await insertText(editor, clipboardText);
    if (insertRange && config.showInlineDecorations) {
      applyDecoration(editor, insertRange, topSeverity);
    }
    debouncedRefreshCodeLens();
    logger.info('PasteShield: false positive logged and pasted');
    return;
  }

  if (choice === 'Show Details') {
    await showDetailsPanel(filtered);
    // Re-prompt with modal for a deliberate second confirmation
    const finalChoice = await vscode.window.showWarningMessage(
      `PasteShield — ${filtered.length} issue(s) found. Paste anyway?`,
      { modal: true },
      'Paste Anyway',
    );
    if (finalChoice === 'Paste Anyway') {
      const insertRange = await insertText(editor, clipboardText);
      if (insertRange && config.showInlineDecorations) {
        applyDecoration(editor, insertRange, topSeverity);
      }
      debouncedRefreshCodeLens();
      logger.info('PasteShield: user bypassed warning after details review');
      
      // Add to history
      if (historyManager) {
        await historyManager.addEntry({
          fileName: editor.document.fileName,
          detections: filtered.map(d => ({ type: d.type, severity: d.severity, category: d.category })),
          actionTaken: 'pasted',
        });
        historyViewProvider?.refresh();
      }
    } else {
      logger.info('PasteShield: paste cancelled after details review');
      
      // Add to history
      if (historyManager) {
        await historyManager.addEntry({
          fileName: editor.document.fileName,
          detections: filtered.map(d => ({ type: d.type, severity: d.severity, category: d.category })),
          actionTaken: 'cancelled',
        });
        historyViewProvider?.refresh();
      }
    }
    return;
  }

  // 'Cancel' or dismissed → do nothing
  logger.info('PasteShield: paste cancelled by user');
  
  // Add to history
  if (historyManager) {
    await historyManager.addEntry({
      fileName: editor.document.fileName,
      detections: filtered.map(d => ({ type: d.type, severity: d.severity, category: d.category })),
      actionTaken: 'cancelled',
    });
    historyViewProvider?.refresh();
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Runs the scan in a microtask yield so it doesn't block the event loop.
 */
function runScanAsync(
  text: string,
  options: { ignoredPatterns: string[] },
): Promise<DetectionResult[]> {
  return new Promise(resolve => {
    // setTimeout(0) yields to allow any pending UI updates first
    setTimeout(() => {
      const start = performance.now();
      const results = scanContent(text, options);
      const elapsed = performance.now() - start;
      if (elapsed > 50) {
        logger.warn(`PasteShield: scan took ${elapsed.toFixed(1)} ms (> 50 ms threshold)`);
      }
      resolve(results);
    }, 0);
  });
}

/**
 * Delegates to VS Code's built-in paste via edit builder.
 */
async function executeFallbackPaste(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    return;
  }

  const text = await vscode.env.clipboard.readText();
  if (!text) {
    return;
  }

  await editor.edit(editBuilder => {
    for (const selection of editor.selections) {
      if (selection.isEmpty) {
        editBuilder.insert(selection.active, text);
      } else {
        editBuilder.replace(selection, text);
      }
    }
  });
}

/**
 * Inserts `text` at the current cursor position(s), replacing selections.
 * Returns the range of the first insertion for decoration purposes.
 */
async function insertText(
  editor: vscode.TextEditor,
  text: string,
): Promise<vscode.Range | undefined> {
  let firstRange: vscode.Range | undefined;

  const success = await editor.edit(editBuilder => {
    for (const selection of editor.selections) {
      if (selection.isEmpty) {
        editBuilder.insert(selection.active, text);
        if (!firstRange) {
          firstRange = new vscode.Range(selection.active, selection.active);
        }
      } else {
        editBuilder.replace(selection, text);
        if (!firstRange) {
          firstRange = selection;
        }
      }
    }
  });

  if (!success) {
    logger.error('PasteShield: edit failed — document may be read-only');
    vscode.window.showErrorMessage(
      'PasteShield: Could not paste — document may be read-only.',
    );
  }

  return firstRange;
}

/**
 * Builds a short human-readable summary for the warning message.
 */
function buildSummaryMessage(detections: DetectionResult[]): string {
  const uniqueTypes = [...new Set(detections.map(d => d.type))];
  const countStr = detections.length === 1 ? '1 issue' : `${detections.length} issues`;

  if (uniqueTypes.length === 1) {
    return `${detections[0].description} (${countStr})`;
  }

  const preview = uniqueTypes.slice(0, 2).join(', ');
  const more    = uniqueTypes.length > 2 ? ` +${uniqueTypes.length - 2} more` : '';
  return `${countStr} detected — ${preview}${more}`;
}

/**
 * Opens a side panel with a formatted security report.
 */
async function showDetailsPanel(detections: DetectionResult[]): Promise<void> {
  if (!extensionContext) {
    vscode.window.showWarningMessage('PasteShield context not initialized.');
    return;
  }

  const severityCounts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  detections.forEach(det => {
    severityCounts[det.severity] = (severityCounts[det.severity] || 0) + 1;
  });

  const detailsData = {
    generatedAt: new Date().toLocaleString(),
    totalDetections: detections.length,
    severityCounts,
    detections: detections.map((det, index) => ({
      index: index + 1,
      type: det.type,
      severity: det.severity,
      category: det.category,
      line: det.line,
      description: det.description,
      match: det.match,
    })),
  };

  const codiconsRoot = vscode.Uri.joinPath(
    extensionContext.extensionUri,
    'node_modules',
    '@vscode',
    'codicons',
    'dist',
  );

  if (!detailsPanel) {
    detailsPanel = vscode.window.createWebviewPanel(
      'pasteShieldDetails',
      'PasteShield Scan Report',
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        localResourceRoots: [codiconsRoot],
      },
    );

    detailsPanel.onDidDispose(() => {
      detailsPanel = undefined;
    });

    // Handle messages from the webview
    detailsPanel.webview.onDidReceiveMessage(async (message) => {
      if (message.command === 'downloadReport') {
        const content = JSON.stringify(message.data, null, 2);
        const defaultFileName = `pasteshield-report-${new Date().toISOString().split('T')[0]}.json`;
        const uri = await vscode.window.showSaveDialog({
          defaultUri: vscode.Uri.file(defaultFileName),
          filters: { JSON: ['json'] },
        });
        if (uri) {
          await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf8'));
          vscode.window.showInformationMessage(`Report downloaded to ${uri.fsPath}`);
        }
      }
    });
  } else {
    detailsPanel.reveal(vscode.ViewColumn.Beside, true);
  }

  const codiconsUri = detailsPanel.webview.asWebviewUri(
    vscode.Uri.joinPath(codiconsRoot, 'codicon.css'),
  );

  detailsPanel.webview.html = buildDetailsWebviewHtml(
    detailsPanel.webview,
    codiconsUri,
    detailsData,
  );
}

/**
 * Adds `patternName` to the `pasteShield.ignoredPatterns` setting globally.
 */
async function addToIgnoredPatterns(patternName: string): Promise<void> {
  const config  = vscode.workspace.getConfiguration(CONFIG_SECTION);
  const current = config.get<string[]>('ignoredPatterns', []);

  if (current.includes(patternName)) {
    vscode.window.showInformationMessage(
      `PasteShield: "${patternName}" is already ignored.`,
    );
    return;
  }

  await config.update(
    'ignoredPatterns',
    [...current, patternName],
    vscode.ConfigurationTarget.Global,
  );

  vscode.window.showInformationMessage(
    `PasteShield: Pattern "${patternName}" added to ignored list.`,
  );
}

/**
 * Logs false positives locally for later analysis.
 */
async function reportFalsePositive(
  detections: DetectionResult[],
  documentUri?: vscode.Uri,
): Promise<void> {
  if (!falsePositiveManager || detections.length === 0) {
    return;
  }

  const patternTypes = [...new Set(detections.map(d => d.type))];
  let selectedPatterns: string[] = [];

  if (patternTypes.length === 1) {
    selectedPatterns = patternTypes;
  } else {
    const selected = await vscode.window.showQuickPick(
      patternTypes.map(p => ({ label: p, description: 'Log as false positive' })),
      {
        placeHolder: 'Select patterns to mark as false positives',
        canPickMany: true,
      }
    );
    if (selected && selected.length > 0) {
      selectedPatterns = selected.map(item => item.label);
    }
  }

  if (selectedPatterns.length === 0) {
    return;
  }

  const loggedCount = await falsePositiveManager.recordFalsePositives(
    selectedPatterns,
    documentUri,
  );

  if (loggedCount > 0) {
    vscode.window.showInformationMessage(
      `PasteShield: logged ${loggedCount} false positive(s) to .pasteshield-fp.json.`,
    );
  }
}

/**
 * Applies a short-lived inline decoration at `range` in `editor`.
 * Auto-clears after 10 seconds.
 */
function applyDecoration(
  editor: vscode.TextEditor,
  range: vscode.Range,
  severity: Severity,
): void {
  if (!decorationTypes) {
    return;
  }
  const dt = decorationTypes[severity];
  editor.setDecorations(dt, [range]);
  activeDecorations.push({ editor, type: dt });

  setTimeout(() => {
    editor.setDecorations(dt, []);
    activeDecorations = activeDecorations.filter(
      d => !(d.editor === editor && d.type === dt),
    );
  }, 10_000);
}

/**
 * Removes decorations for editors that are no longer visible.
 */
function pruneStaleDecorations(): void {
  const visibleEditors = new Set(vscode.window.visibleTextEditors);
  activeDecorations = activeDecorations.filter(({ editor, type }) => {
    if (!visibleEditors.has(editor)) {
      editor.setDecorations(type, []);
      return false;
    }
    return true;
  });
}

// ─── Toggle & Status Bar ──────────────────────────────────────────────────────

function updateStatusBar(enabled: boolean): void {
  if (!statusBarItem) {
    return;
  }
  if (enabled) {
    statusBarItem.text            = '$(shield)';
    statusBarItem.tooltip         = 'PasteShield is active — click to toggle or view last report';
    statusBarItem.color           = undefined;
    statusBarItem.backgroundColor = undefined;
  } else {
    statusBarItem.text            = '$(shield)';
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    statusBarItem.tooltip         = 'PasteShield is disabled — click to enable';
    statusBarItem.color           = new vscode.ThemeColor('statusBarItem.warningForeground');
  }
  statusBarItem.command = TOGGLE_COMMAND_ID;
}

async function togglePasteShield(): Promise<void> {
  const config  = vscode.workspace.getConfiguration(CONFIG_SECTION);
  const current = config.get<boolean>('enabled', true);
  await config.update('enabled', !current, vscode.ConfigurationTarget.Global);
  const next = !current;
  updateStatusBar(next);
  // Refresh CodeLens to hide/show lenses based on the new enabled state
  codeLensProvider?.refresh();
  vscode.window.withProgress(
    {
      location:    vscode.ProgressLocation.Notification,
      title:       `PasteShield ${next ? 'enabled' : 'disabled'}.`,
      cancellable: false,
    },
    () => new Promise<void>(resolve => setTimeout(resolve, 2500)),
  );
}

async function exportHistory(format: 'json' | 'text'): Promise<void> {
  if (!historyManager) {
    vscode.window.showWarningMessage('History manager not initialized.');
    return;
  }

  const content = format === 'json' 
    ? historyManager.exportAsJson() 
    : historyManager.exportAsText();
  
  const extension = format === 'json' ? 'json' : 'txt';
  const defaultFileName = `pasteshield-history-${new Date().toISOString().split('T')[0]}.${extension}`;

  const uri = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(defaultFileName),
    filters: {
      [format.toUpperCase()]: [extension],
    },
  });

  if (uri) {
    await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf8'));
    vscode.window.showInformationMessage(`History exported to ${uri.fsPath}`);
  }
}

async function showLastReport(): Promise<void> {
  if (lastReport.length === 0) {
    vscode.window.withProgress(
      {
        location:    vscode.ProgressLocation.Notification,
        title:       'PasteShield: No scan report available yet.',
        cancellable: false,
      },
      () => new Promise<void>(resolve => setTimeout(resolve, 2500)),
    );
    return;
  }
  await showDetailsPanel(lastReport);
}

/**
 * Show statistics dashboard in a side panel
 */
async function showStatisticsDashboard(): Promise<void> {
  if (!statisticsManager) return;

  const falsePositiveStats = falsePositiveManager
    ? await falsePositiveManager.getStats()
    : undefined;

  const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
  const statsMode = config.get<'visual' | 'ascii'>('statsMode', 'visual');

  if (statsMode === 'ascii') {
    const report = statisticsManager.generateReport(falsePositiveStats);
    const doc = await vscode.workspace.openTextDocument({
      content: report,
      language: 'plaintext',
    });

    await vscode.window.showTextDocument(doc, {
      preview: true,
      viewColumn: vscode.ViewColumn.Beside,
      preserveFocus: false,
    });
    return;
  }

  if (!extensionContext) {
    vscode.window.showWarningMessage('PasteShield context not initialized.');
    return;
  }

  const summary = statisticsManager.getSummary();
  const dailyStats = statisticsManager.getDailyStats(7);
  const riskScore = statisticsManager.getRiskScore();

  const webviewData = {
    generatedAt: new Date().toLocaleString(),
    riskScore,
    summary: {
      totalScans: summary.totalScans,
      totalDetections: summary.totalDetections,
      threatsBlocked: summary.threatsBlocked,
      pastedCount: summary.pastedCount,
      averageDetectionsPerScan: summary.averageDetectionsPerScan,
    },
    severityBreakdown: [
      { label: 'Critical', value: summary.criticalCount, color: '#e74c3c' },
      { label: 'High', value: summary.highCount, color: '#f39c12' },
      { label: 'Medium', value: summary.mediumCount, color: '#f1c40f' },
      { label: 'Low', value: summary.lowCount, color: '#2ecc71' },
    ],
    dailyTrend: dailyStats.map(day => ({
      date: day.date,
      detections: day.detections,
    })),
    topCategories: summary.topCategories.slice(0, 5),
    falsePositiveSummary: falsePositiveStats
      ? {
          total: falsePositiveStats.total,
          topPatterns: falsePositiveStats.topPatterns,
        }
      : { total: 0, topPatterns: [] },
  };

  const chartJsRoot = vscode.Uri.joinPath(
    extensionContext.extensionUri,
    'node_modules',
    'chart.js',
    'dist',
  );
  const codiconsRoot = vscode.Uri.joinPath(
    extensionContext.extensionUri,
    'node_modules',
    '@vscode',
    'codicons',
    'dist',
  );

  if (!statisticsPanel) {
    statisticsPanel = vscode.window.createWebviewPanel(
      'pasteShieldStatistics',
      'PasteShield Statistics',
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        localResourceRoots: [chartJsRoot, codiconsRoot],
      },
    );

    statisticsPanel.onDidDispose(() => {
      statisticsPanel = undefined;
    });

    // Handle messages from the webview
    statisticsPanel.webview.onDidReceiveMessage(async (message) => {
      if (message.command === 'downloadStatistics') {
        const content = JSON.stringify(message.data, null, 2);
        const defaultFileName = `pasteshield-statistics-${new Date().toISOString().split('T')[0]}.json`;
        const uri = await vscode.window.showSaveDialog({
          defaultUri: vscode.Uri.file(defaultFileName),
          filters: { JSON: ['json'] },
        });
        if (uri) {
          await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf8'));
          vscode.window.showInformationMessage(`Statistics downloaded to ${uri.fsPath}`);
        }
      }
    });
  } else {
    statisticsPanel.reveal(vscode.ViewColumn.Beside, true);
  }

  const chartJsUri = statisticsPanel.webview.asWebviewUri(
    vscode.Uri.joinPath(chartJsRoot, 'chart.umd.js'),
  );
  const codiconsUri = statisticsPanel.webview.asWebviewUri(
    vscode.Uri.joinPath(codiconsRoot, 'codicon.css'),
  );

  statisticsPanel.webview.html = buildStatisticsWebviewHtml(
    statisticsPanel.webview,
    chartJsUri,
    codiconsUri,
    webviewData,
  );
}

function buildStatisticsWebviewHtml(
  webview: vscode.Webview,
  chartJsUri: vscode.Uri,
  codiconsUri: vscode.Uri,
  data: {
    generatedAt: string;
    riskScore: number;
    summary: {
      totalScans: number;
      totalDetections: number;
      threatsBlocked: number;
      pastedCount: number;
      averageDetectionsPerScan: number;
    };
    severityBreakdown: Array<{ label: string; value: number; color: string }>;
    dailyTrend: Array<{ date: string; detections: number }>;
    topCategories: Array<{ category: string; count: number }>;
    falsePositiveSummary: { total: number; topPatterns: Array<{ patternName: string; count: number }> };
  },
): string {
  const nonce = getNonce();
  const safeData = JSON.stringify(data).replace(/</g, '\\u003c');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${webview.cspSource} data:; style-src ${webview.cspSource} 'nonce-${nonce}'; font-src ${webview.cspSource}; script-src ${webview.cspSource} 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PasteShield Statistics</title>
  <link rel="stylesheet" href="${codiconsUri}">
  <style nonce="${nonce}">
    :root {
      --bg: var(--vscode-editor-background);
      --fg: var(--vscode-editor-foreground);
      --muted: var(--vscode-descriptionForeground);
      --panel: var(--vscode-editorWidget-background);
      --panel-alt: var(--vscode-sideBar-background);
      --border: var(--vscode-editorWidget-border);
      --accent: var(--vscode-textLink-foreground);
      --accent-strong: var(--vscode-textLink-activeForeground);
      --shadow: rgba(0, 0, 0, 0.12);
      --risk-green: var(--vscode-testing-iconPassed, #2ecc71);
      --risk-amber: var(--vscode-testing-iconQueued, #f39c12);
      --risk-red: var(--vscode-testing-iconFailed, #e74c3c);
      --chart-grid: rgba(127, 127, 127, 0.25);
      --radius-lg: 5px;
      --radius-md: 4px;
      --radius-sm: 3px;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      color: var(--fg);
      background: var(--bg);
      font-family: var(--vscode-font-family);
      font-size: 13px;
    }

    body::before,
    body::after {
      content: '';
      position: fixed;
      inset: 0;
      pointer-events: none;
      z-index: 0;
    }

    body::before {
      background:
        radial-gradient(800px 360px at 10% -10%, var(--accent), transparent 65%),
        radial-gradient(700px 320px at 90% -20%, var(--accent-strong), transparent 70%);
      opacity: 0.04;
    }

    body::after {
      background: linear-gradient(180deg, rgba(127, 127, 127, 0.08) 0%, transparent 40%);
      opacity: 0.2;
    }

    .shell {
      position: relative;
      z-index: 1;
      padding: 10px 6px 16px;
      width: 100%;
      height: 100%;
      display: flex;
      flex-direction: column;
    }

    .hero {
      display: grid;
      grid-template-columns: 1fr;
      gap: 12px;
      align-items: stretch;
      margin-bottom: 12px;
      grid-template-areas: 'header' 'risk';
    }

    .hero-header {
      grid-area: header;
    }

    .hero-risk {
      grid-area: risk;
    }

    .hero-top {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
    }

    .hero-top h1 {
      flex: 1;
      margin: 0;
      font-size: 18px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }

    .hero-top .btn {
      margin-top: 2px;
    }

    .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      color: var(--muted);
      font-size: 11px;
    }

    .meta span {
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }

    .brand {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 8px;
      border-radius: 3px;
      background: rgba(127, 127, 127, 0.1);
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.15em;
      font-weight: 600;
      width: fit-content;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 4px 10px;
      border-radius: 2px;
      background: var(--accent);
      color: var(--bg);
      border: none;
      cursor: pointer;
      font-size: 11px;
      font-weight: 600;
      white-space: nowrap;
      transition: opacity 0.2s;
    }

    .btn:hover {
      opacity: 0.8;
    }

    .risk-card {
      position: relative;
      background: linear-gradient(135deg, rgba(127, 127, 127, 0.1), rgba(127, 127, 127, 0.04));
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 12px 14px;
      overflow: hidden;
      box-shadow: 0 4px 8px var(--shadow);
      grid-area: risk;
    }

    .risk-card::before {
      content: '';
      position: absolute;
      inset: 0;
      border-radius: inherit;
      background: linear-gradient(120deg, rgba(127, 127, 127, 0.1), transparent 60%);
      opacity: 0.3;
      pointer-events: none;
    }

    .risk-title {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.15em;
      color: var(--muted);
      font-weight: 600;
    }

    .risk-score {
      font-size: 28px;
      font-weight: 700;
      margin: 6px 0 2px;
      font-family: var(--vscode-editor-font-family);
    }

    .risk-status {
      font-size: 11px;
      color: var(--muted);
    }

    .risk-track {
      margin-top: 8px;
      height: 4px;
      border-radius: 2px;
      background: rgba(127, 127, 127, 0.15);
      overflow: hidden;
    }

    .risk-track span {
      display: block;
      height: 100%;
      width: 0;
      background: var(--risk-green);
      transition: width 0.8s ease;
    }

    .risk-card[data-risk='amber'] .risk-track span { background: var(--risk-amber); }
    .risk-card[data-risk='red'] .risk-track span { background: var(--risk-red); }

    .kpi-grid {
      margin-top: 12px;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }

    @media (max-width: 1200px) {
      .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .main-grid {
        grid-template-columns: 1fr;
        grid-template-areas:
          'trend'
          'severity'
          'categories'
          'falsePositives'
          'insights';
      }
    }

    @media (max-width: 800px) {
      .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .main-grid {
        grid-template-columns: 1fr;
        grid-template-areas:
          'trend'
          'severity'
          'categories'
          'falsePositives'
          'insights';
      }
    }

    @media (max-width: 500px) {
      .kpi-grid { grid-template-columns: 1fr; }
      .main-grid {
        grid-template-columns: 1fr;
        grid-template-areas:
          'trend'
          'severity'
          'categories'
          'falsePositives'
          'insights';
      }
      .shell { padding: 12px 12px 16px; }
    }

    .kpi-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 10px 8px;
      display: grid;
      gap: 4px;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.08);
      animation: rise 0.6s ease forwards;
    }

    .kpi-label {
      display: flex;
      align-items: center;
      gap: 4px;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.15em;
      color: var(--muted);
      font-weight: 600;
    }

    .kpi-value {
      font-size: 16px;
      font-weight: 700;
      font-family: var(--vscode-editor-font-family);
    }

    .kpi-sub {
      font-size: 10px;
      color: var(--muted);
      line-height: 1.3;
    }

    .main-grid {
      margin-top: 12px;
      display: grid;
      grid-template-columns: 1.4fr 1fr;
      grid-template-areas:
        'trend severity'
        'trend categories'
        'insights falsePositives';
      gap: 10px;
    }

    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 10px 8px;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.08);
    }

    .card h2 {
      margin: 0 0 8px;
      font-size: 13px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .card h2 .codicon { color: var(--accent); }

    .trend-card { grid-area: trend; }
    .severity-card { grid-area: severity; }
    .categories-card { grid-area: categories; }
    .insights-card { grid-area: insights; }
    .false-positives-card { grid-area: falsePositives; }

    .trend-canvas { height: 180px; }
    .trend-canvas canvas { width: 100% !important; height: 100% !important; }

    .donut-wrap {
      display: grid;
      place-items: center;
      position: relative;
      min-height: 160px;
    }

    .donut-canvas { width: 140px; height: 140px; }

    .donut-center {
      position: absolute;
      text-align: center;
    }

    .donut-total {
      font-size: 22px;
      font-weight: 700;
      font-family: var(--vscode-editor-font-family);
    }

    .donut-caption {
      font-size: 10px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.15em;
      font-weight: 600;
    }

    .pill-row {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 8px;
    }

    .pill {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 8px;
      border-radius: 3px;
      background: rgba(127, 127, 127, 0.1);
      font-size: 11px;
      color: var(--muted);
    }

    .legend {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 6px;
      margin-top: 8px;
    }

    .legend-item {
      display: flex;
      align-items: center;
      gap: 4px;
      font-size: 11px;
      color: var(--muted);
    }

    .legend-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      flex-shrink: 0;
    }

    .category-list { display: grid; gap: 8px; }

    .false-positive-list { display: grid; gap: 8px; }

    .false-positive-item {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
      align-items: center;
      font-size: 12px;
    }

    .false-positive-name { font-weight: 600; }
    .false-positive-count { color: var(--muted); font-variant-numeric: tabular-nums; }

    .category-item {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
      align-items: center;
      font-size: 12px;
    }

    .category-name { font-weight: 600; }
    .category-count { color: var(--muted); font-variant-numeric: tabular-nums; }

    .category-bar {
      grid-column: 1 / -1;
      height: 4px;
      background: rgba(127, 127, 127, 0.12);
      border-radius: 2px;
      overflow: hidden;
    }

    .category-bar span {
      display: block;
      height: 100%;
      width: 0;
      background: linear-gradient(90deg, var(--accent), rgba(127, 127, 127, 0.2));
      transition: width 0.8s ease;
    }

    .insights {
      display: grid;
      gap: 6px;
    }

    .insight {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      padding: 8px;
      border-radius: var(--radius-sm);
      background: rgba(127, 127, 127, 0.08);
      color: var(--muted);
      font-size: 11px;
      line-height: 1.4;
    }

    .empty-state {
      font-size: 12px;
      color: var(--muted);
      border: 1px dashed var(--border);
      border-radius: 4px;
      padding: 10px;
      text-align: center;
      background: rgba(127, 127, 127, 0.04);
    }

    @keyframes rise {
      from { opacity: 0; transform: translateY(4px); }
      to { opacity: 1; transform: translateY(0); }
    }
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <div class="hero-header">
        <div class="hero-top">
          <div>
            <div class="brand"><span class="codicon codicon-shield"></span> PasteShield</div>
            <h1>Statistics Dashboard</h1>
            <div class="meta">
              <span><span class="codicon codicon-calendar"></span>Generated ${data.generatedAt}</span>
              <span><span class="codicon codicon-pulse"></span>7-day signal</span>
            </div>
          </div>
          <button class="btn" id="downloadBtn" title="Download statistics as JSON">
            <span class="codicon codicon-download"></span>
            Download
          </button>
        </div>
        <div class="pill-row" id="severityPills"></div>
      </div>
      <div class="hero-risk" id="riskCard">
        <div class="risk-title"><span class="codicon codicon-dashboard"></span> Risk Score</div>
        <div class="risk-score" id="riskScore">--</div>
        <div class="risk-status" id="riskLabel">Analyzing exposure</div>
        <div class="risk-track"><span id="riskFill"></span></div>
      </div>
    </section>

    <section class="kpi-grid">
      <div class="kpi-card" style="animation-delay: 0.05s;">
        <div class="kpi-label"><span class="codicon codicon-search"></span>Total Scans</div>
        <div class="kpi-value" id="totalScans">0</div>
        <div class="kpi-sub">Clipboard inspections across this workspace.</div>
      </div>
      <div class="kpi-card" style="animation-delay: 0.1s;">
        <div class="kpi-label"><span class="codicon codicon-warning"></span>Detections</div>
        <div class="kpi-value" id="totalDetections">0</div>
        <div class="kpi-sub">Total risky patterns detected.</div>
      </div>
      <div class="kpi-card" style="animation-delay: 0.15s;">
        <div class="kpi-label"><span class="codicon codicon-shield"></span>Threats Blocked</div>
        <div class="kpi-value" id="threatsBlocked">0</div>
        <div class="kpi-sub">Stops triggered by PasteShield.</div>
      </div>
      <div class="kpi-card" style="animation-delay: 0.2s;">
        <div class="kpi-label"><span class="codicon codicon-graph"></span>Avg per Scan</div>
        <div class="kpi-value" id="averagePerScan">0</div>
        <div class="kpi-sub">Mean detections per scan.</div>
      </div>
    </section>

    <section class="main-grid">
      <div class="card trend-card">
        <h2><span class="codicon codicon-graph"></span>7-Day Detection Trend</h2>
        <div class="trend-canvas">
          <canvas id="trendChart" role="img" aria-label="Seven day detection trend"></canvas>
        </div>
      </div>

      <div class="card severity-card">
        <h2><span class="codicon codicon-pie-chart"></span>Severity Breakdown</h2>
        <div class="donut-wrap">
          <canvas class="donut-canvas" id="severityChart" width="200" height="200" role="img" aria-label="Severity breakdown chart"></canvas>
          <div class="donut-center">
            <div class="donut-total" id="severityTotal">0</div>
            <div class="donut-caption">detections</div>
          </div>
        </div>
        <div class="legend" id="severityLegend"></div>
      </div>

      <div class="card categories-card">
        <h2><span class="codicon codicon-list-selection"></span>Top Categories</h2>
        <div class="category-list" id="categoryList"></div>
      </div>

      <div class="card false-positives-card">
        <h2><span class="codicon codicon-thumbsup"></span>False Positives</h2>
        <div class="false-positive-list" id="falsePositiveList"></div>
      </div>

      <div class="card insights-card">
        <h2><span class="codicon codicon-lightbulb"></span>Key Insights</h2>
        <div class="insights" id="insightList"></div>
      </div>
    </section>
  </div>

  <script nonce="${nonce}" src="${chartJsUri}"></script>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const data = ${safeData};
    const formatNumber = value => new Intl.NumberFormat().format(value);
    
    // Download functionality
    document.getElementById('downloadBtn').addEventListener('click', () => {
      const statsData = {
        generatedAt: data.generatedAt,
        riskScore: data.riskScore,
        summary: data.summary,
        severityBreakdown: data.severityBreakdown,
        dailyTrend: data.dailyTrend,
        topCategories: data.topCategories,
        falsePositiveSummary: data.falsePositiveSummary,
      };
      vscode.postMessage({
        command: 'downloadStatistics',
        data: statsData,
      });
    });

    const styles = getComputedStyle(document.documentElement);
    const fgColor = styles.getPropertyValue('--fg').trim() || '#e0e0e0';
    const mutedColor = styles.getPropertyValue('--muted').trim() || '#9aa0a6';
    const gridColor = styles.getPropertyValue('--chart-grid').trim() || 'rgba(127, 127, 127, 0.2)';
    const panelColor = styles.getPropertyValue('--panel').trim() || '#1e1e1e';

    if (window.Chart) {
      Chart.defaults.color = mutedColor;
      Chart.defaults.font.family = styles.getPropertyValue('--vscode-font-family').trim() || 'Segoe UI';
    }

    const riskScoreEl = document.getElementById('riskScore');
    const riskCard = document.getElementById('riskCard');
    const riskFill = document.getElementById('riskFill');
    const riskLabel = document.getElementById('riskLabel');
    riskScoreEl.textContent = formatNumber(data.riskScore);
    riskFill.style.width = Math.min(100, data.riskScore) + '%';
    if (data.riskScore >= 67) {
      riskCard.dataset.risk = 'red';
      riskLabel.textContent = 'High exposure - tighten controls';
    } else if (data.riskScore >= 34) {
      riskCard.dataset.risk = 'amber';
      riskLabel.textContent = 'Moderate exposure - monitor closely';
    } else {
      riskCard.dataset.risk = 'green';
      riskLabel.textContent = 'Low exposure - healthy baseline';
    }

    document.getElementById('totalScans').textContent = formatNumber(data.summary.totalScans);
    document.getElementById('totalDetections').textContent = formatNumber(data.summary.totalDetections);
    document.getElementById('threatsBlocked').textContent = formatNumber(data.summary.threatsBlocked);
    document.getElementById('averagePerScan').textContent = data.summary.averageDetectionsPerScan.toFixed(2);

    const severityTotal = data.severityBreakdown.reduce((sum, item) => sum + item.value, 0);
    document.getElementById('severityTotal').textContent = formatNumber(severityTotal);
    const severityLabels = data.severityBreakdown.map(item => item.label);
    const severityValues = data.severityBreakdown.map(item => item.value);
    const severityColors = data.severityBreakdown.map(item => item.color);
    const severityChartCtx = document.getElementById('severityChart');
    if (severityChartCtx) {
      const ctx = severityChartCtx.getContext('2d');
      if (ctx) {
        new Chart(ctx, {
          type: 'doughnut',
          data: {
            labels: severityLabels,
            datasets: [{
              data: severityValues,
              backgroundColor: severityColors,
              borderColor: panelColor,
              borderWidth: 2,
              hoverOffset: 6,
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '72%',
            plugins: {
              legend: { display: false },
              tooltip: {
                backgroundColor: panelColor,
                titleColor: fgColor,
                bodyColor: fgColor,
                borderColor: gridColor,
                borderWidth: 1,
                padding: 8,
                titleFont: { size: 11 },
                bodyFont: { size: 11 },
              },
            },
          },
        });
      }
    }

    const pills = document.getElementById('severityPills');
    data.severityBreakdown.forEach(item => {
      const pill = document.createElement('div');
      pill.className = 'pill';
      const dot = document.createElement('span');
      dot.className = 'legend-dot';
      dot.style.background = item.color;
      const text = document.createElement('span');
      text.textContent = item.label + ' ' + formatNumber(item.value);
      pill.appendChild(dot);
      pill.appendChild(text);
      pills.appendChild(pill);
    });

    const legend = document.getElementById('severityLegend');
    data.severityBreakdown.forEach(item => {
      const row = document.createElement('div');
      row.className = 'legend-item';
      const dot = document.createElement('span');
      dot.className = 'legend-dot';
      dot.style.background = item.color;
      const text = document.createElement('span');
      text.textContent = item.label + ' (' + formatNumber(item.value) + ')';
      row.appendChild(dot);
      row.appendChild(text);
      legend.appendChild(row);
    });

    const trendLabels = data.dailyTrend.map(day => {
      const parts = day.date.split('-').map(Number);
      const localDate = new Date(parts[0], (parts[1] || 1) - 1, parts[2] || 1);
      return localDate.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    });
    const trendValues = data.dailyTrend.map(day => day.detections);
    const trendCanvas = document.getElementById('trendChart');
    if (trendCanvas) {
      const ctx = trendCanvas.getContext('2d');
      if (ctx) {
        const gradient = ctx.createLinearGradient(0, 0, 0, 260);
        gradient.addColorStop(0, 'rgba(46, 204, 113, 0.95)');
        gradient.addColorStop(1, 'rgba(46, 204, 113, 0.15)');

        new Chart(ctx, {
          type: 'bar',
          data: {
            labels: trendLabels,
            datasets: [{
              label: 'Detections',
              data: trendValues,
              backgroundColor: gradient,
              borderRadius: 2,
              borderSkipped: false,
              maxBarThickness: 24,
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { display: false },
              tooltip: {
                backgroundColor: panelColor,
                titleColor: fgColor,
                bodyColor: fgColor,
                borderColor: gridColor,
                borderWidth: 1,
                padding: 8,
                titleFont: { size: 11 },
                bodyFont: { size: 11 },
              },
            },
            scales: {
              x: {
                ticks: { color: mutedColor, font: { size: 11 } },
                grid: { display: false },
              },
              y: {
                ticks: { color: mutedColor, precision: 0, font: { size: 10 } },
                grid: { color: gridColor, drawBorder: false },
                beginAtZero: true,
              },
            },
          },
        });
      }
    }

    const categoryList = document.getElementById('categoryList');
    if (!data.topCategories.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'No detections yet. PasteShield will surface categories after the first scans.';
      categoryList.appendChild(empty);
    } else {
      const maxCount = Math.max(...data.topCategories.map(item => item.count), 1);
      data.topCategories.forEach(item => {
        const row = document.createElement('div');
        row.className = 'category-item';

        const name = document.createElement('span');
        name.className = 'category-name';
        name.textContent = item.category;

        const count = document.createElement('span');
        count.className = 'category-count';
        count.textContent = formatNumber(item.count);

        const barWrap = document.createElement('div');
        barWrap.className = 'category-bar';
        const bar = document.createElement('span');
        barWrap.appendChild(bar);

        row.appendChild(name);
        row.appendChild(count);
        row.appendChild(barWrap);
        categoryList.appendChild(row);

        const widthPercent = Math.round((item.count / maxCount) * 100);
        requestAnimationFrame(() => {
          bar.style.width = String(widthPercent) + '%';
        });
      });
    }

    const falsePositiveList = document.getElementById('falsePositiveList');
    if (!data.falsePositiveSummary.topPatterns.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'No false positives logged yet. Use "Mark as false positive" to populate this list.';
      falsePositiveList.appendChild(empty);
    } else {
      data.falsePositiveSummary.topPatterns.forEach(item => {
        const row = document.createElement('div');
        row.className = 'false-positive-item';

        const name = document.createElement('span');
        name.className = 'false-positive-name';
        name.textContent = item.patternName;

        const count = document.createElement('span');
        count.className = 'false-positive-count';
        count.textContent = formatNumber(item.count);

        row.appendChild(name);
        row.appendChild(count);
        falsePositiveList.appendChild(row);
      });
    }

    const insightList = document.getElementById('insightList');
    const sevenDayTotal = data.dailyTrend.reduce((sum, day) => sum + day.detections, 0);
    const insightItems = [
      { icon: 'codicon-check', text: formatNumber(data.summary.threatsBlocked) + ' threats blocked before paste.' },
      { icon: 'codicon-history', text: formatNumber(sevenDayTotal) + ' detections recorded over the last 7 days.' },
      { icon: 'codicon-debug-continue', text: formatNumber(data.summary.pastedCount) + ' pastes proceeded after warning.' },
    ];
    insightItems.forEach(item => {
      const row = document.createElement('div');
      row.className = 'insight';
      const icon = document.createElement('span');
      icon.className = 'codicon ' + item.icon;
      const text = document.createElement('span');
      text.textContent = item.text;
      row.appendChild(icon);
      row.appendChild(text);
      insightList.appendChild(row);
    });
  </script>
</body>
</html>`;
}

function buildDetailsWebviewHtml(
  webview: vscode.Webview,
  codiconsUri: vscode.Uri,
  data: {
    generatedAt: string;
    totalDetections: number;
    severityCounts: Record<string, number>;
    detections: Array<{
      index: number;
      type: string;
      severity: string;
      category?: string;
      line?: number;
      description: string;
      match: string;
    }>;
  },
): string {
  const nonce = getNonce();
  const safeData = JSON.stringify(data).replace(/</g, '\\u003c');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${webview.cspSource} data:; style-src ${webview.cspSource} 'nonce-${nonce}'; font-src ${webview.cspSource}; script-src ${webview.cspSource} 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PasteShield Report</title>
  <link rel="stylesheet" href="${codiconsUri}">
  <style nonce="${nonce}">
    :root {
      --bg: var(--vscode-editor-background);
      --fg: var(--vscode-editor-foreground);
      --muted: var(--vscode-descriptionForeground);
      --panel: var(--vscode-editorWidget-background);
      --border: var(--vscode-editorWidget-border);
      --accent: var(--vscode-textLink-foreground);
      --critical: var(--vscode-errorForeground, #e74c3c);
      --high: var(--vscode-editorWarning-foreground, #f39c12);
      --medium: var(--vscode-editorInfo-foreground, #f1c40f);
      --low: var(--vscode-editorHint-foreground, #2ecc71);
      --radius-lg: 5px;
      --radius-md: 4px;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      color: var(--fg);
      background: var(--bg);
      font-family: var(--vscode-font-family);
      font-size: 13px;
    }

    body::before {
      content: '';
      position: fixed;
      inset: 0;
      background: radial-gradient(700px 320px at 8% -10%, var(--accent), transparent 70%);
      opacity: 0.04;
      pointer-events: none;
    }

    .shell {
      position: relative;
      z-index: 1;
      padding: 10px 6px 16px;
      width: 100%;
      height: 100%;
      display: flex;
      flex-direction: column;
    }

    .hero {
      display: grid;
      gap: 6px;
      margin-bottom: 10px;
      align-items: start;
      grid-template-columns: 1fr auto;
    }

    .hero-content {
      display: grid;
      gap: 6px;
    }

    .hero-actions {
      display: flex;
      gap: 6px;
      align-items: center;
    }

    .brand {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 8px;
      border-radius: 3px;
      background: rgba(127, 127, 127, 0.1);
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.15em;
      font-weight: 600;
      width: fit-content;
    }

    h1 {
      margin: 0;
      font-size: 16px;
      font-weight: 700;
    }

    .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      color: var(--muted);
      font-size: 10px;
    }

    .meta span {
      display: inline-flex;
      align-items: center;
      gap: 3px;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 4px 10px;
      border-radius: 2px;
      background: var(--accent);
      color: var(--bg);
      border: none;
      cursor: pointer;
      font-size: 11px;
      font-weight: 600;
      white-space: nowrap;
      transition: opacity 0.2s;
    }

    .btn:hover {
      opacity: 0.8;
    }

    .summary-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
      margin: 10px 0 12px;
    }

    .summary-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 8px 6px;
      display: grid;
      gap: 3px;
    }

    .summary-card .label {
      font-size: 9px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: var(--muted);
      display: inline-flex;
      align-items: center;
      gap: 3px;
    }

    .summary-card .value {
      font-size: 14px;
      font-weight: 700;
      font-family: var(--vscode-editor-font-family);
    }

    .detections {
      display: grid;
      gap: 8px;
    }

    .detection-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 8px 6px;
      display: grid;
      gap: 5px;
    }

    .detection-header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
      justify-content: space-between;
    }

    .detection-title {
      display: flex;
      align-items: center;
      gap: 4px;
      font-weight: 700;
      font-size: 12px;
    }

    .severity-pill {
      padding: 1px 5px;
      border-radius: 2px;
      font-size: 9px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-weight: 700;
      background: rgba(127, 127, 127, 0.08);
    }

    .severity-critical { color: var(--critical); }
    .severity-high { color: var(--high); }
    .severity-medium { color: var(--medium); }
    .severity-low { color: var(--low); }

    .detection-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      font-size: 10px;
      color: var(--muted);
    }

    .detection-meta span {
      display: inline-flex;
      align-items: center;
      gap: 3px;
    }

    .detection-body {
      font-size: 11px;
      color: var(--fg);
      line-height: 1.35;
    }

    .match {
      background: rgba(127, 127, 127, 0.06);
      border-radius: 2px;
      padding: 6px 8px;
      font-family: var(--vscode-editor-font-family);
      font-size: 10px;
      white-space: pre-wrap;
      word-break: break-word;
      border: 1px solid var(--border);
    }

    .guidance {
      margin-top: 12px;
      display: grid;
      gap: 6px;
      background: rgba(127, 127, 127, 0.04);
      border-radius: var(--radius-lg);
      padding: 10px;
      border: 1px solid var(--border);
    }

    .guidance-row {
      display: flex;
      align-items: flex-start;
      gap: 6px;
      color: var(--muted);
      font-size: 10px;
      line-height: 1.35;
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="hero">
      <div class="hero-content">
        <div class="brand"><span class="codicon codicon-report"></span> PasteShield Report</div>
        <h1>Security Scan Details</h1>
        <div class="meta">
          <span><span class="codicon codicon-calendar"></span>${data.generatedAt}</span>
          <span><span class="codicon codicon-warning"></span><span id="totalDetections">0</span> issues detected</span>
        </div>
      </div>
      <div class="hero-actions">
        <button class="btn" id="downloadBtn" title="Download report as JSON">
          <span class="codicon codicon-download"></span>
          Download
        </button>
      </div>
    </header>

    <section class="summary-grid">
      <div class="summary-card">
        <div class="label"><span class="codicon codicon-shield"></span>Total Issues</div>
        <div class="value" id="summaryTotal">0</div>
      </div>
      <div class="summary-card">
        <div class="label"><span class="codicon codicon-error"></span>Critical</div>
        <div class="value" id="summaryCritical">0</div>
      </div>
      <div class="summary-card">
        <div class="label"><span class="codicon codicon-warning"></span>High</div>
        <div class="value" id="summaryHigh">0</div>
      </div>
      <div class="summary-card">
        <div class="label"><span class="codicon codicon-info"></span>Medium + Low</div>
        <div class="value" id="summaryOther">0</div>
      </div>
    </section>

    <section class="detections" id="detectionList"></section>

    <section class="guidance">
      <div class="guidance-row">
        <span class="codicon codicon-settings"></span>
        <span>Suppress a pattern via <strong>pasteShield.ignoredPatterns</strong> in settings.</span>
      </div>
      <div class="guidance-row">
        <span class="codicon codicon-exclude"></span>
        <span>Files excluded from paste interception: <strong>.env</strong>, <strong>.env.local</strong>.</span>
      </div>
    </section>
  </div>

  <script nonce="${nonce}">
    const data = ${safeData};
    const formatNumber = value => new Intl.NumberFormat().format(value);
    document.getElementById('totalDetections').textContent = formatNumber(data.totalDetections);
    document.getElementById('summaryTotal').textContent = formatNumber(data.totalDetections);
    document.getElementById('summaryCritical').textContent = formatNumber(data.severityCounts.critical || 0);
    document.getElementById('summaryHigh').textContent = formatNumber(data.severityCounts.high || 0);
    const otherCount = (data.severityCounts.medium || 0) + (data.severityCounts.low || 0);
    document.getElementById('summaryOther').textContent = formatNumber(otherCount);

    // Download functionality
    const vscode = acquireVsCodeApi();
    document.getElementById('downloadBtn').addEventListener('click', () => {
      const reportData = {
        generatedAt: data.generatedAt,
        totalDetections: data.totalDetections,
        severityCounts: data.severityCounts,
        detections: data.detections,
      };
      vscode.postMessage({
        command: 'downloadReport',
        data: reportData,
      });
    });

    const list = document.getElementById('detectionList');
    data.detections.forEach(item => {
      const card = document.createElement('div');
      card.className = 'detection-card severity-' + item.severity;

      const header = document.createElement('div');
      header.className = 'detection-header';

      const titleWrap = document.createElement('div');
      titleWrap.className = 'detection-title';
      const icon = document.createElement('span');
      icon.className = 'codicon codicon-shield';
      const title = document.createElement('span');
      title.textContent = item.type;
      titleWrap.appendChild(icon);
      titleWrap.appendChild(title);

      const severity = document.createElement('span');
      severity.className = 'severity-pill severity-' + item.severity;
      severity.textContent = item.severity.toUpperCase();

      header.appendChild(titleWrap);
      header.appendChild(severity);

      const meta = document.createElement('div');
      meta.className = 'detection-meta';

      const idx = document.createElement('span');
      const idxIcon = document.createElement('span');
      idxIcon.className = 'codicon codicon-list-ordered';
      const idxText = document.createElement('span');
      idxText.textContent = '#' + item.index;
      idx.appendChild(idxIcon);
      idx.appendChild(idxText);
      meta.appendChild(idx);

      if (item.category) {
        const cat = document.createElement('span');
        const catIcon = document.createElement('span');
        catIcon.className = 'codicon codicon-tag';
        const catText = document.createElement('span');
        catText.textContent = item.category;
        cat.appendChild(catIcon);
        cat.appendChild(catText);
        meta.appendChild(cat);
      }

      if (item.line !== undefined) {
        const line = document.createElement('span');
        const lineIcon = document.createElement('span');
        lineIcon.className = 'codicon codicon-location';
        const lineText = document.createElement('span');
        lineText.textContent = 'Line ' + item.line;
        line.appendChild(lineIcon);
        line.appendChild(lineText);
        meta.appendChild(line);
      }

      const body = document.createElement('div');
      body.className = 'detection-body';
      body.textContent = item.description;

      const match = document.createElement('div');
      match.className = 'match';
      match.textContent = item.match;

      card.appendChild(header);
      card.appendChild(meta);
      card.appendChild(body);
      card.appendChild(match);
      list.appendChild(card);
    });
  </script>
</body>
</html>`;
}

function getNonce(): string {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let text = '';
  for (let i = 0; i < 32; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}

/**
 * Export audit log for compliance reporting
 */
async function exportAuditLog(): Promise<void> {
  if (!historyManager) return;

  const config = vscode.workspace.getConfiguration('pasteShield');
  const enableAuditLogging = config.get<boolean>('enableAuditLogging', true);
  
  if (!enableAuditLogging) {
    vscode.window.showWarningMessage('Audit logging is disabled. Enable it in settings to export audit logs.');
    return;
  }

  const history = historyManager.getHistory();
  const auditEntries = history.map(entry => ({
    timestamp: new Date(entry.timestamp).toISOString(),
    file: entry.fileName,
    action: entry.actionTaken,
    detectionCount: entry.detections.length,
    detections: entry.detections.map(d => ({
      type: d.type,
      severity: d.severity,
      category: d.category,
    })),
  }));

  const content = JSON.stringify({
    generatedAt: new Date().toISOString(),
    version: '1.0',
    totalEntries: auditEntries.length,
    entries: auditEntries,
  }, null, 2);

  const defaultFileName = `pasteshield-audit-log-${new Date().toISOString().split('T')[0]}.json`;

  const uri = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(defaultFileName),
    filters: {
      JSON: ['json'],
    },
  });

  if (uri) {
    await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf8'));
    vscode.window.showInformationMessage(`Audit log exported to ${uri.fsPath}`);
  }
}

/**
 * Show secret rotation reminders for detected credentials
 */
async function showRotationReminders(): Promise<void> {
  if (!historyManager) return;

  const config = vscode.workspace.getConfiguration('pasteShield');
  const reminderDays = config.get<number>('secretRotationReminderDays', 90);
  
  const history = historyManager.getHistory();
  const now = Date.now();
  const reminderThreshold = reminderDays * 24 * 60 * 60 * 1000;

  // Group detections by type and find the oldest occurrence
  const oldestDetections: Record<string, { timestamp: number; severity: string; category?: string }> = {};

  for (const entry of history) {
    if (entry.actionTaken !== 'pasted') continue;

    for (const det of entry.detections) {
      const key = `${det.type}-${det.category || 'unknown'}`;
      if (!oldestDetections[key] || entry.timestamp < oldestDetections[key].timestamp) {
        oldestDetections[key] = {
          timestamp: entry.timestamp,
          severity: det.severity,
          category: det.category,
        };
      }
    }
  }

  // Find secrets that need rotation
  const needsRotation: Array<{ type: string; category?: string; daysSinceDetection: number; severity: string }> = [];

  for (const [key, data] of Object.entries(oldestDetections)) {
    const daysSince = Math.floor((now - data.timestamp) / (24 * 60 * 60 * 1000));
    if (daysSince >= reminderDays) {
      const [type, category] = key.split('-');
      needsRotation.push({
        type: type.replace(/-/g, ' '),
        category: category !== 'unknown' ? category : undefined,
        daysSinceDetection: daysSince,
        severity: data.severity,
      });
    }
  }

  if (needsRotation.length === 0) {
    vscode.window.showInformationMessage(
      `🎉 All detected secrets have been rotated recently!\\n\\nNo secrets older than ${reminderDays} days found.`
    );
    return;
  }

  // Sort by severity and days since detection
  needsRotation.sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    if (severityOrder[a.severity as keyof typeof severityOrder] !== severityOrder[b.severity as keyof typeof severityOrder]) {
      return severityOrder[a.severity as keyof typeof severityOrder] - severityOrder[b.severity as keyof typeof severityOrder];
    }
    return b.daysSinceDetection - a.daysSinceDetection;
  });

  const message = `⚠️ Secret Rotation Reminders\\n\\n` +
    `The following secrets were detected ${reminderDays}+ days ago and should be rotated:\\n\\n` +
    needsRotation.slice(0, 10).map(s => 
      `• ${s.type}${s.category ? ` (${s.category})` : ''} - ${s.daysSinceDetection} days ago [${s.severity.toUpperCase()}]`
    ).join('\\n') +
    (needsRotation.length > 10 ? `\\n\\n...and ${needsRotation.length - 10} more` : '');

  const choice = await vscode.window.showWarningMessage(message, { modal: true }, 'Rotate Now', 'Dismiss');
  
  if (choice === 'Rotate Now') {
    await vscode.env.openExternal(vscode.Uri.parse('https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/rotating-secrets'));
  }
}