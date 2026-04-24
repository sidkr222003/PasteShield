"use strict";
/**
 * PasteShield — History Manager
 *
 * Provides persistent storage for scan history across sessions.
 * Uses VS Code's globalState for opt-in persistent storage.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.HistoryManager = void 0;
const vscode = __importStar(require("vscode"));
const HISTORY_STORAGE_KEY = 'pasteShield.scanHistory';
const MAX_HISTORY_ENTRIES = 100;
class HistoryManager {
    constructor(context) {
        this.context = context;
    }
    static getInstance(context) {
        if (!HistoryManager.instance) {
            HistoryManager.instance = new HistoryManager(context);
        }
        return HistoryManager.instance;
    }
    /**
     * Check if history tracking is enabled in settings
     */
    isEnabled() {
        const config = vscode.workspace.getConfiguration('pasteShield');
        // History is now always enabled by default for better UX
        return config.get('enableHistory', true);
    }
    /**
     * Add a new scan entry to history
     */
    async addEntry(entry) {
        if (!this.isEnabled()) {
            return;
        }
        const history = this.getHistory();
        const newEntry = {
            ...entry,
            id: this.generateId(),
            timestamp: Date.now(),
        };
        // Add to beginning (most recent first)
        history.unshift(newEntry);
        // Trim to max entries
        if (history.length > MAX_HISTORY_ENTRIES) {
            history.splice(MAX_HISTORY_ENTRIES);
        }
        await this.saveHistory(history);
    }
    /**
     * Get all history entries
     */
    getHistory() {
        const stored = this.context.globalState.get(HISTORY_STORAGE_KEY, []);
        return stored;
    }
    /**
     * Clear all history
     */
    async clearHistory() {
        await this.context.globalState.update(HISTORY_STORAGE_KEY, []);
    }
    /**
     * Get statistics from history
     */
    getStatistics() {
        const history = this.getHistory();
        const stats = {
            totalScans: history.length,
            totalDetections: 0,
            pastedCount: 0,
            cancelledCount: 0,
            ignoredCount: 0,
            bySeverity: {},
            byCategory: {},
            byType: {},
        };
        for (const entry of history) {
            stats.totalDetections += entry.detections.length;
            switch (entry.actionTaken) {
                case 'pasted':
                    stats.pastedCount++;
                    break;
                case 'cancelled':
                    stats.cancelledCount++;
                    break;
                case 'ignored':
                    stats.ignoredCount++;
                    break;
            }
            for (const detection of entry.detections) {
                stats.bySeverity[detection.severity] = (stats.bySeverity[detection.severity] || 0) + 1;
                if (detection.category) {
                    stats.byCategory[detection.category] = (stats.byCategory[detection.category] || 0) + 1;
                }
                stats.byType[detection.type] = (stats.byType[detection.type] || 0) + 1;
            }
        }
        return stats;
    }
    /**
     * Export history as JSON
     */
    exportAsJson() {
        const history = this.getHistory();
        return JSON.stringify(history, null, 2);
    }
    /**
     * Export history as plain text
     */
    exportAsText() {
        const history = this.getHistory();
        const lines = [
            'PasteShield Scan History Report',
            '='.repeat(50),
            `Generated: ${new Date().toLocaleString()}`,
            `Total Entries: ${history.length}`,
            '',
        ];
        for (const entry of history) {
            const date = new Date(entry.timestamp).toLocaleString();
            const file = entry.fileName || 'Unknown file';
            const action = entry.actionTaken.toUpperCase();
            const detectionCount = entry.detections.length;
            lines.push(`[${date}] ${file}`);
            lines.push(`  Action: ${action}`);
            lines.push(`  Detections: ${detectionCount}`);
            for (const det of entry.detections) {
                lines.push(`    - [${det.severity.toUpperCase()}] ${det.type}${det.category ? ` (${det.category})` : ''}`);
            }
            lines.push('');
        }
        return lines.join('\n');
    }
    /**
     * Save history to storage
     */
    async saveHistory(history) {
        await this.context.globalState.update(HISTORY_STORAGE_KEY, history);
    }
    /**
     * Generate unique ID for entry
     */
    generateId() {
        return `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
    }
}
exports.HistoryManager = HistoryManager;
//# sourceMappingURL=historyManager.js.map