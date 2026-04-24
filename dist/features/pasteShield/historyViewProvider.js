"use strict";
/**
 * PasteShield — History View Provider
 *
 * Provides a TreeDataProvider for displaying scan history in the sidebar.
 * Uses VS Code theme colors and icons for a professional, responsive UI.
 * Enhanced with GitHub-style graph icons and improved visual hierarchy.
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
exports.HistoryItem = exports.HistoryViewProvider = void 0;
const vscode = __importStar(require("vscode"));
class HistoryViewProvider {
    constructor(historyManager) {
        this.historyManager = historyManager;
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    }
    refresh() {
        this._onDidChangeTreeData.fire();
    }
    getTreeItem(element) {
        return element;
    }
    async getChildren(element) {
        if (!element) {
            // Root level - show entries or empty state
            const history = this.historyManager.getHistory();
            if (history.length === 0) {
                const emptyItem = new HistoryItem('No scan history yet', vscode.TreeItemCollapsibleState.None, undefined, new vscode.ThemeIcon('shield', new vscode.ThemeColor('descriptionForeground')));
                emptyItem.contextValue = 'emptyHistory';
                emptyItem.description = 'Paste something to see security scans here';
                return [emptyItem];
            }
            return history.map(entry => this.createEntryItem(entry));
        }
        // Entry level - show detections
        if (element.entry) {
            return element.entry.detections.map(det => new HistoryItem(`${det.type}${det.category ? ` • ${det.category}` : ''}`, vscode.TreeItemCollapsibleState.None, {
                command: 'pasteShield.showDetectionDetails',
                title: 'Show Details',
                arguments: [det],
            }, this.getSeverityThemeIcon(det.severity), this.getSeverityColorId(det.severity)));
        }
        return [];
    }
    createEntryItem(entry) {
        const date = new Date(entry.timestamp);
        const dateStr = date.toLocaleDateString();
        const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const fileLabel = entry.fileName ? this.truncateFileName(entry.fileName) : 'Unknown file';
        const actionIcon = this.getActionThemeIcon(entry.actionTaken);
        const label = `${fileLabel}`;
        const item = new HistoryItem(label, vscode.TreeItemCollapsibleState.Expanded, undefined, actionIcon);
        item.entry = entry;
        item.tooltip = `${fileLabel}\nAction: ${entry.actionTaken.toUpperCase()}\nDetections: ${entry.detections.length}\nTime: ${date.toLocaleString()}`;
        item.description = `${timeStr} • ${this.getHighestSeverity(entry.detections)} • ${entry.detections.length} issue${entry.detections.length !== 1 ? 's' : ''}`;
        item.contextValue = 'historyEntry';
        // Set resource URI for theming support
        item.resourceUri = vscode.Uri.parse(`pasteshield://${entry.actionTaken}/${entry.id}`);
        return item;
    }
    getHighestSeverity(detections) {
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        let highest = 'low';
        for (const det of detections) {
            if (severityOrder[det.severity] < severityOrder[highest]) {
                highest = det.severity;
            }
        }
        return highest.toUpperCase();
    }
    truncateFileName(fileName) {
        const parts = fileName.split('/');
        if (parts.length > 3) {
            return '…/' + parts.slice(-3).join('/');
        }
        return fileName;
    }
    getSeverityThemeIcon(severity) {
        switch (severity.toLowerCase()) {
            case 'critical': return new vscode.ThemeIcon('error', new vscode.ThemeColor('editorError.foreground'));
            case 'high': return new vscode.ThemeIcon('stop', new vscode.ThemeColor('editorWarning.foreground'));
            case 'medium': return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorInfo.foreground'));
            case 'low': return new vscode.ThemeIcon('info', new vscode.ThemeColor('descriptionForeground'));
            default: return new vscode.ThemeIcon('circle');
        }
    }
    getSeverityColorId(severity) {
        switch (severity.toLowerCase()) {
            case 'critical': return 'pasteShield.criticalForeground';
            case 'high': return 'pasteShield.highForeground';
            case 'medium': return 'pasteShield.mediumForeground';
            case 'low': return 'pasteShield.lowForeground';
            default: return 'foreground';
        }
    }
    getActionThemeIcon(action) {
        switch (action) {
            case 'pasted': return new vscode.ThemeIcon('check-circle', new vscode.ThemeColor('terminal.ansiGreen'));
            case 'cancelled': return new vscode.ThemeIcon('skip', new vscode.ThemeColor('terminal.ansiRed'));
            case 'ignored': return new vscode.ThemeIcon('eye-closed', new vscode.ThemeColor('terminal.ansiYellow'));
            default: return new vscode.ThemeIcon('circle');
        }
    }
}
exports.HistoryViewProvider = HistoryViewProvider;
class HistoryItem extends vscode.TreeItem {
    constructor(label, collapsibleState, command, iconPath, colorId) {
        super(label, collapsibleState);
        this.label = label;
        this.collapsibleState = collapsibleState;
        this.command = command;
        if (iconPath) {
            this.iconPath = iconPath;
        }
        // Apply custom color if provided (for tree item foreground)
        if (colorId) {
            // The color is applied via the icon's ThemeColor or through CSS in package.json
            // VS Code doesn't directly support per-item text colors, but we use theme icons
        }
    }
}
exports.HistoryItem = HistoryItem;
//# sourceMappingURL=historyViewProvider.js.map