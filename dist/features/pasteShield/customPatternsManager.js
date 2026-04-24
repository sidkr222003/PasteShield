"use strict";
/**
 * PasteShield — Custom User Patterns Manager
 *
 * Allows users to define custom regex patterns with severity levels via settings.
 * Patterns are stored in VS Code configuration and integrated into the scanning engine.
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
exports.CustomPatternsManager = void 0;
exports.scanWithCustomPatterns = scanWithCustomPatterns;
const vscode = __importStar(require("vscode"));
const CONFIG_SECTION = 'pasteShield';
class CustomPatternsManager {
    constructor(context) {
        this.customPatterns = [];
        this.compiledPatterns = new Map();
        this.context = context;
        this.loadCustomPatterns();
    }
    static getInstance(context) {
        if (!CustomPatternsManager.instance) {
            CustomPatternsManager.instance = new CustomPatternsManager(context);
        }
        return CustomPatternsManager.instance;
    }
    /**
     * Load custom patterns from VS Code configuration
     */
    loadCustomPatterns() {
        const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
        const patterns = config.get('customPatterns', []);
        this.customPatterns = patterns.filter(p => p.enabled !== false);
        this.compilePatterns();
    }
    /**
     * Compile regex patterns and cache them
     */
    compilePatterns() {
        this.compiledPatterns.clear();
        for (const pattern of this.customPatterns) {
            try {
                const regex = new RegExp(pattern.regex, 'g');
                this.compiledPatterns.set(pattern.name, {
                    name: pattern.name,
                    regex,
                    severity: pattern.severity,
                    description: pattern.description || 'Custom user-defined pattern',
                    category: pattern.category || 'Custom',
                    redact: true,
                });
            }
            catch (error) {
                console.error(`Failed to compile custom pattern "${pattern.name}":`, error);
                vscode.window.showWarningMessage(`Custom pattern "${pattern.name}" has an invalid regex and will be skipped.`);
            }
        }
    }
    /**
     * Get all compiled custom pattern definitions
     */
    getCompiledPatterns() {
        return Array.from(this.compiledPatterns.values());
    }
    /**
     * Add a new custom pattern
     */
    async addPattern(pattern) {
        // Validate regex before saving
        try {
            new RegExp(pattern.regex);
        }
        catch (error) {
            vscode.window.showErrorMessage(`Invalid regex pattern: ${error.message}`);
            return;
        }
        const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
        const currentPatterns = config.get('customPatterns', []);
        // Check for duplicate name
        if (currentPatterns.some(p => p.name === pattern.name)) {
            vscode.window.showWarningMessage(`A pattern named "${pattern.name}" already exists.`);
            return;
        }
        const newPatterns = [...currentPatterns, pattern];
        await config.update('customPatterns', newPatterns, vscode.ConfigurationTarget.Global);
        this.loadCustomPatterns();
        vscode.window.showInformationMessage(`Custom pattern "${pattern.name}" added successfully.`);
    }
    /**
     * Remove a custom pattern by name
     */
    async removePattern(name) {
        const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
        const currentPatterns = config.get('customPatterns', []);
        const newPatterns = currentPatterns.filter(p => p.name !== name);
        await config.update('customPatterns', newPatterns, vscode.ConfigurationTarget.Global);
        this.loadCustomPatterns();
        vscode.window.showInformationMessage(`Custom pattern "${name}" removed.`);
    }
    /**
     * Enable or disable a custom pattern
     */
    async togglePattern(name, enabled) {
        const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
        const currentPatterns = config.get('customPatterns', []);
        const updatedPatterns = currentPatterns.map(p => p.name === name ? { ...p, enabled } : p);
        await config.update('customPatterns', updatedPatterns, vscode.ConfigurationTarget.Global);
        this.loadCustomPatterns();
    }
    /**
     * Edit an existing custom pattern
     */
    async editPattern(oldName, newPattern) {
        // Validate regex
        try {
            new RegExp(newPattern.regex);
        }
        catch (error) {
            vscode.window.showErrorMessage(`Invalid regex pattern: ${error.message}`);
            return;
        }
        const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
        const currentPatterns = config.get('customPatterns', []);
        const index = currentPatterns.findIndex(p => p.name === oldName);
        if (index === -1) {
            vscode.window.showErrorMessage(`Pattern "${oldName}" not found.`);
            return;
        }
        currentPatterns[index] = newPattern;
        await config.update('customPatterns', currentPatterns, vscode.ConfigurationTarget.Global);
        this.loadCustomPatterns();
        vscode.window.showInformationMessage(`Custom pattern "${newPattern.name}" updated.`);
    }
    /**
     * Import patterns from JSON
     */
    async importPatterns(jsonContent) {
        try {
            const importedPatterns = JSON.parse(jsonContent);
            if (!Array.isArray(importedPatterns)) {
                throw new Error('Imported data must be an array of patterns');
            }
            // Validate each pattern
            for (const pattern of importedPatterns) {
                if (!pattern.name || !pattern.regex || !pattern.severity) {
                    throw new Error('Each pattern must have name, regex, and severity');
                }
                new RegExp(pattern.regex); // Validate regex
            }
            const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
            const currentPatterns = config.get('customPatterns', []);
            // Merge patterns, avoiding duplicates by name
            const mergedPatterns = [...currentPatterns];
            for (const imported of importedPatterns) {
                const existingIndex = mergedPatterns.findIndex(p => p.name === imported.name);
                if (existingIndex >= 0) {
                    mergedPatterns[existingIndex] = imported;
                }
                else {
                    mergedPatterns.push(imported);
                }
            }
            await config.update('customPatterns', mergedPatterns, vscode.ConfigurationTarget.Global);
            this.loadCustomPatterns();
            vscode.window.showInformationMessage(`Successfully imported ${importedPatterns.length} custom pattern(s).`);
        }
        catch (error) {
            vscode.window.showErrorMessage(`Failed to import patterns: ${error.message}`);
        }
    }
    /**
     * Export patterns to JSON
     */
    exportPatterns() {
        return JSON.stringify(this.customPatterns, null, 2);
    }
    /**
     * Refresh patterns from configuration
     */
    refresh() {
        this.loadCustomPatterns();
    }
    /**
     * Get pattern by name
     */
    getPattern(name) {
        return this.customPatterns.find(p => p.name === name);
    }
    /**
     * Get all custom patterns
     */
    getAllPatterns() {
        return [...this.customPatterns];
    }
}
exports.CustomPatternsManager = CustomPatternsManager;
/**
 * Scan text against custom patterns
 */
function scanWithCustomPatterns(text, patterns) {
    const results = [];
    for (const pattern of patterns) {
        const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
        const match = regex.exec(text);
        if (match) {
            const rawMatch = match[0];
            const displayMatch = pattern.redact ? redactMatch(rawMatch) : truncateMatch(rawMatch);
            results.push({
                type: pattern.name,
                description: pattern.description,
                match: displayMatch,
                severity: pattern.severity,
                line: getLineNumber(text, match.index),
                category: pattern.category,
            });
        }
    }
    return results;
}
function redactMatch(match) {
    if (match.length <= 8) {
        return match.substring(0, 2) + '***';
    }
    return match.substring(0, 4) + '...' + match.substring(match.length - 4);
}
function truncateMatch(match, maxLength = 50) {
    if (match.length <= maxLength) {
        return match;
    }
    return match.substring(0, maxLength - 3) + '...';
}
function getLineNumber(text, index) {
    const lines = text.substring(0, index).split('\n');
    return lines.length;
}
//# sourceMappingURL=customPatternsManager.js.map