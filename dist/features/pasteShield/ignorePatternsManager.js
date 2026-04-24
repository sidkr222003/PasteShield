"use strict";
/**
 * PasteShield — Ignore Patterns Manager
 *
 * Manages workspace-level and user-level ignore patterns.
 * Supports .gitignore-style pattern files for flexible configuration.
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
exports.IgnorePatternsManager = void 0;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const minimatch_1 = require("minimatch");
const WORKSPACE_IGNORE_FILE = '.pasteshieldignore';
const CONFIG_SECTION = 'pasteShield';
class IgnorePatternsManager {
    constructor(context) {
        this.workspacePatterns = [];
        this.gitignorePatterns = [];
        this.context = context;
        this.loadWorkspacePatterns();
        this.loadGitignorePatterns();
    }
    static getInstance(context) {
        if (!IgnorePatternsManager.instance) {
            IgnorePatternsManager.instance = new IgnorePatternsManager(context);
        }
        return IgnorePatternsManager.instance;
    }
    /**
     * Load patterns from workspace .pasteshieldignore file
     */
    loadWorkspacePatterns() {
        this.workspacePatterns = [];
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders)
            return;
        for (const folder of workspaceFolders) {
            const ignoreFilePath = path.join(folder.uri.fsPath, WORKSPACE_IGNORE_FILE);
            try {
                if (fs.existsSync(ignoreFilePath)) {
                    const content = fs.readFileSync(ignoreFilePath, 'utf-8');
                    const lines = content.split('\n');
                    for (let i = 0; i < lines.length; i++) {
                        const line = lines[i].trim();
                        // Skip empty lines and comments
                        if (!line || line.startsWith('#'))
                            continue;
                        this.workspacePatterns.push({
                            pattern: line,
                            source: 'workspace',
                            line: i + 1,
                        });
                    }
                }
            }
            catch (error) {
                console.error(`Error loading workspace ignore file: ${ignoreFilePath}`, error);
            }
        }
    }
    /**
     * Load patterns from .gitignore file
     */
    loadGitignorePatterns() {
        this.gitignorePatterns = [];
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders)
            return;
        for (const folder of workspaceFolders) {
            const gitignorePath = path.join(folder.uri.fsPath, '.gitignore');
            try {
                if (fs.existsSync(gitignorePath)) {
                    const content = fs.readFileSync(gitignorePath, 'utf-8');
                    const lines = content.split('\n');
                    for (const line of lines) {
                        const trimmed = line.trim();
                        // Skip empty lines and comments
                        if (!trimmed || trimmed.startsWith('#'))
                            continue;
                        // Only add patterns that look like they might match secret files
                        if (this.isRelevantGitignorePattern(trimmed)) {
                            this.gitignorePatterns.push(trimmed);
                        }
                    }
                }
            }
            catch (error) {
                console.error(`Error loading .gitignore file: ${gitignorePath}`, error);
            }
        }
    }
    /**
     * Check if a gitignore pattern is relevant for secret detection
     */
    isRelevantGitignorePattern(pattern) {
        const secretRelatedKeywords = [
            '.env', 'secret', 'key', 'token', 'credential', 'password',
            'auth', 'private', 'pem', 'cert', 'ssl', 'ssh'
        ];
        const lowerPattern = pattern.toLowerCase();
        return secretRelatedKeywords.some(keyword => lowerPattern.includes(keyword));
    }
    /**
     * Get all ignore patterns (user + workspace + gitignore)
     */
    getAllPatterns() {
        const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
        const userPatterns = config.get('ignoredPatterns', [])
            .map(pattern => ({ pattern, source: 'user' }));
        return [...userPatterns, ...this.workspacePatterns];
    }
    /**
     * Check if a pattern should be ignored
     */
    shouldIgnore(patternName, filePath) {
        const allPatterns = this.getAllPatterns();
        for (const { pattern, source } of allPatterns) {
            if (this.matchesPattern(patternName, pattern, filePath)) {
                return true;
            }
        }
        // Also check gitignore patterns if file path is provided
        if (filePath) {
            for (const gitPattern of this.gitignorePatterns) {
                if ((0, minimatch_1.minimatch)(filePath, gitPattern, { dot: true })) {
                    return true;
                }
            }
        }
        return false;
    }
    /**
     * Check if a pattern name matches an ignore pattern
     */
    matchesPattern(patternName, ignorePattern, filePath) {
        // Exact match
        if (patternName === ignorePattern) {
            return true;
        }
        // Glob pattern match
        if (ignorePattern.includes('*') || ignorePattern.includes('?')) {
            if ((0, minimatch_1.minimatch)(patternName, ignorePattern)) {
                return true;
            }
        }
        // Partial match (substring)
        if (patternName.toLowerCase().includes(ignorePattern.toLowerCase())) {
            return true;
        }
        return false;
    }
    /**
     * Add a pattern to workspace ignore file
     */
    async addToWorkspaceIgnore(pattern) {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            vscode.window.showWarningMessage('No workspace folder open to save ignore pattern.');
            return;
        }
        const folder = workspaceFolders[0];
        const ignoreFilePath = path.join(folder.uri.fsPath, WORKSPACE_IGNORE_FILE);
        try {
            let content = '';
            if (fs.existsSync(ignoreFilePath)) {
                content = fs.readFileSync(ignoreFilePath, 'utf-8');
                // Check if pattern already exists
                if (content.split('\n').some(line => line.trim() === pattern)) {
                    vscode.window.showInformationMessage(`Pattern "${pattern}" is already in ${WORKSPACE_IGNORE_FILE}`);
                    return;
                }
                content = content.trimEnd() + '\n';
            }
            content += `# Added by PasteShield on ${new Date().toLocaleString()}\n${pattern}\n`;
            fs.writeFileSync(ignoreFilePath, content, 'utf-8');
            this.loadWorkspacePatterns(); // Reload patterns
            vscode.window.showInformationMessage(`Added "${pattern}" to ${WORKSPACE_IGNORE_FILE}`);
        }
        catch (error) {
            vscode.window.showErrorMessage(`Failed to write to ${WORKSPACE_IGNORE_FILE}: ${error}`);
        }
    }
    /**
     * Remove a pattern from workspace ignore file
     */
    async removeFromWorkspaceIgnore(pattern) {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0)
            return;
        const folder = workspaceFolders[0];
        const ignoreFilePath = path.join(folder.uri.fsPath, WORKSPACE_IGNORE_FILE);
        try {
            if (!fs.existsSync(ignoreFilePath))
                return;
            const content = fs.readFileSync(ignoreFilePath, 'utf-8');
            const lines = content.split('\n');
            const newLines = lines.filter(line => line.trim() !== pattern);
            fs.writeFileSync(ignoreFilePath, newLines.join('\n'), 'utf-8');
            this.loadWorkspacePatterns(); // Reload patterns
            vscode.window.showInformationMessage(`Removed "${pattern}" from ${WORKSPACE_IGNORE_FILE}`);
        }
        catch (error) {
            vscode.window.showErrorMessage(`Failed to update ${WORKSPACE_IGNORE_FILE}: ${error}`);
        }
    }
    /**
     * Refresh patterns (e.g., after file changes)
     */
    refresh() {
        this.loadWorkspacePatterns();
        this.loadGitignorePatterns();
    }
    /**
     * Get patterns by source
     */
    getPatternsBySource() {
        const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
        const userPatterns = config.get('ignoredPatterns', [])
            .map(pattern => ({ pattern, source: 'user' }));
        return {
            user: userPatterns,
            workspace: this.workspacePatterns,
            gitignore: this.gitignorePatterns,
        };
    }
}
exports.IgnorePatternsManager = IgnorePatternsManager;
//# sourceMappingURL=ignorePatternsManager.js.map