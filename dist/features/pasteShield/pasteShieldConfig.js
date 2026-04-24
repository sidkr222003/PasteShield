"use strict";
/**
 * PasteShield — Configuration
 * Typed wrappers around VS Code workspace configuration.
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
exports.ALL_PATTERN_NAMES = exports.CONFIG_SECTION = void 0;
exports.getConfig = getConfig;
exports.meetsSeverityThreshold = meetsSeverityThreshold;
const vscode = __importStar(require("vscode"));
const patternDetector_1 = require("./patternDetector");
exports.CONFIG_SECTION = 'pasteShield';
function getConfig() {
    const cfg = vscode.workspace.getConfiguration(exports.CONFIG_SECTION);
    return {
        enabled: cfg.get('enabled', true),
        ignoredPatterns: cfg.get('ignoredPatterns', []),
        showInlineDecorations: cfg.get('showInlineDecorations', true),
        minimumSeverity: cfg.get('minimumSeverity', 'medium'),
        ignoredLanguages: cfg.get('ignoredLanguages', []),
    };
}
/** All available pattern names — used to populate settings IntelliSense. */
exports.ALL_PATTERN_NAMES = patternDetector_1.PATTERN_DEFINITIONS.map(p => p.name);
const SEVERITY_ORDER = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
};
function meetsSeverityThreshold(detectedSeverity, threshold) {
    return (SEVERITY_ORDER[detectedSeverity] ?? 99) <= (SEVERITY_ORDER[threshold] ?? 99);
}
//# sourceMappingURL=pasteShieldConfig.js.map