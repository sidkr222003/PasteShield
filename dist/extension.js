"use strict";
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
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const pasteShield_1 = require("./features/pasteShield/pasteShield");
const customPatternsManager_1 = require("./features/pasteShield/customPatternsManager");
const secretManagement_1 = require("./features/pasteShield/secretManagement");
const enterprisePolicy_1 = require("./features/pasteShield/enterprisePolicy");
function activate(context) {
    (0, pasteShield_1.registerPasteShield)(context);
    // Initialize Custom Patterns Manager
    const customPatternsManager = customPatternsManager_1.CustomPatternsManager.getInstance(context);
    // Register Manage Custom Patterns command
    context.subscriptions.push(vscode.commands.registerCommand('pasteShield.manageCustomPatterns', async () => {
        const patterns = customPatternsManager.getAllPatterns();
        if (patterns.length === 0) {
            const choice = await vscode.window.showInformationMessage('No custom patterns defined. Would you like to add one?', 'Add Pattern', 'Import Patterns', 'Cancel');
            if (choice === 'Add Pattern') {
                await promptAddCustomPattern(customPatternsManager);
            }
            else if (choice === 'Import Patterns') {
                await promptImportPatterns(customPatternsManager);
            }
            return;
        }
        const patternNames = patterns.map(p => p.name);
        const selected = await vscode.window.showQuickPick(patternNames.map(name => ({
            label: name,
            description: patterns.find(p => p.name === name)?.category,
        })), { placeHolder: 'Select a pattern to manage' });
        if (!selected)
            return;
        const pattern = patterns.find(p => p.name === selected.label);
        if (!pattern)
            return;
        const action = await vscode.window.showQuickPick(['Edit', 'Toggle Enable/Disable', 'Remove', 'Export'], { placeHolder: `Manage "${pattern.name}"` });
        switch (action) {
            case 'Edit':
                await promptEditCustomPattern(customPatternsManager, pattern);
                break;
            case 'Toggle Enable/Disable':
                await customPatternsManager.togglePattern(pattern.name, !pattern.enabled);
                break;
            case 'Remove':
                await customPatternsManager.removePattern(pattern.name);
                break;
            case 'Export':
                await exportCustomPatterns(customPatternsManager);
                break;
        }
    }));
    // Register Configure Secret Manager command
    context.subscriptions.push(vscode.commands.registerCommand('pasteShield.configureSecretManager', async () => {
        const provider = await vscode.window.showQuickPick([
            { label: 'none', description: 'No secret manager' },
            { label: 'vault', description: 'HashiCorp Vault' },
            { label: 'aws', description: 'AWS Secrets Manager' },
            { label: 'azure', description: 'Azure Key Vault' },
            { label: 'gcp', description: 'Google Secret Manager' },
        ], { placeHolder: 'Select secret manager provider' });
        if (!provider)
            return;
        const config = vscode.workspace.getConfiguration('pasteShield');
        await config.update('secretManagerProvider', provider.label, vscode.ConfigurationTarget.Global);
        vscode.window.showInformationMessage(`Secret manager set to ${provider.description}. Configure credentials in settings.`);
        await vscode.commands.executeCommand('workbench.action.openSettings', 'pasteShield.secretManagerProvider');
    }));
    // Register List Stored Secrets command
    context.subscriptions.push(vscode.commands.registerCommand('pasteShield.listStoredSecrets', async () => {
        const secretManager = secretManagement_1.SecretManagementIntegration.getInstance(context);
        if (!secretManager.isConfigured()) {
            const choice = await vscode.window.showWarningMessage('Secret manager is not configured. Configure it now?', 'Configure', 'Cancel');
            if (choice === 'Configure') {
                await vscode.commands.executeCommand('pasteShield.configureSecretManager');
            }
            return;
        }
        const secrets = await secretManager.listStoredSecrets();
        if (secrets.length === 0) {
            vscode.window.showInformationMessage('No secrets stored yet.');
            return;
        }
        const quickPickItems = secrets.map(s => ({
            label: s.name,
            description: s.metadata.type,
            detail: `Stored: ${new Date(s.metadata.storedAt).toLocaleString()}`,
            secret: s,
        }));
        const selected = await vscode.window.showQuickPick(quickPickItems, {
            placeHolder: 'Select a stored secret',
        });
        if (!selected)
            return;
        const action = await vscode.window.showQuickPick(['View Details', 'Rotate', 'Delete'], { placeHolder: `Action for ${selected.label}` });
        switch (action) {
            case 'View Details':
                vscode.window.showInformationMessage(`Secret: ${selected.label}\nType: ${selected.description}\nDetected: ${new Date(selected.secret.metadata.detectedAt).toLocaleString()}\nStored: ${new Date(selected.secret.metadata.storedAt).toLocaleString()}`);
                break;
            case 'Rotate':
                const newValue = await vscode.window.showInputBox({
                    prompt: 'Enter new secret value',
                    password: true,
                });
                if (newValue) {
                    await secretManager.rotateStoredSecret(selected.secret.id, newValue);
                }
                break;
            case 'Delete':
                const confirm = await vscode.window.showWarningMessage(`Are you sure you want to delete ${selected.label}?`, { modal: true }, 'Delete');
                if (confirm === 'Delete') {
                    await secretManager.deleteStoredSecret(selected.secret.id);
                }
                break;
        }
    }));
    // Register Show Enterprise Policy command
    context.subscriptions.push(vscode.commands.registerCommand('pasteShield.showEnterprisePolicy', async () => {
        const policyManager = enterprisePolicy_1.EnterprisePolicyManager.getInstance(context);
        if (!policyManager.isEnterpriseModeEnabled()) {
            const choice = await vscode.window.showInformationMessage('Enterprise mode is not enabled. Enable it now?', 'Enable', 'Cancel');
            if (choice === 'Enable') {
                const config = vscode.workspace.getConfiguration('pasteShield');
                await config.update('enterpriseMode', true, vscode.ConfigurationTarget.Global);
                vscode.window.showInformationMessage('Enterprise mode enabled. Configure policies in settings.');
            }
            return;
        }
        const policy = policyManager.getCurrentPolicy();
        if (!policy) {
            vscode.window.showInformationMessage('No enterprise policy configured.');
            return;
        }
        const report = policyManager.generateComplianceReport([]);
        const content = `╔══════════════════════════════════════════════════════╗
║         PasteShield Enterprise Policy Report         ║
╚══════════════════════════════════════════════════════╝

Policy: ${policy.name}
Version: ${policy.version}
Status: ${policy.enabled ? '✅ Enabled' : '❌ Disabled'}
Description: ${policy.description}

┌──────────────────────────────────────────────────────┐
│                    RULES                             │
└──────────────────────────────────────────────────────┘

${policy.rules.map((r, i) => `[${i + 1}] ${r.id}: ${r.type} (${r.severity}) → ${r.action}`).join('\n')}

┌──────────────────────────────────────────────────────┐
│               COMPLIANCE SUMMARY                     │
└──────────────────────────────────────────────────────┘

Compliance Score: ${report.complianceScore}/100
Total Scans (30 days): ${report.totalScans}
Policy Violations: ${report.policyViolations}
Blocked Pastes: ${report.blockedPastes}
`;
        const doc = await vscode.workspace.openTextDocument({
            content,
            language: 'plaintext',
        });
        await vscode.window.showTextDocument(doc, {
            preview: true,
            viewColumn: vscode.ViewColumn.Beside,
        });
    }));
    // Register Export Compliance Report command
    context.subscriptions.push(vscode.commands.registerCommand('pasteShield.exportComplianceReport', async () => {
        const policyManager = enterprisePolicy_1.EnterprisePolicyManager.getInstance(context);
        if (!policyManager.isEnterpriseModeEnabled()) {
            vscode.window.showWarningMessage('Enterprise mode must be enabled to export compliance reports.');
            return;
        }
        // Get history from history manager (would need to be passed in or accessed globally)
        // For now, generate an empty report
        const report = policyManager.generateComplianceReport([]);
        await policyManager.exportComplianceReport(report);
    }));
}
async function promptAddCustomPattern(manager) {
    const name = await vscode.window.showInputBox({
        prompt: 'Enter pattern name',
        placeHolder: 'e.g., My Company API Key',
    });
    if (!name)
        return;
    const regex = await vscode.window.showInputBox({
        prompt: 'Enter regex pattern',
        placeHolder: 'e.g., MYCOMPANY_[a-zA-Z0-9]{32}',
    });
    if (!regex)
        return;
    const severity = await vscode.window.showQuickPick(['critical', 'high', 'medium', 'low'], { placeHolder: 'Select severity level' });
    if (!severity)
        return;
    const description = await vscode.window.showInputBox({
        prompt: 'Enter description',
        placeHolder: 'What does this pattern detect?',
    });
    const category = await vscode.window.showInputBox({
        prompt: 'Enter category',
        placeHolder: 'e.g., Custom, Company-Specific',
        value: 'Custom',
    });
    await manager.addPattern({
        name,
        regex,
        severity: severity,
        description: description || '',
        category: category || 'Custom',
        enabled: true,
    });
}
async function promptEditCustomPattern(manager, pattern) {
    const newName = await vscode.window.showInputBox({
        prompt: 'Enter pattern name',
        value: pattern.name,
    });
    if (!newName)
        return;
    const newRegex = await vscode.window.showInputBox({
        prompt: 'Enter regex pattern',
        value: pattern.regex,
    });
    if (!newRegex)
        return;
    const newSeverity = await vscode.window.showQuickPick(['critical', 'high', 'medium', 'low'], { placeHolder: 'Select severity level' });
    if (!newSeverity)
        return;
    await manager.editPattern(pattern.name, {
        ...pattern,
        name: newName,
        regex: newRegex,
        severity: newSeverity,
    });
}
async function promptImportPatterns(manager) {
    const uri = await vscode.window.showOpenDialog({
        canSelectFiles: true,
        canSelectFolders: false,
        canSelectMany: false,
        filters: { JSON: ['json'] },
    });
    if (!uri || uri.length === 0)
        return;
    const file = await vscode.workspace.fs.readFile(uri[0]);
    const content = Buffer.from(file).toString('utf8');
    await manager.importPatterns(content);
}
async function exportCustomPatterns(manager) {
    const content = manager.exportPatterns();
    const uri = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file('pasteshield-custom-patterns.json'),
        filters: { JSON: ['json'] },
    });
    if (uri) {
        await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf8'));
        vscode.window.showInformationMessage(`Custom patterns exported to ${uri.fsPath}`);
    }
}
function deactivate() { }
//# sourceMappingURL=extension.js.map