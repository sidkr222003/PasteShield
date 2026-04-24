"use strict";
/**
 * PasteShield — Secret Management Integration
 *
 * Provides integration with popular secret management tools:
 * - HashiCorp Vault
 * - AWS Secrets Manager
 * - Azure Key Vault
 * - Google Secret Manager
 *
 * Allows users to store detected secrets securely and retrieve them when needed.
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
exports.SecretManagementIntegration = exports.SecretProvider = void 0;
const vscode = __importStar(require("vscode"));
const crypto = __importStar(require("crypto"));
const CONFIG_SECTION = 'pasteShield';
class SecretProvider {
}
exports.SecretProvider = SecretProvider;
/**
 * Mock Vault Provider - In production, this would use actual Vault API
 */
class VaultProvider extends SecretProvider {
    constructor(config) {
        super();
        this.storage = new Map();
        this.vaultUrl = config.vaultUrl || 'http://localhost:8200';
        this.vaultToken = config.vaultToken || '';
    }
    async storeSecret(secret) {
        // In production: POST /v1/secret/data/{name}
        console.log(`[Vault] Storing secret: ${secret.name} at ${this.vaultUrl}`);
        this.storage.set(secret.id, secret);
    }
    async getSecret(id) {
        // In production: GET /v1/secret/data/{id}
        return this.storage.get(id) || null;
    }
    async deleteSecret(id) {
        // In production: DELETE /v1/secret/data/{id}
        this.storage.delete(id);
    }
    async listSecrets() {
        // In production: LIST /v1/secret/metadata
        return Array.from(this.storage.values());
    }
    async rotateSecret(id, newValue) {
        const existing = await this.getSecret(id);
        if (!existing) {
            throw new Error(`Secret ${id} not found`);
        }
        existing.value = newValue;
        existing.metadata.storedAt = Date.now();
        await this.storeSecret(existing);
    }
}
/**
 * Mock AWS Secrets Manager Provider
 */
class AwsSecretsManagerProvider extends SecretProvider {
    constructor(config) {
        super();
        this.storage = new Map();
        this.region = config.awsRegion || 'us-east-1';
    }
    async storeSecret(secret) {
        // In production: Use AWS SDK v3
        // const client = new SecretsManagerClient({ region: this.region });
        // await client.send(new CreateSecretCommand({ Name: secret.name, SecretString: secret.value }));
        console.log(`[AWS Secrets Manager] Storing secret: ${secret.name} in ${this.region}`);
        this.storage.set(secret.id, secret);
    }
    async getSecret(id) {
        // In production: Use AWS SDK v3
        // const client = new SecretsManagerClient({ region: this.region });
        // const response = await client.send(new GetSecretValueCommand({ SecretId: id }));
        return this.storage.get(id) || null;
    }
    async deleteSecret(id) {
        // In production: Use AWS SDK v3 with ForceDeleteWithoutRecovery
        this.storage.delete(id);
    }
    async listSecrets() {
        // In production: Use AWS SDK v3 ListSecrets
        return Array.from(this.storage.values());
    }
    async rotateSecret(id, newValue) {
        // In production: Use AWS SDK v3 UpdateSecret
        const existing = await this.getSecret(id);
        if (!existing) {
            throw new Error(`Secret ${id} not found`);
        }
        existing.value = newValue;
        existing.metadata.storedAt = Date.now();
        await this.storeSecret(existing);
    }
}
/**
 * Mock Azure Key Vault Provider
 */
class AzureKeyVaultProvider extends SecretProvider {
    constructor(config) {
        super();
        this.storage = new Map();
        this.vaultUrl = config.azureVaultUrl || '';
    }
    async storeSecret(secret) {
        // In production: Use @azure/keyvault-secrets
        // const client = new SecretClient(this.vaultUrl, credential);
        // await client.setSecret(secret.name, secret.value);
        console.log(`[Azure Key Vault] Storing secret: ${secret.name}`);
        this.storage.set(secret.id, secret);
    }
    async getSecret(id) {
        return this.storage.get(id) || null;
    }
    async deleteSecret(id) {
        this.storage.delete(id);
    }
    async listSecrets() {
        return Array.from(this.storage.values());
    }
    async rotateSecret(id, newValue) {
        const existing = await this.getSecret(id);
        if (!existing) {
            throw new Error(`Secret ${id} not found`);
        }
        existing.value = newValue;
        existing.metadata.storedAt = Date.now();
        await this.storeSecret(existing);
    }
}
/**
 * Mock Google Secret Manager Provider
 */
class GoogleSecretManagerProvider extends SecretProvider {
    constructor(config) {
        super();
        this.storage = new Map();
        this.projectId = config.gcpProjectId || '';
    }
    async storeSecret(secret) {
        // In production: Use @google-cloud/secret-manager
        // const client = new SecretManagerServiceClient();
        // await client.addSecretVersion({ parent: `projects/${this.projectId}/secrets/${secret.name}`, payload: { data: secret.value } });
        console.log(`[GCP Secret Manager] Storing secret: ${secret.name} in project ${this.projectId}`);
        this.storage.set(secret.id, secret);
    }
    async getSecret(id) {
        return this.storage.get(id) || null;
    }
    async deleteSecret(id) {
        this.storage.delete(id);
    }
    async listSecrets() {
        return Array.from(this.storage.values());
    }
    async rotateSecret(id, newValue) {
        const existing = await this.getSecret(id);
        if (!existing) {
            throw new Error(`Secret ${id} not found`);
        }
        existing.value = newValue;
        existing.metadata.storedAt = Date.now();
        await this.storeSecret(existing);
    }
}
class SecretManagementIntegration {
    constructor(context) {
        this.provider = null;
        this.config = null;
        this.context = context;
        this.loadConfiguration();
        this.initializeProvider();
    }
    static getInstance(context) {
        if (!SecretManagementIntegration.instance) {
            SecretManagementIntegration.instance = new SecretManagementIntegration(context);
        }
        return SecretManagementIntegration.instance;
    }
    loadConfiguration() {
        const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
        this.config = {
            provider: config.get('secretManagerProvider', 'none'),
            vaultUrl: config.get('vaultUrl'),
            vaultToken: config.get('vaultToken'),
            awsRegion: config.get('awsRegion'),
            awsAccessKeyId: config.get('awsAccessKeyId'),
            awsSecretAccessKey: config.get('awsSecretAccessKey'),
            azureVaultUrl: config.get('azureVaultUrl'),
            azureTenantId: config.get('azureTenantId'),
            azureClientId: config.get('azureClientId'),
            azureClientSecret: config.get('azureClientSecret'),
            gcpProjectId: config.get('gcpProjectId'),
            gcpCredentials: config.get('gcpCredentials'),
        };
    }
    initializeProvider() {
        if (!this.config)
            return;
        switch (this.config.provider) {
            case 'vault':
                this.provider = new VaultProvider(this.config);
                break;
            case 'aws':
                this.provider = new AwsSecretsManagerProvider(this.config);
                break;
            case 'azure':
                this.provider = new AzureKeyVaultProvider(this.config);
                break;
            case 'gcp':
                this.provider = new GoogleSecretManagerProvider(this.config);
                break;
            default:
                this.provider = null;
        }
    }
    /**
     * Store a detected secret in the configured secret manager
     */
    async storeDetectedSecret(secretValue, metadata) {
        if (!this.provider) {
            vscode.window.showWarningMessage('Secret management is not configured. Please configure your secret manager in settings.');
            return null;
        }
        try {
            // Generate a unique ID for the secret
            const id = this.generateSecretId(metadata.type);
            const name = `${metadata.type.replace(/\s+/g, '-').toLowerCase()}-${Date.now()}`;
            const storedSecret = {
                id,
                name,
                value: this.encryptSecret(secretValue),
                metadata: {
                    ...metadata,
                    detectedAt: Date.now(),
                    storedAt: Date.now(),
                },
            };
            await this.provider.storeSecret(storedSecret);
            vscode.window.showInformationMessage(`Secret stored successfully in ${this.config?.provider.toUpperCase()} with ID: ${id}`);
            return id;
        }
        catch (error) {
            vscode.window.showErrorMessage(`Failed to store secret: ${error.message}`);
            return null;
        }
    }
    /**
     * Retrieve a stored secret by ID
     */
    async getStoredSecret(id) {
        if (!this.provider) {
            vscode.window.showWarningMessage('Secret management is not configured.');
            return null;
        }
        try {
            const secret = await this.provider.getSecret(id);
            if (!secret) {
                vscode.window.showWarningMessage(`Secret ${id} not found.`);
                return null;
            }
            return this.decryptSecret(secret.value);
        }
        catch (error) {
            vscode.window.showErrorMessage(`Failed to retrieve secret: ${error.message}`);
            return null;
        }
    }
    /**
     * Delete a stored secret
     */
    async deleteStoredSecret(id) {
        if (!this.provider) {
            return false;
        }
        try {
            await this.provider.deleteSecret(id);
            vscode.window.showInformationMessage(`Secret ${id} deleted successfully.`);
            return true;
        }
        catch (error) {
            vscode.window.showErrorMessage(`Failed to delete secret: ${error.message}`);
            return false;
        }
    }
    /**
     * List all stored secrets
     */
    async listStoredSecrets() {
        if (!this.provider) {
            return [];
        }
        try {
            return await this.provider.listSecrets();
        }
        catch (error) {
            vscode.window.showErrorMessage(`Failed to list secrets: ${error.message}`);
            return [];
        }
    }
    /**
     * Rotate a stored secret with a new value
     */
    async rotateStoredSecret(id, newValue) {
        if (!this.provider) {
            return false;
        }
        try {
            await this.provider.rotateSecret(id, this.encryptSecret(newValue));
            vscode.window.showInformationMessage(`Secret ${id} rotated successfully.`);
            return true;
        }
        catch (error) {
            vscode.window.showErrorMessage(`Failed to rotate secret: ${error.message}`);
            return false;
        }
    }
    /**
     * Quick store action - prompted after detection
     */
    async quickStoreAction(secretValue, metadata) {
        if (!this.provider) {
            const choice = await vscode.window.showWarningMessage('No secret manager configured. Would you like to configure one now?', 'Configure', 'Cancel');
            if (choice === 'Configure') {
                await vscode.commands.executeCommand('workbench.action.openSettings', 'pasteShield.secretManagerProvider');
            }
            return;
        }
        const choice = await vscode.window.showInformationMessage(`Store this ${metadata.type} in ${this.config?.provider.toUpperCase()}?`, 'Store', 'Cancel');
        if (choice === 'Store') {
            await this.storeDetectedSecret(secretValue, metadata);
        }
    }
    /**
     * Generate a unique secret ID
     */
    generateSecretId(type) {
        const hash = crypto.createHash('sha256');
        hash.update(`${type}-${Date.now()}-${Math.random()}`);
        return hash.digest('hex').substring(0, 16);
    }
    /**
     * Encrypt a secret value (simple encryption for demo - use proper KMS in production)
     */
    encryptSecret(value) {
        // In production: Use proper encryption with KMS or HSM
        const algorithm = 'aes-256-cbc';
        const key = crypto.scryptSync('pasteshield-secret-key', 'salt', 32);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(algorithm, key, iv);
        let encrypted = cipher.update(value, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    }
    /**
     * Decrypt a secret value
     */
    decryptSecret(encryptedValue) {
        // In production: Use proper decryption with KMS or HSM
        const algorithm = 'aes-256-cbc';
        const key = crypto.scryptSync('pasteshield-secret-key', 'salt', 32);
        const parts = encryptedValue.split(':');
        const iv = Buffer.from(parts[0], 'hex');
        const encrypted = parts[1];
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
    /**
     * Reconfigure the secret manager
     */
    reconfigure() {
        this.loadConfiguration();
        this.initializeProvider();
    }
    /**
     * Check if secret management is configured
     */
    isConfigured() {
        return this.provider !== null;
    }
    /**
     * Get the current provider type
     */
    getProviderType() {
        return this.config?.provider || 'none';
    }
}
exports.SecretManagementIntegration = SecretManagementIntegration;
//# sourceMappingURL=secretManagement.js.map