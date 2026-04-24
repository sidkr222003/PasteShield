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

import * as vscode from 'vscode';
import * as crypto from 'crypto';

const CONFIG_SECTION = 'pasteShield';

export interface SecretManagerConfig {
  provider: 'vault' | 'aws' | 'azure' | 'gcp' | 'none';
  vaultUrl?: string;
  vaultToken?: string;
  awsRegion?: string;
  awsAccessKeyId?: string;
  awsSecretAccessKey?: string;
  azureVaultUrl?: string;
  azureTenantId?: string;
  azureClientId?: string;
  azureClientSecret?: string;
  gcpProjectId?: string;
  gcpCredentials?: string;
}

export interface StoredSecret {
  id: string;
  name: string;
  value: string;
  metadata: {
    type: string;
    severity: string;
    category?: string;
    detectedAt: number;
    storedAt: number;
    filePath?: string;
  };
}

export abstract class SecretProvider {
  abstract storeSecret(secret: StoredSecret): Promise<void>;
  abstract getSecret(id: string): Promise<StoredSecret | null>;
  abstract deleteSecret(id: string): Promise<void>;
  abstract listSecrets(): Promise<StoredSecret[]>;
  abstract rotateSecret(id: string, newValue: string): Promise<void>;
}

/**
 * Mock Vault Provider - In production, this would use actual Vault API
 */
class VaultProvider extends SecretProvider {
  private vaultUrl: string;
  private vaultToken: string;
  private storage: Map<string, StoredSecret> = new Map();

  constructor(config: SecretManagerConfig) {
    super();
    this.vaultUrl = config.vaultUrl || 'http://localhost:8200';
    this.vaultToken = config.vaultToken || '';
  }

  async storeSecret(secret: StoredSecret): Promise<void> {
    // In production: POST /v1/secret/data/{name}
    console.log(`[Vault] Storing secret: ${secret.name} at ${this.vaultUrl}`);
    this.storage.set(secret.id, secret);
  }

  async getSecret(id: string): Promise<StoredSecret | null> {
    // In production: GET /v1/secret/data/{id}
    return this.storage.get(id) || null;
  }

  async deleteSecret(id: string): Promise<void> {
    // In production: DELETE /v1/secret/data/{id}
    this.storage.delete(id);
  }

  async listSecrets(): Promise<StoredSecret[]> {
    // In production: LIST /v1/secret/metadata
    return Array.from(this.storage.values());
  }

  async rotateSecret(id: string, newValue: string): Promise<void> {
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
  private region: string;
  private storage: Map<string, StoredSecret> = new Map();

  constructor(config: SecretManagerConfig) {
    super();
    this.region = config.awsRegion || 'us-east-1';
  }

  async storeSecret(secret: StoredSecret): Promise<void> {
    // In production: Use AWS SDK v3
    // const client = new SecretsManagerClient({ region: this.region });
    // await client.send(new CreateSecretCommand({ Name: secret.name, SecretString: secret.value }));
    console.log(`[AWS Secrets Manager] Storing secret: ${secret.name} in ${this.region}`);
    this.storage.set(secret.id, secret);
  }

  async getSecret(id: string): Promise<StoredSecret | null> {
    // In production: Use AWS SDK v3
    // const client = new SecretsManagerClient({ region: this.region });
    // const response = await client.send(new GetSecretValueCommand({ SecretId: id }));
    return this.storage.get(id) || null;
  }

  async deleteSecret(id: string): Promise<void> {
    // In production: Use AWS SDK v3 with ForceDeleteWithoutRecovery
    this.storage.delete(id);
  }

  async listSecrets(): Promise<StoredSecret[]> {
    // In production: Use AWS SDK v3 ListSecrets
    return Array.from(this.storage.values());
  }

  async rotateSecret(id: string, newValue: string): Promise<void> {
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
  private vaultUrl: string;
  private storage: Map<string, StoredSecret> = new Map();

  constructor(config: SecretManagerConfig) {
    super();
    this.vaultUrl = config.azureVaultUrl || '';
  }

  async storeSecret(secret: StoredSecret): Promise<void> {
    // In production: Use @azure/keyvault-secrets
    // const client = new SecretClient(this.vaultUrl, credential);
    // await client.setSecret(secret.name, secret.value);
    console.log(`[Azure Key Vault] Storing secret: ${secret.name}`);
    this.storage.set(secret.id, secret);
  }

  async getSecret(id: string): Promise<StoredSecret | null> {
    return this.storage.get(id) || null;
  }

  async deleteSecret(id: string): Promise<void> {
    this.storage.delete(id);
  }

  async listSecrets(): Promise<StoredSecret[]> {
    return Array.from(this.storage.values());
  }

  async rotateSecret(id: string, newValue: string): Promise<void> {
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
  private projectId: string;
  private storage: Map<string, StoredSecret> = new Map();

  constructor(config: SecretManagerConfig) {
    super();
    this.projectId = config.gcpProjectId || '';
  }

  async storeSecret(secret: StoredSecret): Promise<void> {
    // In production: Use @google-cloud/secret-manager
    // const client = new SecretManagerServiceClient();
    // await client.addSecretVersion({ parent: `projects/${this.projectId}/secrets/${secret.name}`, payload: { data: secret.value } });
    console.log(`[GCP Secret Manager] Storing secret: ${secret.name} in project ${this.projectId}`);
    this.storage.set(secret.id, secret);
  }

  async getSecret(id: string): Promise<StoredSecret | null> {
    return this.storage.get(id) || null;
  }

  async deleteSecret(id: string): Promise<void> {
    this.storage.delete(id);
  }

  async listSecrets(): Promise<StoredSecret[]> {
    return Array.from(this.storage.values());
  }

  async rotateSecret(id: string, newValue: string): Promise<void> {
    const existing = await this.getSecret(id);
    if (!existing) {
      throw new Error(`Secret ${id} not found`);
    }
    existing.value = newValue;
    existing.metadata.storedAt = Date.now();
    await this.storeSecret(existing);
  }
}

export class SecretManagementIntegration {
  private static instance: SecretManagementIntegration | undefined;
  private context: vscode.ExtensionContext;
  private provider: SecretProvider | null = null;
  private config: SecretManagerConfig | null = null;

  private constructor(context: vscode.ExtensionContext) {
    this.context = context;
    this.loadConfiguration();
    this.initializeProvider();
  }

  public static getInstance(context: vscode.ExtensionContext): SecretManagementIntegration {
    if (!SecretManagementIntegration.instance) {
      SecretManagementIntegration.instance = new SecretManagementIntegration(context);
    }
    return SecretManagementIntegration.instance;
  }

  private loadConfiguration(): void {
    const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
    this.config = {
      provider: config.get<'vault' | 'aws' | 'azure' | 'gcp' | 'none'>('secretManagerProvider', 'none'),
      vaultUrl: config.get<string>('vaultUrl'),
      vaultToken: config.get<string>('vaultToken'),
      awsRegion: config.get<string>('awsRegion'),
      awsAccessKeyId: config.get<string>('awsAccessKeyId'),
      awsSecretAccessKey: config.get<string>('awsSecretAccessKey'),
      azureVaultUrl: config.get<string>('azureVaultUrl'),
      azureTenantId: config.get<string>('azureTenantId'),
      azureClientId: config.get<string>('azureClientId'),
      azureClientSecret: config.get<string>('azureClientSecret'),
      gcpProjectId: config.get<string>('gcpProjectId'),
      gcpCredentials: config.get<string>('gcpCredentials'),
    };
  }

  private initializeProvider(): void {
    if (!this.config) return;

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
  public async storeDetectedSecret(
    secretValue: string,
    metadata: {
      type: string;
      severity: string;
      category?: string;
      filePath?: string;
    }
  ): Promise<string | null> {
    if (!this.provider) {
      vscode.window.showWarningMessage(
        'Secret management is not configured. Please configure your secret manager in settings.'
      );
      return null;
    }

    try {
      // Generate a unique ID for the secret
      const id = this.generateSecretId(metadata.type);
      const name = `${metadata.type.replace(/\s+/g, '-').toLowerCase()}-${Date.now()}`;

      const storedSecret: StoredSecret = {
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
      
      vscode.window.showInformationMessage(
        `Secret stored successfully in ${this.config?.provider.toUpperCase()} with ID: ${id}`
      );

      return id;
    } catch (error) {
      vscode.window.showErrorMessage(
        `Failed to store secret: ${(error as Error).message}`
      );
      return null;
    }
  }

  /**
   * Retrieve a stored secret by ID
   */
  public async getStoredSecret(id: string): Promise<string | null> {
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
    } catch (error) {
      vscode.window.showErrorMessage(
        `Failed to retrieve secret: ${(error as Error).message}`
      );
      return null;
    }
  }

  /**
   * Delete a stored secret
   */
  public async deleteStoredSecret(id: string): Promise<boolean> {
    if (!this.provider) {
      return false;
    }

    try {
      await this.provider.deleteSecret(id);
      vscode.window.showInformationMessage(`Secret ${id} deleted successfully.`);
      return true;
    } catch (error) {
      vscode.window.showErrorMessage(
        `Failed to delete secret: ${(error as Error).message}`
      );
      return false;
    }
  }

  /**
   * List all stored secrets
   */
  public async listStoredSecrets(): Promise<StoredSecret[]> {
    if (!this.provider) {
      return [];
    }

    try {
      return await this.provider.listSecrets();
    } catch (error) {
      vscode.window.showErrorMessage(
        `Failed to list secrets: ${(error as Error).message}`
      );
      return [];
    }
  }

  /**
   * Rotate a stored secret with a new value
   */
  public async rotateStoredSecret(id: string, newValue: string): Promise<boolean> {
    if (!this.provider) {
      return false;
    }

    try {
      await this.provider.rotateSecret(id, this.encryptSecret(newValue));
      vscode.window.showInformationMessage(`Secret ${id} rotated successfully.`);
      return true;
    } catch (error) {
      vscode.window.showErrorMessage(
        `Failed to rotate secret: ${(error as Error).message}`
      );
      return false;
    }
  }

  /**
   * Quick store action - prompted after detection
   */
  public async quickStoreAction(
    secretValue: string,
    metadata: {
      type: string;
      severity: string;
      category?: string;
      filePath?: string;
    }
  ): Promise<void> {
    if (!this.provider) {
      const choice = await vscode.window.showWarningMessage(
        'No secret manager configured. Would you like to configure one now?',
        'Configure',
        'Cancel'
      );

      if (choice === 'Configure') {
        await vscode.commands.executeCommand(
          'workbench.action.openSettings',
          'pasteShield.secretManagerProvider'
        );
      }
      return;
    }

    const choice = await vscode.window.showInformationMessage(
      `Store this ${metadata.type} in ${this.config?.provider.toUpperCase()}?`,
      'Store',
      'Cancel'
    );

    if (choice === 'Store') {
      await this.storeDetectedSecret(secretValue, metadata);
    }
  }

  /**
   * Generate a unique secret ID
   */
  private generateSecretId(type: string): string {
    const hash = crypto.createHash('sha256');
    hash.update(`${type}-${Date.now()}-${Math.random()}`);
    return hash.digest('hex').substring(0, 16);
  }

  /**
   * Encrypt a secret value (simple encryption for demo - use proper KMS in production)
   */
  private encryptSecret(value: string): string {
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
  private decryptSecret(encryptedValue: string): string {
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
  public reconfigure(): void {
    this.loadConfiguration();
    this.initializeProvider();
  }

  /**
   * Check if secret management is configured
   */
  public isConfigured(): boolean {
    return this.provider !== null;
  }

  /**
   * Get the current provider type
   */
  public getProviderType(): string {
    return this.config?.provider || 'none';
  }
}
