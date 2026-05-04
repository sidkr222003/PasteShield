import * as vscode from 'vscode';
import Ajv, { ErrorObject } from 'ajv';
import {
  ParseError,
  SyntaxKind,
  createScanner,
  findNodeAtLocation,
  parse,
  parseTree,
  printParseErrorCode,
} from 'jsonc-parser';

const POLICY_FILE_NAME = '.pasteshield-policy.json';

export async function validatePolicyFile(
  context: vscode.ExtensionContext,
  diagnostics: vscode.DiagnosticCollection,
): Promise<void> {
  const policyUri = resolvePolicyUri();
  if (!policyUri) {
    diagnostics.clear();
    vscode.window.showWarningMessage('No workspace folder found for policy validation.');
    return;
  }

  const exists = await fileExists(policyUri);
  if (!exists) {
    diagnostics.delete(policyUri);
    vscode.window.showWarningMessage('No .pasteshield-policy.json found in the workspace root.');
    return;
  }

  const document = await vscode.workspace.openTextDocument(policyUri);
  const text = document.getText();

  const diagnosticItems: vscode.Diagnostic[] = [];
  const commentDiagnostics = collectCommentDiagnostics(text, document);
  diagnosticItems.push(...commentDiagnostics);

  const parseErrors: ParseError[] = [];
  const data = parse(text, parseErrors, { allowTrailingComma: false });

  if (parseErrors.length > 0) {
    diagnosticItems.push(...collectParseDiagnostics(parseErrors, document));
  }

  if (parseErrors.length === 0 && commentDiagnostics.length === 0) {
    const schema = await loadPolicySchema(context);
    if (!schema) {
      vscode.window.showErrorMessage('Failed to load policy schema.');
      diagnostics.set(policyUri, diagnosticItems);
      return;
    }

    const root = parseTree(text);
    const ajv = new Ajv({ allErrors: true, strict: false });
    const validate = ajv.compile(schema);
    const valid = validate(data);

    if (!valid && validate.errors) {
      diagnosticItems.push(...collectSchemaDiagnostics(validate.errors, document, root));
    }
  }

  diagnostics.set(policyUri, diagnosticItems);

  if (diagnosticItems.length === 0) {
    vscode.window.showInformationMessage('PasteShield policy file is valid.');
  } else {
    vscode.window.showErrorMessage(
      `PasteShield policy validation found ${diagnosticItems.length} issue(s).`,
    );
  }
}

function resolvePolicyUri(): vscode.Uri | null {
  const activeDocument = vscode.window.activeTextEditor?.document;
  if (activeDocument) {
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(activeDocument.uri);
    if (workspaceFolder) {
      return vscode.Uri.joinPath(workspaceFolder.uri, POLICY_FILE_NAME);
    }
  }

  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    return null;
  }

  return vscode.Uri.joinPath(folders[0].uri, POLICY_FILE_NAME);
}

async function fileExists(uri: vscode.Uri): Promise<boolean> {
  try {
    await vscode.workspace.fs.stat(uri);
    return true;
  } catch {
    return false;
  }
}

async function loadPolicySchema(
  context: vscode.ExtensionContext,
): Promise<Record<string, unknown> | null> {
  try {
    const schemaUri = vscode.Uri.joinPath(context.extensionUri, 'schema', 'policy.schema.json');
    const raw = await vscode.workspace.fs.readFile(schemaUri);
    return JSON.parse(Buffer.from(raw).toString('utf8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function collectCommentDiagnostics(
  text: string,
  document: vscode.TextDocument,
): vscode.Diagnostic[] {
  const diagnostics: vscode.Diagnostic[] = [];
  const scanner = createScanner(text, false);

  let token = scanner.scan();
  while (token !== SyntaxKind.EOF) {
    if (token === SyntaxKind.LineCommentTrivia || token === SyntaxKind.BlockCommentTrivia) {
      const offset = scanner.getTokenOffset();
      const length = Math.max(scanner.getTokenLength(), 1);
      const range = new vscode.Range(
        document.positionAt(offset),
        document.positionAt(offset + length),
      );

      diagnostics.push(
        new vscode.Diagnostic(
          range,
          'Comments are not supported in .pasteshield-policy.json.',
          vscode.DiagnosticSeverity.Error,
        ),
      );
    }

    token = scanner.scan();
  }

  for (const diagnostic of diagnostics) {
    diagnostic.source = 'PasteShield';
  }

  return diagnostics;
}

function collectParseDiagnostics(
  parseErrors: ParseError[],
  document: vscode.TextDocument,
): vscode.Diagnostic[] {
  return parseErrors.map(error => {
    const length = Math.max(error.length, 1);
    const range = new vscode.Range(
      document.positionAt(error.offset),
      document.positionAt(error.offset + length),
    );
    const message = printParseErrorCode(error.error);
    const diagnostic = new vscode.Diagnostic(
      range,
      `Invalid JSON: ${message}.`,
      vscode.DiagnosticSeverity.Error,
    );
    diagnostic.source = 'PasteShield';
    return diagnostic;
  });
}

function collectSchemaDiagnostics(
  errors: ErrorObject[],
  document: vscode.TextDocument,
  root: ReturnType<typeof parseTree>,
): vscode.Diagnostic[] {
  const diagnostics: vscode.Diagnostic[] = [];

  for (const error of errors) {
    const message = formatSchemaError(error);
    const range = resolveSchemaErrorRange(error, document, root);
    const diagnostic = new vscode.Diagnostic(range, message, vscode.DiagnosticSeverity.Error);
    diagnostic.source = 'PasteShield';
    diagnostics.push(diagnostic);
  }

  return diagnostics;
}

function resolveSchemaErrorRange(
  error: ErrorObject,
  document: vscode.TextDocument,
  root: ReturnType<typeof parseTree>,
): vscode.Range {
  if (!root) {
    return new vscode.Range(new vscode.Position(0, 0), new vscode.Position(0, 1));
  }

  const instanceSegments = decodeJsonPointer(error.instancePath);

  if (error.keyword === 'additionalProperties') {
    const extra = (error.params as { additionalProperty?: string }).additionalProperty;
    if (extra) {
      const extraNode = findNodeAtLocation(root, [...instanceSegments, extra]);
      if (extraNode) {
        return nodeRange(extraNode, document);
      }
    }
  }

  if (error.keyword === 'required') {
    const targetNode = findNodeAtLocation(root, instanceSegments) || root;
    return nodeRange(targetNode, document);
  }

  const node = findNodeAtLocation(root, instanceSegments);
  if (node) {
    return nodeRange(node, document);
  }

  return new vscode.Range(new vscode.Position(0, 0), new vscode.Position(0, 1));
}

function nodeRange(node: { offset: number; length: number }, document: vscode.TextDocument): vscode.Range {
  const length = Math.max(node.length, 1);
  return new vscode.Range(
    document.positionAt(node.offset),
    document.positionAt(node.offset + length),
  );
}

function decodeJsonPointer(pointer: string): string[] {
  if (!pointer) {
    return [];
  }

  return pointer
    .split('/')
    .filter(Boolean)
    .map(segment => segment.replace(/~1/g, '/').replace(/~0/g, '~'));
}

function formatSchemaError(error: ErrorObject): string {
  if (error.keyword === 'required') {
    const missing = (error.params as { missingProperty?: string }).missingProperty;
    if (missing) {
      return `Missing required property "${missing}".`;
    }
  }

  if (error.keyword === 'additionalProperties') {
    const extra = (error.params as { additionalProperty?: string }).additionalProperty;
    if (extra) {
      return `Unknown property "${extra}".`;
    }
  }

  if (error.message) {
    return `Policy schema: ${error.message}.`;
  }

  return 'Policy schema validation error.';
}
