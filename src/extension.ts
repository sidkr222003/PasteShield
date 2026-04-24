import * as vscode from "vscode";
import { registerPasteShield } from "./features/pasteShield/pasteShield";

export function activate(context: vscode.ExtensionContext) {
  registerPasteShield(context);
}

export function deactivate(): void {}