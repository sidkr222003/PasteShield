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
exports.createLogger = createLogger;
const vscode = __importStar(require("vscode"));
function getTimestamp() {
    const now = new Date();
    const hours = String(now.getHours()).padStart(2, "0");
    const minutes = String(now.getMinutes()).padStart(2, "0");
    const seconds = String(now.getSeconds()).padStart(2, "0");
    return `${hours}:${minutes}:${seconds}`;
}
function createLogger(name) {
    const channel = vscode.window.createOutputChannel(name);
    const formatPayload = (payload) => {
        if (payload === undefined)
            return "";
        if (typeof payload === "string")
            return payload;
        if (payload instanceof Error)
            return payload.stack || payload.message;
        try {
            return JSON.stringify(payload);
        }
        catch {
            return String(payload);
        }
    };
    return {
        info(header, payload) {
            channel.appendLine(`[${getTimestamp()}] ${name}: ${header}${payload !== undefined ? " " + formatPayload(payload) : ""}`);
        },
        warn(header, payload) {
            channel.appendLine(`[${getTimestamp()}] ${name}: WARNING: ${header}${payload !== undefined ? " " + formatPayload(payload) : ""}`);
        },
        error(header, payload) {
            channel.appendLine(`[${getTimestamp()}] ${name}: ERROR: ${header}${payload !== undefined ? " " + formatPayload(payload) : ""}`);
        },
        debug(header, payload) {
            channel.appendLine(`[${getTimestamp()}] ${name}: DEBUG: ${header}${payload !== undefined ? " " + formatPayload(payload) : ""}`);
        }
    };
}
//# sourceMappingURL=logger.js.map