#!/usr/bin/env node
/*
 * dynam-ncp - Node.js wrapper around the native `ncp` CLI binary.
 *
 * Resolution order:
 *   1. DYNAM_NCP_BIN environment variable (explicit path, useful for testing)
 *   2. <package>/vendor/ncp(.exe) downloaded by the postinstall script
 *
 * All CLI arguments are forwarded verbatim; stdin/stdout/stderr are inherited
 * and the child exit code / termination signal is propagated to the caller.
 */
'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const PKG_ROOT = path.resolve(__dirname, '..');

function resolveBinary() {
    if (process.env.DYNAM_NCP_BIN && process.env.DYNAM_NCP_BIN.trim() !== '') {
        return process.env.DYNAM_NCP_BIN;
    }
    const exe = process.platform === 'win32' ? 'ncp.exe' : 'ncp';
    return path.join(PKG_ROOT, 'vendor', exe);
}

function main() {
    const bin = resolveBinary();

    if (!fs.existsSync(bin)) {
        console.error('[dynam-ncp] Native binary not found: ' + bin);
        console.error('[dynam-ncp] The postinstall step may have been skipped or failed.');
        console.error('[dynam-ncp] Try reinstalling:  npm install -g dynam-ncp');
        console.error('[dynam-ncp] Or point DYNAM_NCP_BIN to an existing ncp binary.');
        process.exit(1);
    }

    const args = process.argv.slice(2);
    const child = spawn(bin, args, { stdio: 'inherit' });

    child.on('error', (err) => {
        console.error('[dynam-ncp] Failed to start ' + bin + ': ' + err.message);
        if (err.code === 'EACCES') {
            console.error('[dynam-ncp] Permission denied - try: chmod +x ' + bin);
        }
        process.exit(1);
    });

    child.on('exit', (code, signal) => {
        if (signal) {
            // Re-raise the signal on ourselves so shells see the real cause.
            try {
                process.kill(process.pid, signal);
            } catch (_) {
                process.exit(128 + (require('os').constants.signals[signal] || 1));
            }
            return;
        }
        process.exit(code === null ? 1 : code);
    });
}

main();
