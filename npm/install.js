#!/usr/bin/env node
/*
 * dynam-ncp postinstall: downloads the prebuilt `ncp` binary for the current
 * platform from the GitHub Releases of kirin2461/Dynam and installs it into
 * <package>/vendor/.
 *
 * Assets produced by .github/workflows/release.yml:
 *   ncp-linux-x64.tar.gz    (contains ncp-linux-x64/ncp)
 *   ncp-macos-x64.tar.gz    (contains ncp-macos-x64/ncp)
 *   ncp-windows-x64.zip     (contains ncp-windows-x64/ncp.exe)
 *
 * Environment variables:
 *   DYNAM_NCP_SKIP_DOWNLOAD=1   skip downloading entirely (CI/tests)
 *   DYNAM_NCP_RELEASE=<tag>    download from a specific release tag (e.g. v1.5.0)
 *
 * This script NEVER fails the npm install: on any error it prints a clear
 * warning and exits 0 so the package manager continues.
 */
'use strict';

const https = require('https');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const REPO = 'kirin2461/Dynam';
const PKG_ROOT = __dirname;
const VENDOR_DIR = path.join(PKG_ROOT, 'vendor');
const IS_WIN = process.platform === 'win32';
const BIN_NAME = IS_WIN ? 'ncp.exe' : 'ncp';
const BIN_PATH = path.join(VENDOR_DIR, BIN_NAME);

// ---------------------------------------------------------------------------
// Platform mapping
// ---------------------------------------------------------------------------
function resolveAsset() {
    const p = process.platform;
    const a = process.arch;
    if (p === 'linux' && a === 'x64') {
        return { asset: 'ncp-linux-x64.tar.gz', note: null };
    }
    if (p === 'darwin' && a === 'x64') {
        return { asset: 'ncp-macos-x64.tar.gz', note: null };
    }
    if (p === 'darwin' && a === 'arm64') {
        return {
            asset: 'ncp-macos-x64.tar.gz',
            note: 'No native macOS arm64 build yet; using the x64 build (runs via Rosetta 2).',
        };
    }
    if (p === 'win32' && a === 'x64') {
        return { asset: 'ncp-windows-x64.zip', note: null };
    }
    return null;
}

// ---------------------------------------------------------------------------
// Download helper (follows GitHub's redirects to the CDN)
// ---------------------------------------------------------------------------
function download(url, dest, redirectsLeft) {
    return new Promise((resolve, reject) => {
        const mod = url.startsWith('http:') ? http : https;
        mod
            .get(url, { headers: { 'User-Agent': 'dynam-ncp-installer' } }, (res) => {
                if (
                    res.statusCode >= 300 &&
                    res.statusCode < 400 &&
                    res.headers.location
                ) {
                    res.resume();
                    if (redirectsLeft <= 0) {
                        return reject(new Error('Too many redirects for ' + url));
                    }
                    return resolve(download(res.headers.location, dest, redirectsLeft - 1));
                }
                if (res.statusCode !== 200) {
                    res.resume();
                    return reject(
                        new Error('HTTP ' + res.statusCode + ' for ' + url)
                    );
                }
                const out = fs.createWriteStream(dest);
                res.pipe(out);
                out.on('finish', () => out.close(() => resolve(dest)));
                out.on('error', reject);
            })
            .on('error', reject);
    });
}

// ---------------------------------------------------------------------------
// Extraction: uses the system `tar` (bsdtar on Windows 10+ also reads .zip)
// ---------------------------------------------------------------------------
function extract(archive, destDir) {
    if (archive.endsWith('.zip')) {
        execFileSync('tar', ['-xf', archive, '-C', destDir], { stdio: 'pipe' });
    } else {
        execFileSync('tar', ['-xzf', archive, '-C', destDir], { stdio: 'pipe' });
    }
}

function findBinary(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const e of entries) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) {
            const found = findBinary(full);
            if (found) return found;
        } else if (e.name === 'ncp' || e.name === 'ncp.exe') {
            return full;
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Verification: non-empty file + `ncp --help` actually runs
// ---------------------------------------------------------------------------
function verifyBinary(binPath) {
    const stat = fs.statSync(binPath);
    // Bundled-libs layout: `ncp` is a small $ORIGIN wrapper script and the
    // real ELF is the sibling `ncp.bin` — allow the small file then.
    const hasBundledSibling = fs.existsSync(binPath + '.bin');
    if ((!stat.isFile() || stat.size < 1024) && !hasBundledSibling) {
        throw new Error('Downloaded binary is suspiciously small (' + stat.size + ' bytes)');
    }
    if (!IS_WIN) {
        fs.chmodSync(binPath, 0o755);
    }
    const res = spawnSync(binPath, ['--help'], {
        encoding: 'utf8',
        timeout: 20000,
    });
    if (res.error) {
        throw new Error('Binary failed to run: ' + res.error.message);
    }
    if (res.status !== 0) {
        throw new Error('`ncp --help` exited with code ' + res.status);
    }
}

function warnAndExit(msg) {
    console.warn('');
    console.warn('[dynam-ncp] WARNING: ' + msg);
    console.warn('[dynam-ncp] The package was installed WITHOUT the native binary.');
    console.warn('[dynam-ncp] You can retry later with: npm rebuild dynam-ncp');
    console.warn('[dynam-ncp] Or build from source: https://github.com/' + REPO);
    console.warn('');
    process.exit(0);
}

async function main() {
    console.log('[dynam-ncp] Installing native ncp binary for ' +
        process.platform + '-' + process.arch + ' ...');

    if (process.env.DYNAM_NCP_SKIP_DOWNLOAD === '1') {
        console.log('[dynam-ncp] DYNAM_NCP_SKIP_DOWNLOAD=1 - skipping download.');
        return;
    }

    if (fs.existsSync(BIN_PATH)) {
        console.log('[dynam-ncp] Binary already present at ' + BIN_PATH + ' - skipping.');
        return;
    }

    const target = resolveAsset();
    if (!target) {
        warnAndExit(
            'Unsupported platform: ' + process.platform + '-' + process.arch +
            '. Supported: linux-x64, darwin-x64, darwin-arm64 (via Rosetta), win32-x64.'
        );
    }
    if (target.note) {
        console.warn('[dynam-ncp] NOTE: ' + target.note);
    }

    const pkg = JSON.parse(fs.readFileSync(path.join(PKG_ROOT, 'package.json'), 'utf8'));
    const baseUrl = (process.env.DYNAM_NCP_BASE_URL ||
        'https://github.com/' + REPO + '/releases').replace(/\/+$/, '');
    const urls = [];
    if (process.env.DYNAM_NCP_RELEASE) {
        urls.push(baseUrl + '/download/' +
            process.env.DYNAM_NCP_RELEASE + '/' + target.asset);
    } else {
        urls.push(baseUrl + '/latest/download/' + target.asset);
        // Fallback: tag matching this package version
        urls.push(baseUrl + '/download/v' + pkg.version + '/' + target.asset);
    }

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dynam-ncp-'));
    const archive = path.join(tmpDir, target.asset);
    const extractDir = path.join(tmpDir, 'extract');
    fs.mkdirSync(extractDir, { recursive: true });

    let lastErr = null;
    let downloaded = false;
    for (const url of urls) {
        console.log('[dynam-ncp] Downloading ' + url);
        try {
            await download(url, archive, 5);
            downloaded = true;
            break;
        } catch (err) {
            lastErr = err;
            console.warn('[dynam-ncp]   -> ' + err.message);
        }
    }
    if (!downloaded) {
        warnAndExit('Could not download ' + target.asset + ' (' +
            (lastErr ? lastErr.message : 'unknown error') + ').');
    }

    try {
        extract(archive, extractDir);
    } catch (err) {
        warnAndExit('Failed to extract ' + target.asset + ': ' + err.message);
    }

    const found = findBinary(extractDir);
    if (!found) {
        warnAndExit('Archive did not contain an ncp binary.');
    }

    // Release assets ship ncp alongside its runtime: bundled shared libs
    // (lib/ + ncp.bin wrapper layout on Linux, *.dll on Windows,
    // Dynam.app on macOS) and the web/ UI. Copy the whole payload
    // directory so the binary actually starts on a stock system.
    fs.mkdirSync(VENDOR_DIR, { recursive: true });
    const payloadDir = path.dirname(found);
    if (fs.cpSync) {
        fs.cpSync(payloadDir, VENDOR_DIR, { recursive: true });
    } else {
        execFileSync('cp', ['-r', payloadDir + '/.', VENDOR_DIR], { stdio: 'pipe' });
    }

    try {
        verifyBinary(BIN_PATH);
    } catch (err) {
        try { fs.unlinkSync(BIN_PATH); } catch (_) { /* ignore */ }
        warnAndExit('Binary verification failed: ' + err.message);
    }

    // Cleanup temp files (best effort)
    try { fs.rmSync ? fs.rmSync(tmpDir, { recursive: true, force: true })
                    : execFileSync('rm', ['-rf', tmpDir]); } catch (_) { /* ignore */ }

    console.log('[dynam-ncp] Installed ' + BIN_NAME + ' -> ' + BIN_PATH);
    console.log('[dynam-ncp] Run `dynam-ncp --help` (or `ncp --help`) to get started.');
}

main().catch((err) => warnAndExit('Unexpected installer error: ' + err.message));
