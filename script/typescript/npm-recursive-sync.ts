#!/usr/bin/env -S npx ts-node

import * as child_process from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as process from 'process';

import * as utils from './utils/';

const ROOT = process.cwd();

// eslint-disable-next-line @typescript-eslint/no-magic-numbers
const COMMAND = process.argv.slice(2).join(' ');

function commandRecursive(folder: string): void {
    const hasPackageJson = fs.existsSync(path.join(folder, 'package.json'));

    /**
     * If there is `package.json` in this folder
     * then perform commands.
     */
    if (hasPackageJson && folder !== ROOT) {
        // eslint-disable-next-line no-console
        console.log(`Current directory: ${folder}`);
        child_process.execSync(COMMAND, {
            cwd:   folder,
            env:   process.env,
            stdio: 'inherit',
        });
    }

    // Recurse into subfolders
    utils.subfolders.usesNode(folder).forEach((subfolder) => {
        commandRecursive(subfolder);
    });
}

commandRecursive(ROOT);
