#!/usr/bin/env -S npx ts-node

import * as fs from 'fs';
import * as path from 'path';
import * as process from 'process';

import * as utils from './utils/';

const ROOT = process.cwd();

// eslint-disable-next-line @typescript-eslint/no-magic-numbers
const COMMAND = process.argv.slice(2).join(' ');

function commandRecursive(folder: string): utils.concurrently.Command[] {
    const hasPackageJson = fs.existsSync(path.join(folder, 'package.json'));
    const relativePath = path.relative(ROOT, folder);
    const commands: utils.concurrently.Command[] = [];

    /**
     * If there is `package.json` in this folder
     * then perform commands.
     */
    if (hasPackageJson && relativePath !== '') {
        commands.push({
            command: COMMAND,
            where:   relativePath,
        });
    }

    // Recurse into subfolders
    utils.subfolders.usesNode(folder).forEach((subfolder) => {
        commands.push(...commandRecursive(subfolder));
    });

    return commands;
}

utils.concurrently.exec(ROOT, commandRecursive(ROOT)).
    then(() => {
        // eslint-disable-next-line no-console
        console.log(`Finished (${COMMAND})`);
    }).
    catch(() => {
        // eslint-disable-next-line no-console
        console.error(`Failed (${COMMAND})`);
        // eslint-disable-next-line @typescript-eslint/no-magic-numbers
        process.exit(1);
    });
