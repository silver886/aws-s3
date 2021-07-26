#!/usr/bin/env -S npx ts-node

import * as fs from 'fs';
import * as path from 'path';
import * as process from 'process';

import * as utils from './utils/';

const ROOT = process.cwd();
const PATHS: string[] = [];

function npmRunBundleRecursive(folder: string): utils.concurrently.Command[] {
    const hasPackageJson = fs.existsSync(path.join(folder, 'package.json'));
    const relativePath = path.relative(ROOT, folder);
    const commands: utils.concurrently.Command[] = [];

    /**
     * If there is `package.json` in this folder
     * and relative folder path contain lambda
     * and this is not the root folder
     * and `bundle` is available
     * then perform `npm run bundle`.
     */
    if (hasPackageJson && relativePath.includes('lambda') && folder !== ROOT) {
        const {scripts} = JSON.parse(fs.readFileSync(path.join(folder, 'package.json')).toString()) as {
            scripts: Record<string, string>;
        };
        if (scripts.bundle) {
            commands.push({
                command: 'npm run bundle',
                where:   relativePath,
            });
            PATHS.push(relativePath);
        }
    }

    // Recurse into subfolders
    utils.subfolders.usesNode(folder).forEach((subfolder) => {
        commands.push(...npmRunBundleRecursive(subfolder));
    });

    return commands;
}

utils.concurrently.exec(ROOT, npmRunBundleRecursive(ROOT)).
    then(async () => Promise.all(PATHS.map(async (v) => {
        const src = path.resolve(ROOT, v, 'dist');
        const dest = path.resolve(ROOT, v.replace(/^src/u, 'lib'));
        return fs.promises.mkdir(dest, {recursive: true}).
            then(async () => fs.promises.readdir(src, {withFileTypes: true})).
            then((entries) => entries.map(async (e) => fs.promises.copyFile(path.join(src, e.name), path.join(dest, e.name))));
    }))).
    then(() => {
        // eslint-disable-next-line no-console
        console.log('Finished (npm run bundle && copy)');
    }).
    catch(() => {
        // eslint-disable-next-line no-console
        console.error('Failed (npm run bundle && copy)');
        // eslint-disable-next-line @typescript-eslint/no-magic-numbers
        process.exit(1);
    });
