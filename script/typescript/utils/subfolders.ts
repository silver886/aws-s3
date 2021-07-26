import * as fs from 'fs';
import * as path from 'path';

// Lists subfolders which has node_modules in a folder.
export function usesNode(folder: string): string[] {
    return fs.readdirSync(folder).
        filter((subfolder) => fs.statSync(path.join(folder, subfolder)).isDirectory()).
        filter((subfolder) => subfolder !== 'node_modules' && !subfolder.startsWith('.')).
        map((subfolder) => path.join(folder, subfolder));
}
