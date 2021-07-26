import * as concurrently from 'concurrently';
import * as path from 'path';

export interface Command {
    command: string;
    where: string;
}

export async function exec(root: string, commands: Command[]): Promise<concurrently.ExitInfos[]> {
    return concurrently(commands.map((command) => ({
        command:     command.command,
        cwd:         path.join(root, command.where),
        env:         process.env,
        name:        `${command.where} | ${command.command}`,
        prefixColor: 'bgBlack.gray',
    })));
}
