export function escapeShell(cmd: string): string {
    return '"' + cmd.replace(/(["'$`\\])/g, '\\$1') + '"';
}
