/**
 * Shell quoting for recipes that compose command text.
 *
 * A recipe splices its values into a command a shell reads: a `script`'s `check`
 * and `run`, or a script it writes to a file. Each value goes in as one
 * single-quoted word, inside which a shell reads every byte literally except a
 * single quote — so a value can't change what the command means, whatever it
 * holds (`$`, backticks, `"`, `;`, spaces, newlines).
 *
 * A value may be a reference (`env_ref` / `zap.env`). Its marker holds no single
 * quote, so it lands inside the quotes, and zap refuses to resolve a reference
 * whose value holds one when the command runs. A literal single quote in the
 * text is escaped (`'\''`), which is what it means inside single quotes.
 *
 * A pure function, like the recipes that import it: it only assembles a string.
 * Beside it are the checks of the names recipes write into commands and config:
 * `sudo_as_user` and `ACCOUNT_NAME`.
 *
 * @module
 */

/**
 * What an account name a recipe writes must be: a lowercase letter or `_`, then
 * lowercase letters, digits, `_` or `-`, optionally ending in `$`, exactly the
 * schema's `AccountName`. Never a uid or gid, so `0` can't stand in for root, and
 * never a pattern or a list, as sshd's `AllowUsers` would read `*`, `?`, `!`,
 * `user@host`, or a `,`.
 */
export const ACCOUNT_NAME = /^[a-z_][a-z0-9_-]*\$?$/;

/**
 * `value` as one single-quoted shell word, each `'` in it written `'\''`.
 *
 * The twin of zap's own quoting for the values it composes into commands, so a
 * recipe's command quotes the way zap's do.
 *
 * @param value - the text, literal or holding references
 * @returns the quoted word
 */
export const single_quote = (value: string): string => `'${value.replaceAll("'", "'\\''")}'`;

/**
 * The `sudo -u <user> ` prefix of a command a recipe runs as `user`, refusing a `user`
 * that wouldn't name the account the recipe means.
 *
 * `sudo -u` reads a `user` starting with `#` as a uid (`#0` is root), and an empty one
 * as nothing at all. A reference (`env_ref` / `zap.env`) is refused too: its value
 * isn't known until the command runs, so a recipe can't check it, and a value of `#0`
 * would run the command as root.
 *
 * @param recipe - the recipe's name, for the error
 * @param user - the account's name
 * @returns `sudo -u` and the quoted name, then a space
 * @throws Error if `user` is empty, starts with `#`, or holds a reference
 */
export const sudo_as_user = (recipe: string, user: string): string => {
	if (/[\uFDD0\uFDD1]/.test(user)) {
		throw new Error(
			`${recipe}: user must be written out, not a reference, because \`sudo -u\` reads a value starting with \`#\` as a uid (\`#0\` is root) and a reference's value isn't known until it runs`
		);
	}
	if (user === '' || user.startsWith('#')) {
		throw new Error(
			`${recipe}: user ${JSON.stringify(
				user
			)} must be a user name, not empty and not \`#<uid>\`, because \`sudo -u\` reads \`#\` as a uid (\`#0\` is root)`
		);
	}
	return `sudo -u ${single_quote(user)} `;
};
