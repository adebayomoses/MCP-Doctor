export interface ErrorExplanation {
  /** One short sentence saying what went wrong, in plain language. */
  title: string;
  /** What the person can do about it. */
  hint: string;
}

export interface ErrorContext {
  command?: string;
  url?: string;
  timeoutMs?: number;
  /** Last lines the server wrote to stderr, if any. */
  stderr?: string;
}

/**
 * Turn a low-level connection error into something a first-time user can act on.
 * The raw error is always kept elsewhere (reports show it as evidence); this only adds guidance.
 */
export function explainConnectError(raw: string, ctx: ErrorContext = {}): ErrorExplanation {
  const err = raw ?? "";
  const stderr = ctx.stderr ?? "";
  const seconds = Math.round((ctx.timeoutMs ?? 30000) / 1000);

  if (/\b(401|403)\b|unauthori[sz]ed|forbidden|not authenticated|authentication (?:is )?required|\b(?:invalid|missing|expired|bad)\b[^.]{0,25}\b(?:token|api[ _-]?key|credentials?|authorization)\b|oauth/i.test(err))
    return {
      title: "This server needs you to sign in.",
      hint: 'It rejected the connection because no valid credentials were sent. If you have a token, add it as a header, for example --header "Authorization: Bearer YOUR_TOKEN" (or the Headers box in the web app).',
    };

  if (/Invalid URL/i.test(err))
    return { title: "That does not look like a valid web address.", hint: "Use the full address, starting with https:// (or http:// for a server on your own computer)." };

  // The program exists but a file it needs does not: checked first, because its stderr can also say "not found".
  if (/MODULE_NOT_FOUND|Cannot find module|ModuleNotFoundError|No module named/i.test(stderr))
    return {
      title: "The server crashed on start because a file or package is missing.",
      hint: "Run the same command in a terminal to see the full error. You probably need to install its dependencies first (npm install, pip install) or fix the path to the script.",
    };

  // The program itself does not exist. Depending on the OS and shell this shows up in the error or only on stderr
  // (Windows: "'x' is not recognized as an internal or external command"; sh: "x: not found").
  if (ctx.command && /ENOENT|is not recognized as an internal|command not found|: not found\b|not found in PATH/i.test(`${err}\n${stderr}`))
    return {
      title: `The program "${ctx.command.split(/\s+/)[0]}" was not found.`,
      hint: "Check the spelling, and make sure it is installed and on your PATH. For Node servers start the command with node or npx; for Python servers use python or uvx.",
    };

  if (/ECONNREFUSED|ENOTFOUND|EAI_AGAIN|fetch failed|ECONNRESET|certificate|ETIMEDOUT/i.test(err))
    return {
      title: `Could not reach ${ctx.url ? new URL(ctx.url).host : "the server"}.`,
      hint: "Check the address, your internet connection, and that the server is actually running. For a server on your own computer, start it first.",
    };

  if (/timed out/i.test(err))
    return {
      title: `The server did not finish starting within ${seconds} seconds.`,
      hint: ctx.command && /^(npx|uvx|pnpm|bunx|dlx)/i.test(ctx.command)
        ? "The first run of npx or uvx has to download the package, which can be slow. Try again; the second run is usually much faster. You can also raise the limit with --timeout."
        : "It may be hanging or waiting for input. Run the command in a terminal to see what it prints, or raise the limit with --timeout.",
    };

  if (/protocol version/i.test(err))
    return {
      title: "The server speaks a protocol version this tool does not know.",
      hint: "Update the server's MCP SDK to a current release, or update mcp-detector if the server is newer.",
    };

  if (/\b404\b/.test(err) && ctx.url)
    return { title: "The address answered, but there is no MCP server at that path.", hint: "MCP endpoints are often at a path such as /mcp or /sse. Check the server's documentation for the right URL." };

  if (/Connection closed|exited|EPIPE/i.test(err))
    return {
      title: "The server stopped right after starting.",
      hint: stderr.trim()
        ? "Its own error output is shown below the finding. Fix that, then try again."
        : "Run the same command in a terminal to see why it exits; servers often print the reason when they stop.",
    };

  return { title: "Could not connect to the server.", hint: "Run the same command (or open the same address) on its own to check that it works, then try again." };
}
