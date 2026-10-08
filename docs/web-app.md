# The web app

`mcp-detector ui` opens a small web app in your browser so you can check an MCP server without remembering any command-line options.

```bash
mcp-detector ui
```

It prints a link and opens it for you. Keep the terminal window open while you use the app; press **Ctrl+C** to stop it. Options: `--port <n>` (default: any free port) and `--no-open` (print the link without opening a browser).

## What you can do

| Tab | What it does |
|---|---|
| **Try the demo** | Scans a built-in example server (one deliberately unsafe, one well built) so you can see what a report looks like. Nothing on your computer is touched. |
| **Paste a command** | Type the command that starts your MCP server, for example `npx -y @modelcontextprotocol/server-everything`. You must tick a box confirming that this starts the program on your computer. |
| **Web address** | Scan a remote server by URL. If it needs a sign-in, add a header such as `Authorization: Bearer …`. |
| **Servers I already use** | Lists servers configured in Claude Desktop, Cursor, VS Code, Windsurf and Claude Code. Tick the ones to scan (again with a confirmation box). |

Results appear below the form: a score, the number of findings by severity, and the full report (category bars, every finding with its evidence, why it matters and how to fix it). You can download the report as HTML or the data as JSON. Earlier scans are listed so you can reopen them.

By default a scan is **passive**: it connects, lists tools, resources and prompts, and never calls a tool. The command tab has an opt-in box to also time read-only tools; leave it off if you are unsure.

## When something goes wrong

Errors are explained in plain language with a next step, for example:

- *The program "foo" was not found.* Check the spelling, and make sure it is installed and on your PATH.
- *The server did not finish starting within 30 seconds.* The first run of `npx` has to download the package; try again.
- *This server needs you to sign in.* Add a token as a header.
- *The server crashed on start because a file or package is missing.* Run the same command in a terminal to see the full error.

The underlying technical error is still shown in the report as the evidence for finding MCP-001.

## Security model

The app can start programs on your computer, so it is locked down:

- **Local only.** It listens on `127.0.0.1`, never on a network interface.
- **Private access key.** Every start generates a random key, carried in the link's `#fragment`. Browsers never send fragments to servers, so it does not appear in logs or `Referer` headers, and the page removes it from the address bar immediately. Every API call must include it (checked in constant time). Without it the page shows instructions instead of data.
- **Other websites cannot drive it.** Requests must be addressed to `localhost` or `127.0.0.1` on the app's own port (this defeats DNS-rebinding), cross-site requests are refused, and no CORS headers are ever sent, so a web page you happen to visit cannot make your browser start scans.
- **Explicit consent to run things.** Starting a command or an installed server requires a confirmation in the request itself, not only a checked box in the page. Servers chosen from your apps are started by id; the browser never supplies their command line, environment or headers.
- **Credentials stay out of results.** Headers you type are used for that scan only. They are never stored, returned by the API, written to history, or shown in reports, and tokens in command lines and URLs are redacted from labels and targets.
- **Server output is untrusted.** The report is rendered by the server as escaped, script-free HTML and displayed inside a fully sandboxed `<iframe>`. The page's Content-Security-Policy allows a single nonce-protected script and no network resources, so a hostile MCP server cannot run code in your browser.
- **Limits.** At most two scans run at once, request bodies are capped at 64 KB, finished jobs expire after 30 minutes, and unknown routes and malformed ids are rejected.

If you run `mcp-detector ui` on a shared machine, remember that other local users could connect to the port but cannot use it without the key.

Like the command line, scanning a local (stdio) server **runs that server**, with your privileges. Only scan programs you would be willing to run.
