# Figma-scoped runtime analysis

When the pentest scope is **one updated feature flow**, use its Figma design as a machine-readable
scope boundary + expected-behavior oracle, then auto-drive/analyze only that flow.

## Why it works
- Figma frames = the exact in-scope screens; element labels/texts = what to tap/fill; prototype
  links = the navigation order → the agent knows precisely what is (and isn't) in scope.
- The design is the oracle: deviations (missing validation, hidden fields/endpoints, client-only
  checks) are findings.

## Setup — open-figma-mcp (self-hosted, no cloud token)
Talks to the **open Figma desktop file** via a local dev plugin (bridge on `ws://localhost:3055`).
```bash
# one-time (quits & relaunches Figma desktop):
npx -y open-figma-mcp install-plugin        # or --no-quit / --no-relaunch
claude mcp add open-figma-mcp --scope user -- npx -y open-figma-mcp   # (Claude Code)
# opencode: already added to ~/.config/opencode/opencode.json (mcp.open-figma-mcp)
```
Then: open the target Figma file → **Plugins → Development → Open Figma MCP** → call
`figma_status` (dot turns green). Tools: `figma_status`, `figma_get_pages`/`set_page`,
`figma_get_selection`, `figma_get_metadata`, `figma_screenshot`, `figma_exec` (arbitrary Plugin API).

## Run it
Select the feature's frames in Figma, then: `/scope-flow <package>`. The command ingests the flow,
sets up scoped instrumentation, drives only those screens via `uiautomator2-mcp`, and reports per
Figma screen.

## Scope discipline (important)
- Only the screens/inputs present in the selected frames are in scope.
- Network logging + Frida hooks are filtered to the flow's endpoints/handlers — do not observe or
  touch unrelated features.
- If a finding needs action outside the flow, STOP and flag it; don't expand scope.
- Dynamic traffic hits the authorized/local backend only.

_Tooling: open-figma-mcp (pradityaaldi), uiautomator2-mcp, runtime/ Frida scripts._
