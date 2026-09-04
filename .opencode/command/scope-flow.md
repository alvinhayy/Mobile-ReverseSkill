---
description: Scope-constrained runtime analysis of ONE feature flow, driven by its Figma design (open-figma-mcp + uiautomator2 + Frida)
argument-hint: "<package>  (select the scoped feature's frames in Figma first)"
allowed-tools: Bash(adb:*), Bash(frida:*), Bash(frida-ps:*)
---

Analyze **only** the in-scope feature flow of `$ARGUMENTS`. The Figma design is the **scope
contract** (which screens/actions are allowed) and the **oracle** (expected behavior). Stay strictly
inside the flow — if something requires acting outside it, STOP and flag it.

### 1. Ingest scope from Figma (desktop: open-figma-mcp · browser/cloud: figma-rest)
- **Desktop**: `figma_status` (green) then select the frames. **Browser/cloud**: use `figma-rest`
  `get_figma_data` with the file/node URL of the scoped frames (needs `FIGMA_API_KEY`). See
  `docs/figma-scoped-analysis.md`.
- Have the user select the feature's frames, then `figma_get_selection` +
  `figma_get_metadata` (ordered screens, element names/text, inputs, buttons) +
  `figma_screenshot` each frame. Read prototype interactions for navigation order.
- Write a **SCOPE CONTRACT**: the ordered in-scope screens, the in-scope inputs/actions, and any
  endpoint/field hints. Everything not in these frames is OUT OF SCOPE.

### 2. Lab + scoped instrumentation
- Device up (`/spawn`), frida ready (`/setup`), `connect_device`, app installed.
- Attach `runtime/ssl-pinning-universal.js` + a network logger **filtered to this flow's endpoints
  only**; hook only the feature's handlers if identifiable (`runtime/rn-frida-hook.js` /
  `crypto-dump.js` scoped). Do NOT hook or observe unrelated features.

### 3. Map Figma → app
`app_start`, `dump_hierarchy_summary`; match Figma frame texts/element labels to the live UI.
Build a step plan bounded to the flow.

### 4. Drive the flow (uiautomator2-mcp)
Walk the exact screens in Figma order; enter test inputs (valid per Figma + targeted malicious
**only for in-scope fields**); `screenshot` each state; correlate app screen ↔ Figma frame. Stop at
the flow's end per Figma — do not navigate beyond scope.

### 5. Analyze within scope
For this flow's endpoints/inputs/storage: input validation, authz/IDOR on the flow's calls,
insecure storage of the flow's data, and **deviations from the Figma spec** (missing validation,
hidden extra fields/endpoints, client-only checks). Keep everything scoped to the feature.

### 6. Report
Per Figma screen: screen → observed behavior → finding / scope-note. Explicitly confirm the scope
boundary was respected. Save to `<out>/scope-flow-report.md`.

Authorized, scoped engagement only.
