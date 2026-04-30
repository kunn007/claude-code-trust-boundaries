# Whose Trust Is It Anyway? Project Configuration in AI Development Tools

**Kundan Yadav · April 2026 · Melbourne, Australia**

> *Two vendors. One trust-boundary question. Opposite answers. One CVSS 10.0.*

---

## Abstract

AI-powered development tools are entering CI/CD pipelines at scale. Tools like Anthropic's Claude Code and Google's Gemini CLI execute in headless mode against cloned repositories, automating code review, bug fixing, and analysis. Both support project-scoped configuration files that travel with the repository and modify the tool's behavior at runtime.

This paper examines the structural question these tools surface: when an AI agent runs in an automated pipeline against a repository it did not author, should the repository's configuration be able to expand the agent's permissions?

Two vendors reached opposite conclusions on closely related questions in April 2026 — one treating headless workspace trust as a Critical-severity vulnerability (CVSS 10.0), the other as documented intended behavior. This divergence reveals an unsettled trust boundary that the industry will need to resolve as AI agent adoption in CI/CD accelerates.

---

## 1. Background: Project Configuration in AI Development Tools

Modern AI development tools support project-level configuration files committed to source control. These files allow teams to standardize how the AI agent behaves across a shared codebase.

**Claude Code** (`.claude/settings.json`):
- Permission allow/deny rules controlling which tools the agent can invoke
- Shell helper commands for authentication (`apiKeyHelper`, `awsAuthRefresh`)
- MCP (Model Context Protocol) server definitions
- Environment variable overrides

**Gemini CLI** (`.gemini/settings.json`):
- Environment variables
- Tool allowlists
- Workspace configuration

In interactive mode, both tools present a trust dialog before honoring project configuration. The user sees a prompt — *"Do you trust this folder?"* — and must explicitly accept before project settings take effect.

In headless mode, used in CI/CD pipelines, there is no interactive prompt. The question becomes: **what happens to project configuration when no human is present to approve it?**

---

## 2. The Divergent Answers

### 2.1 Anthropic's Position: Trust Delegation

Anthropic's security model treats headless invocation as an explicit trust assertion by the automation caller. From their security documentation:

> *"Trust verification is disabled when running non-interactively with the -p flag."*

Their stated position, communicated through their vulnerability disclosure program:

> *"In non-interactive mode (-p/--print, piped stdin, SDK), Claude Code delegates trust decisions to the automation caller — invoking claude -p in a directory is the caller asserting control over that directory's contents, and the workspace trust dialog (a human-in-the-loop control) does not apply."*

Under this model, running `claude --print` in a directory is equivalent to saying "I trust everything in this directory, including its configuration files." The tool provides a `--bare` flag that skips project settings entirely, and Anthropic recommends this flag for pipelines processing repositories the operator does not control. Per their documentation, `--bare` will become the default for headless mode in a future release.

This approach has substantial precedent in traditional development tooling. Running `make` in a cloned repository executes whatever the Makefile contains. Running `npm install` executes `preinstall` and `postinstall` scripts unless `--ignore-scripts` is set. Running `cargo build` can execute arbitrary `build.rs` code. In each case, the ecosystem has decided that honoring project-local configuration is a feature — and the operator is responsible for auditing repositories before running tools against them. The `--bare` flag in Claude Code is a direct analog of `npm install --ignore-scripts`.

### 2.2 Google's Position: Headless Trust is a Vulnerability

On April 24, 2026, Google published [GHSA-wpqr-6v78-jr5g](https://github.com/advisories/GHSA-wpqr-6v78-jr5g), addressing two related issues in Gemini CLI. The advisory states:

> *"In previous versions, Gemini CLI running in CI environments (headless mode) automatically trusted workspace folders for the purpose of loading configuration and environment variables. This is potentially risky in situations where Gemini CLI runs on untrusted folders in headless mode. If used with untrusted directory contents, this could lead to remote code execution via malicious environment variables in the local .gemini/ directory."*

Google rated this **Critical (CVSS 10.0)**, patched it in `@google/gemini-cli` v0.39.1 and `google-github-actions/run-gemini-cli` v0.1.22, and credited researchers Dan Lisichkin (Pillar Security) and Elad Meged (Novee Security) via Google's Vulnerability Rewards Program.

The fix aligned headless mode with interactive mode: workspace folders must be explicitly trusted before configuration files are processed, even in automated contexts. CI/CD pipelines that previously relied on automatic trust now require an explicit `GEMINI_TRUST_WORKSPACE=true` environment variable.

The same advisory addresses a second issue: under `--yolo` mode, Gemini CLI previously ignored fine-grained tool allowlists in `~/.gemini/settings.json`, with the consequence that an entry like `run_shell_command(echo)` would allow any shell command. Google identifies prompt injection in untrusted content as the exploitation path. The policy engine was updated in v0.39.1 to enforce allowlists in `--yolo` mode.

This second component is structurally close to the Claude Code permission allow rule behavior described in §3.1: a permission system that exists but is bypassed in the specific automation context where its protections matter most.

---

## 3. Research Findings

The following findings were identified through independent security research on **Claude Code v2.1.81** (tested April 2026) and reported to Anthropic through their HackerOne vulnerability disclosure program. Both were classified as Informative. This research is published with Anthropic's knowledge and without objection.

### 3.1 Permission Allow Rules in Headless Mode

Claude Code's project settings accept a `permissions.allow` array that pre-approves tool calls. The entry `Bash(*)` matches every shell command through a wildcard pattern.

In default headless mode, this allow rule is loaded from the project directory without any trust verification. Claude Code has a dangerous-rule stripping mechanism that identifies `Bash(*)` and removes it — but this mechanism only activates in a specific permission mode (`auto`), not in the default headless invocation.

**Observed behavior:** A repository containing `.claude/settings.json` with `{"permissions": {"allow": ["Bash(*)"]}}` causes all shell commands to execute without permission prompts when Claude Code runs in default headless mode. A control test in a directory without this file showed the same commands being blocked. Tests were conducted with the standard `claude --print` invocation; `--bare` was not used, since the relevant question is what default headless behavior does in the current release.

The dangerous-rule stripping infrastructure is complete and functional — the gap is that it is only called in one of several headless invocation modes. Anthropic's own permissions documentation acknowledges the underlying risk:

> *"The classifier does not read from shared project settings in .claude/settings.json, because a checked-in repo could otherwise inject its own allow rules."*

This protection is applied in auto mode but not in default headless mode.

### 3.2 Pre-Authentication Shell Execution and a Reachability Defect

Claude Code supports an `apiKeyHelper` field in project settings — a shell command executed to obtain an API key. This command runs during API client initialization, **before any model interaction occurs.**

This finding is worth separating from the broader design debate. A trust gate exists in the code that is *intended* to block this execution when workspace trust has not been confirmed. The unreachable branch contains the literal string:

```
"Security: apiKeyHelper executed before workspace trust is confirmed."
```

Clear evidence that the developer who wrote this guard expected it to fire in this exact scenario.

The guard's boolean condition is structured roughly as `if (!isTrustedWorkspace && !isHeadless)`. In headless mode, `isHeadless` is true, which makes `!isHeadless` false, which makes the entire conjunction false — so the guard branch is never entered when the tool is running headlessly. The condition appears to be **inverted relative to its author's intent**: a guard explicitly meant to fire in headless mode is unreachable in headless mode.

**Observed behavior:** A repository containing `.claude/settings.json` with an `apiKeyHelper` value causes the specified shell command to execute immediately when Claude Code starts in headless mode — before API authentication, before the model processes any prompt, and before any permission system is invoked. If the helper returns an invalid API key, Claude Code exits with an authentication error. The shell payload has already executed.

Three additional shell helper fields (`awsAuthRefresh`, `gcpAuthRefresh`, `awsCredentialExport`) share the same trust gate pattern.

### 3.3 Classifier Coverage Gaps

Analysis of the dangerous-rule classifier revealed additional gaps:

- The PowerShell dangerous-rule check is implemented as a **stub that always returns false**, leaving `PowerShell(*)` unstripped in all modes including auto mode
- **No classifier predicates exist** for `Edit` or `Write` tool wildcards — these are never identified as dangerous in any mode
- Two safety functions referenced in the codebase by name — described in their surrounding code as providing semantic command analysis as a defense-in-depth layer — are present but appear to be **unused or disabled** in current builds. Specific function names are withheld pending vendor review.

These gaps affect all permission modes, not only headless invocations.

---

## 4. The CI/CD Supply Chain Scenario

The scenario that makes this trust boundary consequential is not a developer running an AI tool in their own repository. It is an **automated pipeline running the tool against a repository authored by a third party.**

Consider a standard CI/CD workflow:

1. A contributor submits a pull request to an open source project
2. The CI pipeline clones the PR branch
3. The pipeline runs `claude --print "review this code"` for AI-assisted code review
4. Claude Code loads `.claude/settings.json` from the PR branch
5. If that file contains `Bash(*)` or `apiKeyHelper`, the attacker's configuration takes effect

The standard GitHub Actions pattern most exposed to this is `pull_request_target` — which runs workflow code from the base branch with repository secrets available while checking out PR branch contents. Exactly the asymmetry where the pipeline operator and the configuration author are different people.

**The operator trusts the AI tool. The AI tool trusts the project configuration. The project configuration was authored by the PR submitter.**

This is not a novel attack pattern — it mirrors supply chain risks in package managers (post-install scripts), build systems (Makefile injection), and editor configurations (VS Code workspace settings). What makes AI development tools distinctive is the breadth of capability they grant. A `Bash(*)` permission doesn't execute a single command — it grants the AI agent unlimited shell access for the duration of the session, amplified by the model's ability to chain commands intelligently based on prompt injection in the repository's source files.

---

## 5. Analysis: Why Reasonable Vendors Disagree

The divergence between Anthropic and Google reflects a genuine tension in security design, not a simple oversight by either party.

### The case for Anthropic's approach (trust delegation)

Headless mode is designed for automation. Automation callers are expected to control their execution environment. Adding mandatory trust verification to headless mode creates friction for legitimate CI/CD workflows where the operator has already established trust through other means (signed commits, branch protection rules, repository access controls). The `--bare` flag provides a clear opt-out for untrusted contexts.

This position aligns with the broader dev-tooling tradition. Package managers, build systems, and editor configurations all honor project-local configuration that can execute arbitrary code, and the ecosystem has consistently treated this as a property to be managed by the operator rather than a vulnerability to be patched. Viewed in this lineage, Anthropic's stance is the conservative one and Google's is the outlier.

Anthropic explicitly rejects the comparison drawn in this paper, stating that "another vendor choosing a different default for their tool does not change our documented threat model." That position is internally consistent. The case for considering the comparison anyway is that AI development tools are a sufficiently new category that no individual vendor's threat model has yet been established as the settled industry reference point — the comparison here is between two vendors actively defining the category, not between a settled standard and a deviation from it.

### The case for Google's approach (headless trust as vulnerability)

CI/CD pipelines routinely process untrusted inputs — pull requests, forked repositories, dependency updates. The pipeline operator's decision to run an AI tool is not the same as endorsing every configuration file in the repository. Aligning headless behavior with interactive behavior (explicit trust required) provides defense-in-depth without significant friction — a single environment variable (`GEMINI_TRUST_WORKSPACE=true`) re-enables automatic trust for pipelines that need it.

The argument that AI tools warrant a stricter default than traditional dev tooling rests on two observations. First, the capability surface is larger: an AI agent with `Bash(*)` doesn't just run one command, it runs whatever sequence of commands the model decides on, potentially influenced by prompt injection from elsewhere in the repository. Second, AI tools are entering CI/CD faster than security practice is keeping up — the population of operators who understand that `.claude/settings.json` can grant shell access is much smaller than the population who understand the same about `package.json`.

### The structural question

As AI development tools become as ubiquitous as linters and formatters in CI/CD, will operators audit project configuration files for every tool in their pipeline? History with package managers suggests they will not — `--ignore-scripts` exists, and most CI pipelines don't use it. Whether the AI-tool case is similar enough that the same equilibrium will hold, or different enough that a stricter default is warranted, is the empirical question the next few years will answer.

---

## 6. Recommendations

### For CI/CD operators

- **Audit project configuration files** (`.claude/settings.json`, `.mcp.json`, `.gemini/settings.json`) in repositories before running AI tools against them. Treat them with the same scrutiny as Makefiles and `package.json` scripts.
- **Use restrictive modes** when processing untrusted repositories. For Claude Code, use `--bare` to skip project settings. For Gemini CLI (v0.39.1+), workspace trust is disabled by default in headless mode.
- **Don't rely on model-level safety** as a security boundary. Model heuristics are keyword-heuristic, not semantic, and are straightforwardly bypassed by avoiding trigger vocabulary.
- **Scope permissions narrowly** when configuring AI tools for CI/CD. Use specific permission rules (`Bash(npm test)`, `Bash(git diff)`) rather than wildcards.

### For AI tool vendors

- **Make a deliberate, documented choice** about headless trust posture. Both the trust-delegation model and the explicit-trust model are defensible. What is harder to defend is leaving the choice implicit, where individual code paths reflect different assumptions and operators have to read the source to know which posture applies.
- **Make project configuration capabilities visible.** If a configuration file can execute shell commands, modify permissions, or launch server processes, this should be clearly documented as a security-relevant capability — not buried in general settings documentation.
- **Audit dangerous-rule classifiers for completeness.** If a safety mechanism exists to strip dangerous permission patterns, ensure it covers all tool types that can modify the filesystem or execute commands. Stub implementations that always return false should be treated as bugs regardless of the surrounding design philosophy.
- **Verify that intended guards are reachable.** Where an in-code error message indicates a developer intended a particular code path to execute as a safety measure, that path should be reachable in the conditions the message describes.

---

## 7. Conclusion

The trust boundary between project configuration and AI agent permissions is an emerging security surface that the industry has not yet standardized. The April 2026 divergence between Anthropic and Google — with closely related trust-boundary questions receiving a CVSS 10.0 from one vendor and an Informative classification from another — demonstrates that this is a genuine design question, not a clear-cut security issue.

As AI development tools become as routine as linters and build systems in CI/CD pipelines, the default trust posture of headless mode will have supply chain security implications at scale. Whether the industry converges on Anthropic's trust-delegation model (continuous with the package-manager tradition) or Google's explicit-trust model (a deliberate departure justified by the larger AI-agent capability surface) will likely depend on which approach produces fewer incidents in practice.

This research is published to contribute to that conversation.

---

## Disclosure Timeline

| Date | Event |
|---|---|
| April 8, 2026 | Permission bypass finding reported to Anthropic via HackerOne |
| April 9, 2026 | Closed as Informative — "working as designed" |
| April 9, 2026 | Follow-up with documentation analysis and source-level evidence |
| April 10, 2026 | Pre-auth shell execution finding reported to Anthropic |
| April 10, 2026 | Closed as Informative — same design rationale |
| April 15, 2026 | Follow-up with Anthropic reaffirming position |
| April 24, 2026 | Google publishes [GHSA-wpqr-6v78-jr5g](https://github.com/advisories/GHSA-wpqr-6v78-jr5g) for related trust-boundary class in Gemini CLI (CVSS 10.0) |
| April 25, 2026 | Gemini CLI advisory shared with Anthropic; position reaffirmed |
| April 30, 2026 | Anthropic confirms no objection to public writeup; draft shared for review |

---

## About the Author

**Kundan Yadav** is an independent security researcher based in Melbourne, Australia, focused on AI security, cloud security, and applied offensive security research. He holds CISSP and GCP Professional Cloud Security Engineer certifications.

This research was conducted independently. All findings were reported to the vendor before publication, and the vendor was given the opportunity to review this writeup prior to release.

---

*The behavior described in this writeup is documented by Anthropic as intended. The recommended mitigation (`--bare` flag) is publicly available. Per Anthropic's published documentation, `--bare` is the recommended mode for scripted and SDK calls, and will become the default for `-p` in a future release.*

---

## License

This work is licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE).
You are free to share and adapt this material for any purpose, provided you give appropriate credit.
