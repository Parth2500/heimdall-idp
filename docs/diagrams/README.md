# Diagrams

The diagrams use Mermaid. GitHub renders them in the browser. In VS Code, use a Markdown preview with Mermaid support.
The diagrams show the design in `docs/threat-model.md` and `docs/schema-design.md`. When a design decision changes, change the diagram in the same commit.

| File | Content |
|---|---|
| [01-architecture.md](01-architecture.md) | Layers, system context with trust boundaries, settings layers |
| [02-authorization-code-flow.md](02-authorization-code-flow.md) | Full authorization code flow with PKCE, decisions at `/token` |
| [03-refresh-and-reuse.md](03-refresh-and-reuse.md) | Refresh rotation, reuse detection, double redemption race, state diagrams |
| [04-data-model.md](04-data-model.md) | Entity relationship diagram |
| [05-keys-and-jwks.md](05-keys-and-jwks.md) | Signing key lifecycle, rotation, order of rotation steps, JWKS request path |
| [06-login-and-session.md](06-login-and-session.md) | Login checks, session cookie, abuse control layers, consent and CSRF |
