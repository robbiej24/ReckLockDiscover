# Manifest export

Pass `--export-manifests` to emit **unsigned** YAML manifests suitable for review & import into **ReckLock Registry** after editing.

## Output location

Defaults to:

```
<output-dir>/recklock_manifest_exports/
```

Override with `--manifest-dir`.

## Which findings export?

Exports are generated for findings whose `recommended_action` is one of:

- `register`  
- `govern`  
- `manual_review`  

Each manifest includes inferred capabilities, permission scopes, model providers (when LLM signals exist), risk level, and structured metadata pointing back to the originating path.

## Validation

Drafts are validated against the same core fields ReckLock Registry expects (`AgentManifest` in `manifest_schema.py`). Unknown metadata keys from the scanner are ignored by downstream tooling when using standard Pydantic settings.

## Operational guidance

1. Treat files as **drafts** — rename agents, tighten scopes, & attach owners before publishing.  
2. Store manifests in version control only **after** removing sensitive commentary if needed.  
3. Coordinate imports with Registry maintainers so IDs do not collide with existing agents.
