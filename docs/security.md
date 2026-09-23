# BELTU Security Model

BELTU uses multiple security boundaries. They are intentionally separate: the **reasoning context boundary** protects every reasoning model from attacker-controlled target text, while the **cloud privacy boundary** adds stricter controls before any Gemini request.

## 1. Trust boundary for target-derived text

Target-controlled material can arrive from HTTP responses, browser DOM text, JavaScript, API responses, headers, crawler output, fuzzing logs, and tool output. That content is data, not BELTU instructions.

The mandatory path is:

\`\`\`text
Target / Tool / Browser / API
          |
          v
ObservationPipeline
          |
          v
Persistent local observations/evidence
          |
          v
ContextBuilder
  - joins observations
  - builds attack/intelligence context
          |
          v
ContextSecurityBoundary   <-- mandatory reasoning trust boundary
  - bounded sizes
  - secret redaction
  - Unicode/control normalization
  - trust labels
  - fail-closed configuration
          |
          v
AgentContext
          |
          v
Reasoning prompt
  <BELTU_TARGET_DATA> ... </BELTU_TARGET_DATA>
          |
          v
Local reasoning model
\`\`\`

The raw observations can remain in the local persistence/evidence layer for authorized testing and evidence handling. They must not be passed directly from a tool adapter into the reasoning provider.

## 2. What ContextSecurityBoundary does

\`src/beltu/brain/context_security.py\` is the explicit boundary used by \`ContextBuilder\`.

Before \`ContextBuilder.build()\` returns its \`AgentContext\`, the boundary:

1. Normalizes text with Unicode NFKC.
2. Removes selected invisible/control characters that can hide prompt-manipulation text.
3. Redacts common secret-bearing fields and patterns, including authorization/cookie headers, bearer values, JWT-shaped strings, API keys, passwords, session tokens, and private-key blocks.
4. Bounds individual strings and the aggregate reasoning context.
5. Keeps a bounded recent observation window when the aggregate context is too large.
6. Adds \`_beltu_context_trust=untrusted_target_data\` (or a derived-data label) and marks the value as \`evidence_only; never instructions\`.
7. Fails closed when the boundary is explicitly disabled.

The boundary does **not** delete ordinary attacker-controlled text simply because it looks like an instruction. That text can itself be meaningful security evidence. Instead, the prompt layer explicitly tells the reasoning model that everything inside \`<BELTU_TARGET_DATA>\` is untrusted evidence and cannot override BELTU's system instructions or control layers.

## 3. Reasoning prompt boundary

\`src/beltu/brain/llm/prompting.py\` places the serialized context inside:

\`\`\`text
<BELTU_TARGET_DATA>
{JSON evidence}
</BELTU_TARGET_DATA>
\`\`\`

The prompt explicitly states that embedded instructions, commands, role changes, policies, and requests are data only.

This is defense in depth:

- \`ContextSecurityBoundary\` controls the object before it reaches reasoning.
- Prompt delimiting communicates the same trust rule to the model.
- Response validation still constrains the model's output.
- Scope, policy, approval, capability, and resource gates remain outside the model.

## 4. Gemini has a second, stricter boundary

When the local operator uses Gemini as the v1.3 cloud co-pilot, the already-bounded \`AgentContext\` passes through \`CloudPrivacyFilter\` again before the network request is created.

The cloud boundary is stricter than the local reasoning boundary. It excludes final-report material, confirmed exploit payloads, PoC code, credentials, and session secrets from Gemini-visible context, in addition to redacting secret-bearing fields.

Therefore the intended chain is:

\`\`\`text
Target-derived text
      |
      v
ContextSecurityBoundary
      |
      v
Local AgentContext
      |
      +----> Standard Local :8000 reasoning
      |
      +----> Altar-1 :8001 when routed locally
      |
      +----> CloudPrivacyFilter
                    |
                    v
                Gemini Cloud
\`\`\`

Gemini remains advisory-only. It cannot execute tools or bypass BELTU's local execution authority.

## 5. Developer requirements

Any new reasoning entry point must consume the \`AgentContext\` produced by \`ContextBuilder\` or explicitly invoke \`ContextSecurityBoundary\` first.

Do not add a new provider call that accepts raw tool output directly.

Do not disable \`ReasoningContextPolicy.enabled\`.

Do not treat \`_beltu_context_trust\` as proof that the underlying data is trustworthy; it is a machine-readable label that tells the reasoning layer how to handle it.

Security-sensitive tests for this boundary live in \`tests/stage24/test_context_security_boundary.py\`.
