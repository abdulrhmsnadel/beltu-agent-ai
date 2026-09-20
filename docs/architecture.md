# BELTU Architecture

The Agent is a closed-loop system. Interfaces submit intents; the Agent Core manages lifecycle; the Brain reasons over persisted context; Policy gates actions; Execution runs only validated capabilities; results become Evidence/Observations; the Feedback loop replans.

Trust boundaries:

1. CLI / Mobile / WhatsApp interface
2. Remote gateway authentication and audit
3. Agent lifecycle and scheduler
4. Brain / LLM / capability selection
5. Scope, approval, resource, and action policy
6. Capability adapters / process manager
7. SQLite / evidence / workspace storage

The Brain does not receive a direct process-spawning primitive.
