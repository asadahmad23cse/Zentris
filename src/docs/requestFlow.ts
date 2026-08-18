// Zentris request flow (executable behavior is implemented in middleware/pipeline.ts).
//
// 1. Authenticate through LiteLLM. Only the token's SHA-256 digest is cached;
//    bearer tokens are never logged or persisted.
// 2. Validate roles and shape. Client `system` content cannot become server policy,
//    and the immutable Zentris security instruction is always first.
// 3. Scan raw and normalized/decoded views with the versioned injection catalog.
//    Findings add risk metadata, untrusted wrappers, and a server warning.
//    Injection detection alone never blocks.
// 4. Scan input, history, and RAG content with the DLP catalog. Internal LiteLLM
//    receives typed redaction markers instead of detected values.
// 5. Apply independent authentication, rate-limit, tool authorization, tenant,
//    confirmation, malformed-input, and internal-failure controls. Those controls
//    may reject a request independently of injection detection.
// 6. Forward sanitized messages and supported generation options to LiteLLM.
//    Provider failures return honest 502/503/504 responses.
// 7. Scan completions, including a rolling cross-chunk SSE buffer. Sensitive
//    values are redacted without fabricating or injection-terminating output.
// 8. Return request/security headers and `zentris_security`, then enqueue safe
//    metadata plus protected raw/sanitized history to a Redis Stream.
// 9. The Python worker writes PostgreSQL aggregates/history/events and applies
//    30-day raw-history and 90-day security-event retention.

export {};
