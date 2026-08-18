CREATE TABLE "LiteLLM_ZentrisConversationHistory" (
    "id" TEXT NOT NULL,
    "request_id" TEXT NOT NULL,
    "session_id" TEXT NOT NULL,
    "user_id" TEXT,
    "tenant_id" TEXT,
    "organization_id" TEXT,
    "route" TEXT NOT NULL,
    "model" TEXT,
    "model_parameters" JSONB NOT NULL DEFAULT '{}',
    "raw_messages" JSONB NOT NULL,
    "sanitized_messages" JSONB NOT NULL,
    "raw_result" JSONB,
    "sanitized_result" JSONB,
    "status" TEXT NOT NULL,
    "http_status" INTEGER,
    "failure_code" TEXT,
    "failure_message" TEXT,
    "latency_ms" INTEGER NOT NULL,
    "security_summary" JSONB NOT NULL,
    "metric_recorded" BOOLEAN NOT NULL DEFAULT false,
    "review_status" TEXT NOT NULL DEFAULT 'unreviewed',
    "dataset_targets" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "security_label" TEXT,
    "review_notes" TEXT,
    "reviewed_by" TEXT,
    "reviewed_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "LiteLLM_ZentrisConversationHistory_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "LiteLLM_ZentrisSecurityEvent" (
    "id" TEXT NOT NULL,
    "event_key" TEXT NOT NULL,
    "request_id" TEXT NOT NULL,
    "conversation_id" TEXT,
    "session_id" TEXT NOT NULL,
    "user_id" TEXT,
    "tenant_id" TEXT,
    "event_type" TEXT NOT NULL,
    "stage" TEXT NOT NULL,
    "risk" TEXT NOT NULL,
    "score" INTEGER NOT NULL,
    "action" TEXT NOT NULL,
    "rule_ids" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "details" JSONB NOT NULL,
    "model" TEXT,
    "route" TEXT NOT NULL,
    "latency_ms" INTEGER,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "LiteLLM_ZentrisSecurityEvent_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "LiteLLM_ZentrisDailyMetric" (
    "day" DATE NOT NULL,
    "request_count" INTEGER NOT NULL DEFAULT 0,
    "success_count" INTEGER NOT NULL DEFAULT 0,
    "failure_count" INTEGER NOT NULL DEFAULT 0,
    "injection_count" INTEGER NOT NULL DEFAULT 0,
    "dlp_count" INTEGER NOT NULL DEFAULT 0,
    "latency_sum_ms" BIGINT NOT NULL DEFAULT 0,
    "latency_sample_count" INTEGER NOT NULL DEFAULT 0,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "LiteLLM_ZentrisDailyMetric_pkey" PRIMARY KEY ("day")
);

CREATE UNIQUE INDEX "LiteLLM_ZentrisConversationHistory_request_id_key" ON "LiteLLM_ZentrisConversationHistory"("request_id");
CREATE UNIQUE INDEX "LiteLLM_ZentrisSecurityEvent_event_key_key" ON "LiteLLM_ZentrisSecurityEvent"("event_key");
CREATE INDEX "LiteLLM_ZentrisConversationHistory_created_at_idx" ON "LiteLLM_ZentrisConversationHistory"("created_at");
CREATE INDEX "LiteLLM_ZentrisConversationHistory_expires_at_idx" ON "LiteLLM_ZentrisConversationHistory"("expires_at");
CREATE INDEX "LiteLLM_ZentrisConversationHistory_status_created_at_idx" ON "LiteLLM_ZentrisConversationHistory"("status", "created_at");
CREATE INDEX "LiteLLM_ZentrisConversationHistory_review_status_created_at_idx" ON "LiteLLM_ZentrisConversationHistory"("review_status", "created_at");
CREATE INDEX "LiteLLM_ZentrisConversationHistory_user_id_created_at_idx" ON "LiteLLM_ZentrisConversationHistory"("user_id", "created_at");
CREATE INDEX "LiteLLM_ZentrisSecurityEvent_request_id_idx" ON "LiteLLM_ZentrisSecurityEvent"("request_id");
CREATE INDEX "LiteLLM_ZentrisSecurityEvent_created_at_idx" ON "LiteLLM_ZentrisSecurityEvent"("created_at");
CREATE INDEX "LiteLLM_ZentrisSecurityEvent_expires_at_idx" ON "LiteLLM_ZentrisSecurityEvent"("expires_at");
CREATE INDEX "LiteLLM_ZentrisSecurityEvent_event_type_created_at_idx" ON "LiteLLM_ZentrisSecurityEvent"("event_type", "created_at");
CREATE INDEX "LiteLLM_ZentrisSecurityEvent_risk_created_at_idx" ON "LiteLLM_ZentrisSecurityEvent"("risk", "created_at");
