"use client";

import useAuthorized from "@/app/(dashboard)/hooks/useAuthorized";
import { getProxyBaseUrl } from "@/components/networking";
import {
  Alert, Button, Card, Col, Descriptions, Drawer, Input, Modal, Row, Select, Space,
  Statistic, Table, Tabs, Tag, Typography, message,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import { useQuery } from "@tanstack/react-query";
import { useCallback, useMemo, useState } from "react";

const { Title, Text, Paragraph } = Typography;

interface Summary {
  requests: number;
  success: number;
  failed: number;
  success_rate: number;
  injection_attempts: number;
  dlp_findings: number;
  latency_ms: { p50: number; p95: number; p99: number };
  telemetry: { available: boolean; queued_entries: number; pending_entries: number; lag_seconds: number | null };
  time_series: Array<{ day: string; requests: number; success: number; failed: number; injection: number; dlp: number; average_latency_ms: number }>;
  breakdowns: Record<"rules" | "categories" | "models", Array<{ name: string; count: number }>>;
  truncated?: boolean;
}

interface SecurityEvent {
  id: string;
  request_id: string;
  event_type: string;
  stage: string;
  risk: string;
  score: number;
  action: string;
  rule_ids: string[];
  details: Record<string, unknown>;
  model?: string;
  latency_ms?: number;
  created_at: string;
  conversation?: Pick<HistoryItem, "id" | "request_id" | "raw_messages" | "sanitized_messages" | "raw_result" | "sanitized_result">;
}

interface HistoryItem {
  id: string;
  request_id: string;
  session_id: string;
  route: string;
  model?: string;
  status: string;
  http_status?: number;
  latency_ms: number;
  failure_code?: string;
  review_status: "unreviewed" | "approved" | "rejected";
  dataset_targets: string[];
  security_summary: Record<string, unknown>;
  sanitized_messages?: Array<{ role: string; content: string }>;
  sanitized_result?: { role: string; content: string };
  raw_messages?: Array<{ role: string; content: string }>;
  raw_result?: { role: string; content: string };
  created_at: string;
}

interface Page<T> {
  data: T[];
  next_cursor?: string | null;
}

const riskColor = (risk: string) => ({ high: "red", medium: "orange", low: "blue" })[risk] ?? "default";
const statusColor = (status: string) => ({ success: "green", failed: "red", rejected: "orange", approved: "green" })[status] ?? "default";
export const isSecurityTrainingExample = (item: HistoryItem) => {
  const findings = item.security_summary?.findings;
  return item.status !== "success"
    || item.security_summary?.injectionDetected === true
    || item.security_summary?.dlpDetected === true
    || (Array.isArray(findings) && findings.length > 0);
};

export default function ZentrisSecurityDashboard() {
  const { accessToken, userRole } = useAuthorized();
  const [selectedHistory, setSelectedHistory] = useState<HistoryItem | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [pendingDelete, setPendingDelete] = useState<HistoryItem | null>(null);
  const [historyDeleting, setHistoryDeleting] = useState(false);
  const [eventType, setEventType] = useState<string>();
  const [risk, setRisk] = useState<string>();
  const [historyStatus, setHistoryStatus] = useState<string>();
  const [reviewStatus, setReviewStatus] = useState<string>();
  const [search, setSearch] = useState("");
  const [eventCursor, setEventCursor] = useState<string>();
  const [historyCursor, setHistoryCursor] = useState<string>();
  const [eventCursorHistory, setEventCursorHistory] = useState<string[]>([]);
  const [historyCursorHistory, setHistoryCursorHistory] = useState<string[]>([]);
  const [selectedHistoryIds, setSelectedHistoryIds] = useState<string[]>([]);

  const api = useCallback(async <T,>(path: string, init?: RequestInit): Promise<T> => {
    if (!accessToken) throw new Error("Administrator access token is unavailable");
    const response = await fetch(`${getProxyBaseUrl()}${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${accessToken}`,
        ...(init?.body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(init?.headers ?? {}),
      },
      cache: "no-store",
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail || body.error?.message || `Request failed (${response.status})`);
    }
    return response.json() as Promise<T>;
  }, [accessToken]);

  const telemetryQuery = useQuery({
    queryKey: ["zentris-security", accessToken, eventType, risk, historyStatus, reviewStatus, eventCursor, historyCursor],
    enabled: Boolean(accessToken) && (userRole === "Admin" || userRole === "proxy_admin"),
    staleTime: 15_000,
    queryFn: async () => {
      const eventParams = new URLSearchParams({ limit: "50" });
      if (eventType) eventParams.set("event_type", eventType);
      if (risk) eventParams.set("risk", risk);
      if (eventCursor) eventParams.set("cursor", eventCursor);
      const historyParams = new URLSearchParams({ limit: "50" });
      if (historyStatus) historyParams.set("status", historyStatus);
      if (reviewStatus) historyParams.set("review_status", reviewStatus);
      if (historyCursor) historyParams.set("cursor", historyCursor);
      const [summary, events, history] = await Promise.all([
        api<Summary>("/v1/zentris/security/summary"),
        api<Page<SecurityEvent>>(`/v1/zentris/security/events?${eventParams}`),
        api<Page<HistoryItem>>(`/v1/zentris/history?${historyParams}`),
      ]);
      return { summary, events, history };
    },
  });
  const summary = telemetryQuery.data?.summary;
  const events = telemetryQuery.data?.events.data ?? [];
  const history = telemetryQuery.data?.history.data ?? [];
  const loading = telemetryQuery.isLoading || telemetryQuery.isFetching;
  const error = telemetryQuery.error instanceof Error ? telemetryQuery.error.message : null;
  const load = telemetryQuery.refetch;

  const filteredEvents = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return events;
    return events.filter((item) => [item.request_id, item.event_type, item.model, ...item.rule_ids].some((value) => value?.toLowerCase().includes(query)));
  }, [events, search]);

  const openHistory = async (item: HistoryItem) => {
    try {
      setSelectedHistory(await api<HistoryItem>(`/v1/zentris/history/${item.id}`));
    } catch (detailError) {
      message.error(detailError instanceof Error ? detailError.message : "Unable to load history");
    }
  };

  const openEvent = async (item: SecurityEvent) => {
    try {
      setSelectedEvent(await api<SecurityEvent>(`/v1/zentris/security/events/${item.id}`));
    } catch (detailError) {
      message.error(detailError instanceof Error ? detailError.message : "Unable to load event");
    }
  };

  const review = async (item: HistoryItem, state: "approved" | "rejected") => {
    try {
      await api(`/v1/zentris/history/${item.id}/review`, {
        method: "PATCH",
        body: JSON.stringify({
          review_status: state,
          dataset_targets: state === "approved" ? [isSecurityTrainingExample(item) ? "security" : "assistant"] : [],
        }),
      });
      message.success(`History ${state}`);
      setSelectedHistory(null);
      await load();
    } catch (reviewError) {
      message.error(reviewError instanceof Error ? reviewError.message : "Review failed");
    }
  };

  const bulkReview = async (state: "approved" | "rejected") => {
    if (!selectedHistoryIds.length) return;
    const selected = history.filter((item) => selectedHistoryIds.includes(item.id));
    const assistantEligible = state === "approved" && selected.every((item) => !isSecurityTrainingExample(item));
    try {
      await api("/v1/zentris/history/bulk-review", {
        method: "POST",
        body: JSON.stringify({
          ids: selectedHistoryIds,
          review_status: state,
          dataset_targets: state === "approved" ? (assistantEligible ? ["assistant"] : ["security"]) : [],
        }),
      });
      message.success(`${selectedHistoryIds.length} histories ${state}`);
      setSelectedHistoryIds([]);
      await load();
    } catch (reviewError) {
      message.error(reviewError instanceof Error ? reviewError.message : "Bulk review failed");
    }
  };

  const remove = (item: HistoryItem) => setPendingDelete(item);

  const confirmRemove = async () => {
    if (!pendingDelete) return;
    setHistoryDeleting(true);
    try {
      await api(`/v1/zentris/history/${pendingDelete.id}`, { method: "DELETE" });
      setPendingDelete(null);
      setSelectedHistory(null);
      await load();
    } catch (deleteError) {
      message.error(deleteError instanceof Error ? deleteError.message : "Delete failed");
    } finally {
      setHistoryDeleting(false);
    }
  };

  const exportDataset = async (dataset: "assistant" | "security") => {
    if (!accessToken) return;
    try {
      const response = await fetch(`${getProxyBaseUrl()}/v1/zentris/training-exports`, {
        method: "POST",
        headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ dataset, content: "sanitized" }),
      });
      if (!response.ok) throw new Error("Export failed");
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `zentris-${dataset}.jsonl`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (exportError) {
      message.error(exportError instanceof Error ? exportError.message : "Export failed");
    }
  };

  const eventColumns: ColumnsType<SecurityEvent> = [
    { title: "Time", dataIndex: "created_at", render: (value: string) => new Date(value).toLocaleString() },
    { title: "Request ID", dataIndex: "request_id", ellipsis: true },
    { title: "Type", dataIndex: "event_type", render: (value: string) => <Tag>{value.replaceAll("_", " ")}</Tag> },
    { title: "Risk", dataIndex: "risk", render: (value: string) => <Tag color={riskColor(value)}>{value}</Tag> },
    { title: "Rule", dataIndex: "rule_ids", render: (value: string[]) => value?.join(", ") || "—" },
    { title: "Model", dataIndex: "model", render: (value?: string) => value || "—" },
    { title: "Latency", dataIndex: "latency_ms", render: (value?: number) => value === undefined ? "—" : `${value} ms` },
    { title: "", render: (_, item) => <Button size="small" onClick={() => void openEvent(item)}>Inspect</Button> },
  ];

  const historyColumns: ColumnsType<HistoryItem> = [
    { title: "Time", dataIndex: "created_at", render: (value: string) => new Date(value).toLocaleString() },
    { title: "Request ID", dataIndex: "request_id", ellipsis: true },
    { title: "Status", dataIndex: "status", render: (value: string) => <Tag color={statusColor(value)}>{value}</Tag> },
    { title: "Model", dataIndex: "model", render: (value?: string) => value || "—" },
    { title: "Review", dataIndex: "review_status", render: (value: string) => <Tag color={statusColor(value)}>{value}</Tag> },
    { title: "Latency", dataIndex: "latency_ms", render: (value: number) => `${value} ms` },
    { title: "Failure", dataIndex: "failure_code", render: (value?: string) => value || "—" },
    { title: "", render: (_, item) => <Button size="small" onClick={() => void openHistory(item)}>View</Button> },
  ];

  const dailyColumns: ColumnsType<Summary["time_series"][number]> = [
    { title: "Day", dataIndex: "day", render: (value: string) => new Date(value).toLocaleDateString() },
    { title: "Requests", dataIndex: "requests" },
    { title: "Success", dataIndex: "success" },
    { title: "Failed", dataIndex: "failed" },
    { title: "Injection", dataIndex: "injection" },
    { title: "DLP", dataIndex: "dlp" },
    { title: "Avg latency", dataIndex: "average_latency_ms", render: (value: number) => `${value} ms` },
  ];
  const breakdownColumns: ColumnsType<{ name: string; count: number }> = [
    { title: "Name", dataIndex: "name" },
    { title: "Count", dataIndex: "count", width: 100 },
  ];

  const nextEvents = () => {
    const next = telemetryQuery.data?.events.next_cursor;
    if (!next) return;
    setEventCursorHistory((current) => [...current, eventCursor ?? ""]);
    setEventCursor(next);
  };
  const previousEvents = () => {
    const previous = eventCursorHistory.at(-1);
    setEventCursorHistory((current) => current.slice(0, -1));
    setEventCursor(previous || undefined);
  };
  const nextHistory = () => {
    const next = telemetryQuery.data?.history.next_cursor;
    if (!next) return;
    setHistoryCursorHistory((current) => [...current, historyCursor ?? ""]);
    setHistoryCursor(next);
  };
  const previousHistory = () => {
    const previous = historyCursorHistory.at(-1);
    setHistoryCursorHistory((current) => current.slice(0, -1));
    setHistoryCursor(previous || undefined);
  };

  if (userRole !== "Admin" && userRole !== "proxy_admin") {
    return <Alert type="error" showIcon message="Proxy administrator access is required" />;
  }

  return (
    <main className="min-h-screen bg-slate-50 px-6 py-6">
      <Space direction="vertical" size={20} className="mx-auto w-full max-w-[1600px]">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <Title level={2} className="!mb-1">Zentris Security Operations</Title>
            <Paragraph className="!mb-0 text-slate-600">Prompt-injection warnings, DLP findings, failed calls, retained conversations, and curated training exports.</Paragraph>
          </div>
          <Space><Button onClick={() => void exportDataset("assistant")}>Export assistant JSONL</Button><Button onClick={() => void exportDataset("security")}>Export security JSONL</Button><Button type="primary" loading={loading} onClick={() => void load()}>Refresh</Button></Space>
        </div>
        {error && <Alert type="error" showIcon message="Telemetry unavailable" description={error} />}
        {summary?.truncated && <Alert type="warning" showIcon message="Summary is based on the newest 10,000 records" />}
        {summary && !summary.telemetry.available && <Alert type="warning" showIcon message="Telemetry queue status is unavailable" description="Database history remains visible, but Redis queue lag cannot currently be measured." />}
        <Row gutter={[12, 12]}>
          <Col xs={12} lg={3}><Card><Statistic title="Requests" value={summary?.requests ?? 0} /></Card></Col>
          <Col xs={12} lg={3}><Card><Statistic title="Success rate" value={(summary?.success_rate ?? 0) * 100} precision={1} suffix="%" /></Card></Col>
          <Col xs={12} lg={3}><Card><Statistic title="Injection warnings" value={summary?.injection_attempts ?? 0} valueStyle={{ color: "#d97706" }} /></Card></Col>
          <Col xs={12} lg={3}><Card><Statistic title="DLP findings" value={summary?.dlp_findings ?? 0} valueStyle={{ color: "#2563eb" }} /></Card></Col>
          <Col xs={12} lg={3}><Card><Statistic title="Failed calls" value={summary?.failed ?? 0} valueStyle={{ color: "#dc2626" }} /></Card></Col>
          <Col xs={12} lg={3}><Card><Statistic title="p95 latency" value={summary?.latency_ms.p95 ?? 0} suffix="ms" /></Card></Col>
          <Col xs={12} lg={3}><Card><Statistic title="Queue entries" value={summary?.telemetry.queued_entries ?? 0} /></Card></Col>
          <Col xs={12} lg={3}><Card><Statistic title="Telemetry lag" value={summary?.telemetry.lag_seconds ?? 0} precision={1} suffix="s" /></Card></Col>
        </Row>
        <Card>
          <Tabs items={[
            {
              key: "events", label: `Security events (${events.length})`, children: <Space direction="vertical" className="w-full" size={12}>
                <Space wrap>
                  <Input.Search allowClear placeholder="Request, model, rule…" onSearch={setSearch} onChange={(event) => setSearch(event.target.value)} style={{ width: 280 }} />
                  <Select allowClear placeholder="Event type" value={eventType} onChange={(value) => { setEventType(value); setEventCursor(undefined); setEventCursorHistory([]); }} options={["prompt_injection", "secret", "pii", "failed_call"].map((value) => ({ value, label: value.replaceAll("_", " ") }))} style={{ width: 180 }} />
                  <Select allowClear placeholder="Risk" value={risk} onChange={(value) => { setRisk(value); setEventCursor(undefined); setEventCursorHistory([]); }} options={["high", "medium", "low"].map((value) => ({ value, label: value }))} style={{ width: 130 }} />
                </Space>
                <Table rowKey="id" columns={eventColumns} dataSource={filteredEvents} loading={loading} scroll={{ x: 900 }} pagination={false} />
                <Space><Button disabled={!eventCursorHistory.length} onClick={previousEvents}>Previous</Button><Button disabled={!telemetryQuery.data?.events.next_cursor} onClick={nextEvents}>Next</Button></Space>
              </Space>,
            },
            {
              key: "history", label: `Prompt history (${history.length})`, children: <Space direction="vertical" className="w-full" size={12}>
                <Space wrap>
                  <Select allowClear placeholder="Call status" value={historyStatus} onChange={(value) => { setHistoryStatus(value); setHistoryCursor(undefined); setHistoryCursorHistory([]); }} options={["success", "failed", "rejected"].map((value) => ({ value, label: value }))} style={{ width: 160 }} />
                  <Select allowClear placeholder="Review status" value={reviewStatus} onChange={(value) => { setReviewStatus(value); setHistoryCursor(undefined); setHistoryCursorHistory([]); }} options={["unreviewed", "approved", "rejected"].map((value) => ({ value, label: value }))} style={{ width: 170 }} />
                  <Button disabled={!selectedHistoryIds.length} onClick={() => void bulkReview("approved")}>Approve selected</Button>
                  <Button disabled={!selectedHistoryIds.length} onClick={() => void bulkReview("rejected")}>Reject selected</Button>
                </Space>
                <Table rowKey="id" rowSelection={{ selectedRowKeys: selectedHistoryIds, onChange: (keys) => setSelectedHistoryIds(keys.map(String)) }} columns={historyColumns} dataSource={history} loading={loading} scroll={{ x: 900 }} pagination={false} />
                <Space><Button disabled={!historyCursorHistory.length} onClick={previousHistory}>Previous</Button><Button disabled={!telemetryQuery.data?.history.next_cursor} onClick={nextHistory}>Next</Button></Space>
              </Space>,
            },
            { key: "latency", label: "Latency", children: <Row gutter={[16, 16]}><Col span={8}><Card><Statistic title="p50" value={summary?.latency_ms.p50 ?? 0} suffix="ms" /></Card></Col><Col span={8}><Card><Statistic title="p95" value={summary?.latency_ms.p95 ?? 0} suffix="ms" /></Card></Col><Col span={8}><Card><Statistic title="p99" value={summary?.latency_ms.p99 ?? 0} suffix="ms" /></Card></Col></Row> },
            { key: "trends", label: "Trends & breakdowns", children: <Space direction="vertical" className="w-full" size={16}>
              <Table rowKey="day" size="small" columns={dailyColumns} dataSource={summary?.time_series ?? []} pagination={false} scroll={{ x: 760 }} />
              <Row gutter={[12, 12]}>
                <Col xs={24} lg={8}><Card size="small" title="Top rules"><Table rowKey="name" size="small" columns={breakdownColumns} dataSource={summary?.breakdowns.rules ?? []} pagination={false} /></Card></Col>
                <Col xs={24} lg={8}><Card size="small" title="Categories"><Table rowKey="name" size="small" columns={breakdownColumns} dataSource={summary?.breakdowns.categories ?? []} pagination={false} /></Card></Col>
                <Col xs={24} lg={8}><Card size="small" title="Models"><Table rowKey="name" size="small" columns={breakdownColumns} dataSource={summary?.breakdowns.models ?? []} pagination={false} /></Card></Col>
              </Row>
            </Space> },
          ]} />
        </Card>
      </Space>

      <Drawer width={720} title="Security event" open={Boolean(selectedEvent)} onClose={() => setSelectedEvent(null)}>
        {selectedEvent && <Space direction="vertical" size={16} className="w-full">
          <Descriptions column={1} bordered size="small" items={[
            { key: "request", label: "Request ID", children: selectedEvent.request_id },
            { key: "type", label: "Type", children: selectedEvent.event_type },
            { key: "risk", label: "Risk", children: <Tag color={riskColor(selectedEvent.risk)}>{selectedEvent.risk}</Tag> },
            { key: "action", label: "Action", children: selectedEvent.action },
            { key: "rules", label: "Rules", children: selectedEvent.rule_ids.join(", ") || "—" },
            { key: "details", label: "Safe details", children: <pre className="whitespace-pre-wrap">{JSON.stringify(selectedEvent.details, null, 2)}</pre> },
          ]} />
          {selectedEvent.conversation && <>
            <Alert type="warning" showIcon message="Raw content is sensitive" description="Viewing this comparison is audit logged." />
            <Card size="small" title="Raw messages"><pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(selectedEvent.conversation.raw_messages, null, 2)}</pre></Card>
            <Card size="small" title="Sanitized model messages"><pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(selectedEvent.conversation.sanitized_messages, null, 2)}</pre></Card>
            <Card size="small" title="Raw result"><pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(selectedEvent.conversation.raw_result, null, 2)}</pre></Card>
            <Card size="small" title="Sanitized client result"><pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(selectedEvent.conversation.sanitized_result, null, 2)}</pre></Card>
          </>}
        </Space>}
      </Drawer>

      <Drawer width={900} title="Retained prompt and result" open={Boolean(selectedHistory)} onClose={() => setSelectedHistory(null)} extra={selectedHistory && <Space><Button onClick={() => void review(selectedHistory, "approved")}>Approve</Button><Button onClick={() => void review(selectedHistory, "rejected")}>Reject</Button><Button danger onClick={() => remove(selectedHistory)}>Delete</Button></Space>}>
        {selectedHistory && <Space direction="vertical" size={16} className="w-full">
          <Alert type="warning" showIcon message="Raw content is sensitive" description="Viewing this record is audit logged. Do not copy credentials or personal data into external systems." />
          <Descriptions bordered size="small" column={2} items={[
            { key: "request", label: "Request ID", children: selectedHistory.request_id },
            { key: "status", label: "Status", children: <Tag color={statusColor(selectedHistory.status)}>{selectedHistory.status}</Tag> },
            { key: "model", label: "Model", children: selectedHistory.model || "—" },
            { key: "latency", label: "Latency", children: `${selectedHistory.latency_ms} ms` },
          ]} />
          <Card size="small" title="Raw messages"><pre className="max-h-72 overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(selectedHistory.raw_messages, null, 2)}</pre></Card>
          <Card size="small" title="Sanitized model messages"><pre className="max-h-72 overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(selectedHistory.sanitized_messages, null, 2)}</pre></Card>
          <Card size="small" title="Raw result"><pre className="max-h-72 overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(selectedHistory.raw_result, null, 2)}</pre></Card>
          <Card size="small" title="Sanitized result"><pre className="max-h-72 overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(selectedHistory.sanitized_result, null, 2)}</pre></Card>
        </Space>}
      </Drawer>
      <Modal
        title="Delete retained prompt and result?"
        open={Boolean(pendingDelete)}
        okText="Delete"
        okButtonProps={{ danger: true }}
        confirmLoading={historyDeleting}
        onOk={() => void confirmRemove()}
        onCancel={() => setPendingDelete(null)}
      >
        <Paragraph>This permanently removes the history record and its linked security events.</Paragraph>
      </Modal>
    </main>
  );
}
