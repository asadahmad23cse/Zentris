"use client";

import { Card, Col, Progress, Row, Space, Table, Tag, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";

const { Title, Text, Paragraph } = Typography;

interface SecurityMilestone {
  key: string;
  capability: string;
  status: string;
  artifact: string;
  coverage: string;
}

const milestones: SecurityMilestone[] = [
  {
    key: "hook",
    capability: "Prompt Injection Detection Hook",
    status: "Implemented",
    artifact: "hooks/prompt_injection_detection.py",
    coverage: "Normalization, base64 decoding, fuzzy templates, semantic signals, CLI JSON output",
  },
  {
    key: "corpus",
    capability: "Red-Team Corpus",
    status: "Implemented",
    artifact: "tests/prompt_injection_corpus.json",
    coverage: "Direct jailbreaks, role override, env/path probes, boundary injection, benign controls",
  },
  {
    key: "ci",
    capability: "Security Gate",
    status: "Implemented",
    artifact: ".github/workflows/security_gate.yml",
    coverage: "Runs Python hook tests with existing TypeScript build and integration checks",
  },
  {
    key: "runtime",
    capability: "Multi-Stage Security Runtime",
    status: "Implemented",
    artifact: "zentris_security/pipeline.py",
    coverage: "Input, retrieval, tool-call, MCP, and output inspection with latency-aware policy decisions",
  },
  {
    key: "rag",
    capability: "Indirect Injection + RAG Poisoning",
    status: "Implemented",
    artifact: "zentris_security/detectors/",
    coverage: "External content instruction detection, source trust scoring, hidden prompt markers, poisoned retrieval signals",
  },
  {
    key: "soc",
    capability: "Audit Replay + Red-Team Simulator",
    status: "Implemented",
    artifact: "zentris_security/audit.py",
    coverage: "JSONL audit events, replay, OWASP/MITRE mapped red-team simulation, CLI verification",
  },
];

const columns: ColumnsType<SecurityMilestone> = [
  {
    title: "Capability",
    dataIndex: "capability",
    key: "capability",
    render: (value: string) => <Text strong>{value}</Text>,
  },
  {
    title: "Status",
    dataIndex: "status",
    key: "status",
    render: (value: string) => <Tag color={value === "Implemented" ? "green" : "blue"}>{value}</Tag>,
  },
  {
    title: "Artifact",
    dataIndex: "artifact",
    key: "artifact",
    render: (value: string) => <Text code>{value}</Text>,
  },
  {
    title: "Coverage",
    dataIndex: "coverage",
    key: "coverage",
  },
];

export default function ZentrisSecurityDashboard() {
  return (
    <main className="min-h-screen bg-slate-50 px-8 py-7">
      <div className="mx-auto max-w-7xl">
        <Space direction="vertical" size={24} className="w-full">
          <div>
            <Title level={2} className="!mb-2">
              Zentris AI Security Runtime
            </Title>
            <Paragraph className="!mb-0 max-w-4xl text-slate-600">
              Project-owned AI runtime security layer for prompt injection, RAG, tool calls, MCP, output risk, audit replay,
              and red-team verification.
            </Paragraph>
          </div>

          <Row gutter={[16, 16]}>
            <Col xs={24} md={8}>
              <Card>
                <Text type="secondary">Runtime detectors</Text>
                <Title level={3} className="!mb-2 !mt-2">
                  6
                </Title>
                <Tag color="green">Zentris owned</Tag>
              </Card>
            </Col>
            <Col xs={24} md={8}>
              <Card>
                <Text type="secondary">Red-team simulator</Text>
                <Title level={3} className="!mb-2 !mt-2">
                  9/9
                </Title>
                <Tag color="blue">Passing</Tag>
              </Card>
            </Col>
            <Col xs={24} md={8}>
              <Card>
                <Text type="secondary">Local model backend</Text>
                <Title level={3} className="!mb-2 !mt-2">
                  Ollama
                </Title>
                <Tag color="green">Free stack</Tag>
              </Card>
            </Col>
          </Row>

          <Card title="Security Platform Coverage">
            <Row gutter={[24, 24]} align="middle">
              <Col xs={24} md={8}>
                <Progress type="dashboard" percent={68} strokeColor="#1677ff" />
              </Col>
              <Col xs={24} md={16}>
                <Space direction="vertical" size={12}>
                  <Text strong>Completed in this slice</Text>
                  <Text>Dependency-free Zentris runtime package with policy decisions and structured findings.</Text>
                  <Text>Direct, indirect, RAG, tool-call, MCP, and output-risk detector families.</Text>
                  <Text>OWASP LLM Top 10 and MITRE ATLAS mapped red-team simulation with audit replay.</Text>
                  <Text type="secondary">
                    Remaining production hardening: inline LiteLLM middleware enforcement, streaming token inspection,
                    persistent SOC telemetry, and multi-model consensus.
                  </Text>
                </Space>
              </Col>
            </Row>
          </Card>

          <Card title="Implementation Artifacts">
            <Table columns={columns} dataSource={milestones} pagination={false} />
          </Card>

          <Card title="Running Local Services">
            <Row gutter={[16, 16]}>
              <Col xs={24} md={8}>
                <Text type="secondary">Zentris Admin UI</Text>
                <Paragraph copyable className="!mt-2">
                  http://localhost:4000/ui/
                </Paragraph>
              </Col>
              <Col xs={24} md={8}>
                <Text type="secondary">Zentris Local Model</Text>
                <Paragraph copyable className="!mt-2">
                  zentris-local-qwen
                </Paragraph>
              </Col>
              <Col xs={24} md={8}>
                <Text type="secondary">Zentris Proxy</Text>
                <Paragraph copyable className="!mt-2">
                  http://localhost:4000
                </Paragraph>
              </Col>
            </Row>
          </Card>
        </Space>
      </div>
    </main>
  );
}



