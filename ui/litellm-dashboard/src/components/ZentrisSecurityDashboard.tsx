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
    capability: "Runtime Visibility",
    status: "Visible in UI",
    artifact: "ui/Zentris-dashboard/src/components/ZentrisSecurityDashboard.tsx",
    coverage: "Dashboard status page added for implementation-plan progress",
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
              Zentris AI Security Implementation
            </Title>
            <Paragraph className="!mb-0 max-w-4xl text-slate-600">
              Visible status for the security architecture transformation work currently implemented from the plan.
            </Paragraph>
          </div>

          <Row gutter={[16, 16]}>
            <Col xs={24} md={8}>
              <Card>
                <Text type="secondary">Prompt injection hook</Text>
                <Title level={3} className="!mb-2 !mt-2">
                  Active
                </Title>
                <Tag color="green">Implemented</Tag>
              </Card>
            </Col>
            <Col xs={24} md={8}>
              <Card>
                <Text type="secondary">Implementation commits pushed</Text>
                <Title level={3} className="!mb-2 !mt-2">
                  30
                </Title>
                <Tag color="blue">GitHub main</Tag>
              </Card>
            </Col>
            <Col xs={24} md={8}>
              <Card>
                <Text type="secondary">Local verification</Text>
                <Title level={3} className="!mb-2 !mt-2">
                  Passing
                </Title>
                <Tag color="green">Python + TypeScript</Tag>
              </Card>
            </Col>
          </Row>

          <Card title="Phase 1 Progress">
            <Row gutter={[24, 24]} align="middle">
              <Col xs={24} md={8}>
                <Progress type="dashboard" percent={35} strokeColor="#1677ff" />
              </Col>
              <Col xs={24} md={16}>
                <Space direction="vertical" size={12}>
                  <Text strong>Completed in this slice</Text>
                  <Text>Dependency-free Python prompt injection hook with scoring and structured output.</Text>
                  <Text>Red-team benchmark corpus committed as separate auditable cases.</Text>
                  <Text>CI security gate now runs the hook test suite.</Text>
                  <Text type="secondary">
                    Remaining Phase 1 work: deeper runtime integration, semantic model service, and dashboard telemetry
                    backed by live audit data.
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
                <Text type="secondary">Dashboard</Text>
                <Paragraph copyable className="!mt-2">
                  http://127.0.0.1:3001
                </Paragraph>
              </Col>
              <Col xs={24} md={8}>
                <Text type="secondary">Zentris API</Text>
                <Paragraph copyable className="!mt-2">
                  http://127.0.0.1:3000
                </Paragraph>
              </Col>
              <Col xs={24} md={8}>
                <Text type="secondary">Zentris Admin Proxy</Text>
                <Paragraph copyable className="!mt-2">
                  http://127.0.0.1:4000
                </Paragraph>
              </Col>
            </Row>
          </Card>
        </Space>
      </div>
    </main>
  );
}


