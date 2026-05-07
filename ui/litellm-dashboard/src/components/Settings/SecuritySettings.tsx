"use client";

import React, { useEffect, useMemo, useState } from "react";
import { Button, Card, Input, List, Switch, Typography } from "antd";
import {
  DeleteOutlined,
  PlusOutlined,
  SaveOutlined,
} from "@ant-design/icons";
import {
  getSecurityGuardrailSettings,
  SecurityGuardrailSettings,
  updateSecurityGuardrailSettings,
} from "@/components/networking";
import NotificationsManager from "@/components/molecules/notifications_manager";
import { useAllProxyModels } from "@/app/(dashboard)/hooks/models/useModels";

const { Title, Text } = Typography;

interface SecuritySettingsProps {
  accessToken: string | null;
}

const SecuritySettings: React.FC<SecuritySettingsProps> = ({ accessToken }) => {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [regexInput, setRegexInput] = useState("");
  const [regexPatterns, setRegexPatterns] = useState<string[]>([]);
  const [modelToggleMap, setModelToggleMap] = useState<Record<string, boolean>>({});
  const { data: modelsData } = useAllProxyModels();

  const modelNames = useMemo(() => {
    const raw = modelsData?.data || [];
    return raw.map((m) => m.id).filter(Boolean);
  }, [modelsData]);

  useEffect(() => {
    if (!accessToken) return;
    const load = async () => {
      setLoading(true);
      try {
        const settings = await getSecurityGuardrailSettings(accessToken);
        setRegexPatterns(settings.dlp_regex_patterns || []);
        setModelToggleMap(settings.ml_injection_detection_by_model || {});
      } catch (error) {
        NotificationsManager.fromBackend("Failed to load Security Settings");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [accessToken]);

  const addRegexPattern = () => {
    const trimmed = regexInput.trim();
    if (!trimmed) return;
    if (regexPatterns.includes(trimmed)) {
      NotificationsManager.fromBackend("Regex pattern already exists");
      return;
    }
    setRegexPatterns((prev) => [...prev, trimmed]);
    setRegexInput("");
  };

  const removeRegexPattern = (pattern: string) => {
    setRegexPatterns((prev) => prev.filter((p) => p !== pattern));
  };

  const setModelToggle = (model: string, enabled: boolean) => {
    setModelToggleMap((prev) => ({ ...prev, [model]: enabled }));
  };

  const saveSettings = async () => {
    if (!accessToken) return;
    setSaving(true);
    try {
      const payload: Partial<SecurityGuardrailSettings> = {
        dlp_regex_patterns: regexPatterns,
        ml_injection_detection_by_model: modelToggleMap,
      };
      await updateSecurityGuardrailSettings(accessToken, payload);
      NotificationsManager.success("Security settings updated successfully");
    } catch (error) {
      NotificationsManager.fromBackend("Failed to update Security Settings");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="w-full mx-auto p-6">
      <div className="flex items-center justify-between mb-6">
        <Title level={3} className="m-0">
          Security Settings
        </Title>
        <Button
          type="primary"
          icon={<SaveOutlined />}
          onClick={saveSettings}
          loading={saving}
          disabled={!accessToken}
        >
          Save Changes
        </Button>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <Card title="DLP Regex Patterns" loading={loading}>
          <div className="flex gap-2 mb-4">
            <Input
              placeholder="Add regex pattern (e.g. \\b\\d{3}-\\d{2}-\\d{4}\\b)"
              value={regexInput}
              onChange={(e) => setRegexInput(e.target.value)}
              onPressEnter={addRegexPattern}
            />
            <Button type="default" icon={<PlusOutlined />} onClick={addRegexPattern}>
              Add
            </Button>
          </div>
          <List
            bordered
            dataSource={regexPatterns}
            locale={{ emptyText: "No DLP regex patterns configured" }}
            renderItem={(pattern) => (
              <List.Item
                actions={[
                  <Button
                    key={`delete-${pattern}`}
                    type="text"
                    danger
                    icon={<DeleteOutlined />}
                    onClick={() => removeRegexPattern(pattern)}
                  />,
                ]}
              >
                <Text code>{pattern}</Text>
              </List.Item>
            )}
          />
        </Card>

        <Card title="ML-based Injection Detection by Model" loading={loading}>
          <List
            bordered
            dataSource={modelNames}
            locale={{ emptyText: "No models available" }}
            renderItem={(modelName) => (
              <List.Item
                actions={[
                  <Switch
                    key={`switch-${modelName}`}
                    checked={Boolean(modelToggleMap[modelName])}
                    onChange={(checked) => setModelToggle(modelName, checked)}
                  />,
                ]}
              >
                <Text>{modelName}</Text>
              </List.Item>
            )}
          />
        </Card>
      </div>
    </div>
  );
};

export default SecuritySettings;



