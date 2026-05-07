import { useDisableShowPrompts } from "@/app/(dashboard)/hooks/useDisableShowPrompts";
import { GithubOutlined, CommentOutlined } from "@ant-design/icons";
import { Button } from "antd";
import React from "react";

export const CommunityEngagementButtons: React.FC = () => {
  const disableShowPrompts = useDisableShowPrompts();

  // Hide buttons if prompts are disabled
  if (disableShowPrompts) {
    return null;
  }

  return (
    <div className="flex items-center gap-3">
      <Button
        href="https://github.com/asadahmad23cse/Zentris/discussions"
        target="_blank"
        rel="noopener noreferrer"
        icon={<CommentOutlined />}
        className="border-none bg-indigo-50 text-indigo-600 hover:bg-indigo-100 hover:text-indigo-700 shadow-sm transition-all duration-200 font-medium"
      >
        Discussions
      </Button>
      <Button
        href="https://github.com/asadahmad23cse/Zentris"
        target="_blank"
        rel="noopener noreferrer"
        icon={<GithubOutlined />}
        className="border-none bg-gray-900 text-white hover:bg-gray-800 shadow-md hover:shadow-lg transition-all duration-200 font-medium"
      >
        Star Zentris
      </Button>
    </div>
  );
};



