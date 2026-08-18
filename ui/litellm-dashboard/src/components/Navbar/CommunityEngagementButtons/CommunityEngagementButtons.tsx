import React from "react";
import { useDisableShowPrompts } from "@/app/(dashboard)/hooks/useDisableShowPrompts";

export const CommunityEngagementButtons: React.FC = () => {
  const disableShowPrompts = useDisableShowPrompts();
  if (disableShowPrompts) return null;

  const linkClass = "rounded-md border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50";
  return (
    <div className="flex items-center gap-2">
      <a className={linkClass} href="https://github.com/asadahmad23cse/Zentris/discussions" target="_blank" rel="noopener noreferrer">
        Community
      </a>
      <a className={linkClass} href="https://github.com/asadahmad23cse/Zentris" target="_blank" rel="noopener noreferrer">
        Star Zentris
      </a>
    </div>
  );
};



