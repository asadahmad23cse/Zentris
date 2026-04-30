"use client";

import useAuthorized from "@/app/(dashboard)/hooks/useAuthorized";
import SecuritySettings from "@/components/Settings/SecuritySettings";

const SecuritySettingsPage = () => {
  const { accessToken } = useAuthorized();
  return <SecuritySettings accessToken={accessToken} />;
};

export default SecuritySettingsPage;
