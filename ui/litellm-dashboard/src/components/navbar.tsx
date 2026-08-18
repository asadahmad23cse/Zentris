import { useHealthReadiness } from "@/app/(dashboard)/hooks/healthReadiness/useHealthReadiness";
import { useDisableBouncingIcon } from "@/app/(dashboard)/hooks/useDisableBouncingIcon";
import { getProxyBaseUrl } from "@/components/networking";
import { useTheme } from "@/contexts/ThemeContext";
import { clearTokenCookies } from "@/utils/cookieUtils";
import { clearStoredReturnUrl } from "@/utils/returnUrlUtils";
import { fetchProxySettings } from "@/utils/proxyUtils";
import { MenuFoldOutlined, MenuUnfoldOutlined, MoonOutlined, SunOutlined } from "@ant-design/icons";
import { Switch, Tag } from "antd";
import Link from "next/link";
import React, { useEffect, useState } from "react";
import UserDropdown from "./Navbar/UserDropdown/UserDropdown";
import WorkerDropdown from "./Navbar/WorkerDropdown/WorkerDropdown";

interface NavbarProps {
  userID: string | null;
  userEmail: string | null;
  userRole: string | null;
  premiumUser: boolean;
  proxySettings: any;
  setProxySettings: React.Dispatch<React.SetStateAction<any>>;
  accessToken: string | null;
  isPublicPage: boolean;
  sidebarCollapsed?: boolean;
  onToggleSidebar?: () => void;
  isDarkMode: boolean;
  toggleDarkMode: () => void;
}

const Navbar: React.FC<NavbarProps> = ({
  userID,
  userEmail,
  userRole,
  premiumUser,
  proxySettings,
  setProxySettings,
  accessToken,
  isPublicPage = false,
  sidebarCollapsed = false,
  onToggleSidebar,
  isDarkMode,
  toggleDarkMode,
}) => {
  const baseUrl = getProxyBaseUrl();
  const [logoutUrl, setLogoutUrl] = useState("");
  const { logoUrl } = useTheme();
  const { data: healthData } = useHealthReadiness();
  const version = healthData?.Zentris_version;
  const disableBouncingIcon = useDisableBouncingIcon();

  const imageUrl = logoUrl || "/assets/logos/zentris_logo.svg";

  useEffect(() => {
    const initializeProxySettings = async () => {
      if (accessToken) {
        const settings = await fetchProxySettings(accessToken);
        console.log("response from fetchProxySettings", settings);
        if (settings) {
          setProxySettings(settings);
        }
      }
    };

    initializeProxySettings();
  }, [accessToken]);

  useEffect(() => {
    setLogoutUrl(proxySettings?.PROXY_LOGOUT_URL || "");
  }, [proxySettings]);

  const handleLogout = () => {
    clearTokenCookies();
    localStorage.removeItem("Zentris_selected_worker_id");
    localStorage.removeItem("Zentris_worker_url");
    window.location.href = logoutUrl;
  };

  const handleWorkerSwitch = (workerId: string) => {
    clearTokenCookies();
    clearStoredReturnUrl();
    localStorage.removeItem("Zentris_selected_worker_id");
    localStorage.removeItem("Zentris_worker_url");
    window.location.href = `/ui/login?worker=${encodeURIComponent(workerId)}`;
  };

  return (
    <nav className="zentris-navbar sticky top-0 z-20">
      <div className="w-full">
        <div className="flex items-center h-16 px-4">
          <div className="flex items-center flex-shrink-0">
            {onToggleSidebar && (
              <button
                onClick={onToggleSidebar}
                className="flex items-center justify-center w-10 h-10 mr-3 text-slate-600 hover:text-slate-950 hover:bg-slate-100 rounded-lg transition-colors"
                title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
                aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
              >
                <span className="text-lg">{sidebarCollapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}</span>
              </button>
            )}

            <div className="flex items-center gap-3">
              <Link href={baseUrl ? baseUrl : "/"} className="flex items-center">
                <div className="relative flex items-center gap-3">
                  <div className="h-10 max-w-48 flex items-center justify-center overflow-hidden rounded-lg bg-white/70 ring-1 ring-slate-200">
                    <img
                      src={imageUrl}
                      alt="Zentris Brand"
                      className="max-w-full max-h-full w-auto h-auto object-contain"
                    />
                  </div>
                  <div className="hidden sm:block">
                    <div className="text-[11px] font-semibold uppercase text-slate-500">AI Gateway</div>
                    <div className="text-sm font-semibold text-slate-950">Enterprise Control Plane</div>
                  </div>
                </div>
              </Link>
              {version && (
                <div className="relative">
                  {!disableBouncingIcon && (
                    <span
                      className="absolute -top-1 -left-2 text-lg animate-bounce"
                      style={{ animationDuration: "2s" }}
                      title="Thanks for using Zentris!"
                    >
                      🌑
                    </span>
                  )}
                  <Tag className="relative text-xs font-medium cursor-pointer z-10 border-slate-200 bg-slate-50 text-slate-700">
                    <a
                      href="https://github.com/asadahmad23cse/Zentris/releases"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex-shrink-0"
                    >
                      v{version}
                    </a>
                  </Tag>
                </div>
              )}
            </div>
          </div>
          {/* Right side nav items */}
          <div className="flex items-center gap-3 ml-auto">
            <a
              href="https://github.com/asadahmad23cse/Zentris#readme"
              target="_blank"
              rel="noopener noreferrer"
              className="hidden sm:inline-flex text-sm font-medium text-slate-600 hover:text-slate-950"
            >
              Docs
            </a>
            <div
              className="hidden lg:flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-1.5 text-xs font-medium text-emerald-700"
              role="status"
              aria-label="Zentris services are live"
            >
              <span className="h-2 w-2 rounded-full bg-emerald-500 shadow-[0_0_0_4px_rgba(16,185,129,0.14)]" />
              Live
            </div>
            <WorkerDropdown onWorkerSwitch={handleWorkerSwitch} />
            {/* Dark mode is currently a work in progress. To test, you can change 'false' to 'true' below.
            Do not set this to true by default until all components are confirmed to support dark mode styles. */}
            {false && (
              <Switch
                data-testid="dark-mode-toggle"
                checked={isDarkMode}
                onChange={toggleDarkMode}
                checkedChildren={<MoonOutlined />}
                unCheckedChildren={<SunOutlined />}
              />
            )}
            {!isPublicPage && <UserDropdown onLogout={handleLogout} />}
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;



