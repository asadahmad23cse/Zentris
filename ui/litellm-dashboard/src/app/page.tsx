"use client";

import SidebarProvider from "@/app/(dashboard)/components/SidebarProvider";
import OldModelDashboard from "@/app/(dashboard)/models-and-endpoints/ModelsAndEndpointsView";
import PlaygroundPage from "@/app/(dashboard)/playground/page";
import LoginPage from "@/app/login/LoginPage";
import AdminPanel from "@/components/AdminPanel";
import AgentsPanel from "@/components/agents";
import BudgetPanel from "@/components/budgets/budget_panel";
import CacheDashboard from "@/components/cache_dashboard";
import ClaudeCodePluginsPanel from "@/components/claude_code_plugins";
import { teamListCall as v2TeamListCall } from "@/app/(dashboard)/hooks/teams/useTeams";
import LoadingScreen from "@/components/common_components/LoadingScreen";
import { CostTrackingSettings } from "@/components/CostTrackingSettings";
import GeneralSettings from "@/components/general_settings";
import GuardrailsMonitorView from "@/components/GuardrailsMonitor/GuardrailsMonitorView";
import GuardrailsPanel from "@/components/guardrails";
import PoliciesPanel from "@/components/policies";
import ZentrisSecurityDashboard from "@/components/ZentrisSecurityDashboard";
import ZentrisBrandingEnforcer from "@/components/ZentrisBrandingEnforcer";
import { Team } from "@/components/key_team_helpers/key_list";
import { MCPServers } from "@/components/mcp_tools";
import ModelHubTable from "@/components/AIHub/ModelHubTable";
import Navbar from "@/components/navbar";
import { getUiConfig, Organization, proxyBaseUrl, setGlobalZentrisHeaderName, getInProductNudgesCall, getProxyBaseUrl } from "@/components/networking";
import NewUsagePage from "@/components/UsagePage/components/UsagePageView";
import OldTeams from "@/components/OldTeams";
import { fetchUserModels, CreateKeyPrefillData } from "@/components/organisms/create_key_button";
import Organizations, { fetchOrganizations } from "@/components/organizations";
import PassThroughSettings from "@/components/pass_through_settings";
import PromptsPanel from "@/components/prompts";
import PublicModelHub from "@/components/public_model_hub";
import { SearchTools } from "@/components/SearchTools";
import Settings from "@/components/settings";
import { SurveyPrompt, SurveyModal, ClaudeCodePrompt, ClaudeCodeModal } from "@/components/survey";
import TagManagement from "@/components/tag_management";
import TransformRequestPanel from "@/components/transform_request";
import UIThemeSettings from "@/components/ui_theme_settings";
import Usage from "@/components/usage";
import UserDashboard from "@/components/user_dashboard";
import { AccessGroupsPage } from "@/components/AccessGroups/AccessGroupsPage";
import { ProjectsPage } from "@/components/Projects/ProjectsPage";
import VectorStoreManagement from "@/components/vector_store_management";
import ToolPoliciesView from "@/components/ToolPoliciesView";
import SpendLogsTable from "@/components/view_logs";
import ViewUserDashboard from "@/components/view_users";
import { ThemeProvider } from "@/contexts/ThemeContext";
import { isJwtExpired } from "@/utils/jwtUtils";
import { consumeReturnUrl, isValidReturnUrl, normalizeUrlForCompare } from "@/utils/returnUrlUtils";
import { formatUserRole, isAdminRole } from "@/utils/roles";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { jwtDecode } from "jwt-decode";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useRef, useState } from "react";
import { ConfigProvider, theme } from "antd";

const isLegacyInvalidAccessToken = (token: string): boolean => {
  const [headerSegment, _payloadSegment, signatureSegment] = token.split(".");
  if (!headerSegment || !signatureSegment) {
    return true;
  }

  try {
    const padded = headerSegment.padEnd(headerSegment.length + ((4 - (headerSegment.length % 4)) % 4), "=");
    const header = JSON.parse(atob(padded.replace(/-/g, "+").replace(/_/g, "/")));
    return header?.alg !== "HS256" || signatureSegment === "public";
  } catch {
    return true;
  }
};

function PublicHome() {
  const chatHref = "/ui/chat";
  const modelHubHref = "/ui/model_hub";
  const dashboardHref = "/ui/login?redirect_to=%2Fui%2F%3Fpage%3Dllm-playground";

  return (
    <main
      style={{
        minHeight: "100vh",
        background: "#f8fafc",
        color: "#111827",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <header
        style={{
          height: 68,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0 clamp(20px, 6vw, 72px)",
          borderBottom: "1px solid #e5e7eb",
          background: "#ffffff",
        }}
      >
        <a
          href="/ui/"
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            color: "#111827",
            textDecoration: "none",
            fontWeight: 800,
            fontSize: 18,
          }}
        >
          <img
            src="/assets/logos/zentris_logo.svg"
            alt="Zentris"
            style={{ height: 34, width: 34, objectFit: "contain" }}
          />
          <span>Zentris</span>
        </a>
        <nav style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <a
            href={dashboardHref}
            style={{
              color: "#475569",
              textDecoration: "none",
              fontSize: 14,
              fontWeight: 600,
              padding: "9px 12px",
            }}
          >
            Main dashboard
          </a>
          <a
            href={modelHubHref}
            style={{
              color: "#475569",
              textDecoration: "none",
              fontSize: 14,
              fontWeight: 600,
              padding: "9px 12px",
            }}
          >
            Models
          </a>
          <a
            href={chatHref}
            style={{
              color: "#ffffff",
              background: "#111827",
              textDecoration: "none",
              fontSize: 14,
              fontWeight: 700,
              padding: "10px 14px",
              borderRadius: 8,
            }}
          >
            Try chat
          </a>
        </nav>
      </header>

      <section
        style={{
          flex: 1,
          display: "grid",
          gridTemplateColumns: "minmax(0, 1.05fr) minmax(300px, 0.95fr)",
          alignItems: "center",
          gap: "clamp(28px, 5vw, 64px)",
          padding: "clamp(42px, 7vw, 88px) clamp(20px, 6vw, 72px)",
        }}
      >
        <div style={{ maxWidth: 720 }}>
          <p
            style={{
              margin: "0 0 14px",
              color: "#0f766e",
              fontSize: 14,
              fontWeight: 800,
              textTransform: "uppercase",
              letterSpacing: 0,
            }}
          >
            AI gateway and security runtime
          </p>
          <h1
            style={{
              margin: 0,
              fontSize: 56,
              lineHeight: 1.02,
              letterSpacing: 0,
              fontWeight: 850,
              maxWidth: 680,
            }}
          >
            Zentris
          </h1>
          <p
            style={{
              margin: "22px 0 0",
              color: "#475569",
              fontSize: 19,
              lineHeight: 1.65,
              maxWidth: 680,
            }}
          >
            One secure console for OpenAI, Claude, Gemini, model routing, usage, guardrails, and
            production monitoring.
          </p>

          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: 12,
              marginTop: 32,
            }}
          >
            <a
              href={dashboardHref}
              style={{
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                minHeight: 48,
                padding: "0 20px",
                borderRadius: 8,
                background: "#111827",
                color: "#ffffff",
                textDecoration: "none",
                fontSize: 15,
                fontWeight: 800,
              }}
            >
              Main dashboard
            </a>
            <a
              href={chatHref}
              style={{
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                minHeight: 48,
                padding: "0 20px",
                borderRadius: 8,
                background: "#ffffff",
                color: "#111827",
                border: "1px solid #cbd5e1",
                textDecoration: "none",
                fontSize: 15,
                fontWeight: 800,
              }}
            >
              Try chat
            </a>
            <a
              href={modelHubHref}
              style={{
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                minHeight: 48,
                padding: "0 20px",
                borderRadius: 8,
                background: "#ffffff",
                color: "#111827",
                border: "1px solid #cbd5e1",
                textDecoration: "none",
                fontSize: 15,
                fontWeight: 800,
              }}
            >
              Browse models
            </a>
          </div>
        </div>

        <div
          style={{
            background: "#ffffff",
            border: "1px solid #e5e7eb",
            borderRadius: 8,
            boxShadow: "0 24px 80px rgba(15, 23, 42, 0.10)",
            overflow: "hidden",
          }}
        >
          <div
            style={{
              padding: "14px 16px",
              borderBottom: "1px solid #e5e7eb",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              background: "#f8fafc",
            }}
          >
            <span style={{ fontSize: 13, fontWeight: 800, color: "#111827" }}>Production status</span>
            <span
              style={{
                fontSize: 12,
                color: "#047857",
                background: "#d1fae5",
                padding: "4px 8px",
                borderRadius: 999,
                fontWeight: 800,
              }}
            >
              Ready
            </span>
          </div>
          <div style={{ padding: 20, display: "grid", gap: 14 }}>
            {[
              ["Providers", "OpenAI, Claude, Gemini"],
              ["Security", "Prompt injection, DLP, tool confirmation"],
              ["Reliability", "Health checks, CI gate, smoke tests"],
              ["Operations", "Postgres, Redis, Prometheus, Grafana"],
            ].map(([label, value]) => (
              <div
                key={label}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 16,
                  padding: "13px 0",
                  borderBottom: "1px solid #f1f5f9",
                }}
              >
                <span style={{ color: "#64748b", fontSize: 14, fontWeight: 700 }}>{label}</span>
                <span style={{ color: "#111827", fontSize: 14, fontWeight: 800, textAlign: "right" }}>
                  {value}
                </span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <style jsx>{`
        @media (max-width: 860px) {
          section {
            grid-template-columns: 1fr !important;
          }
          nav a:first-child {
            display: none !important;
          }
        }
      `}</style>
    </main>
  );
}

function getCookie(name: string) {
  // Safer cookie read + decoding; handles '=' inside values
  const match = document.cookie.split("; ").find((row) => row.startsWith(name + "="));
  if (!match) return null;
  const value = match.slice(name.length + 1);
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function deleteCookie(name: string, path = "/") {
  // Best-effort client-side clear (works for non-HttpOnly cookies without Domain)
  document.cookie = `${name}=; Max-Age=0; Path=${path}`;
}

interface ProxySettings {
  PROXY_BASE_URL: string;
  PROXY_LOGOUT_URL: string;
  Zentris_UI_API_DOC_BASE_URL?: string | null;
}

/**
 * Map of legacy query-param page keys → new path-based route segments.
 * When a user visits ?page=<key>, they are redirected to /ui/<value>.
 * Add entries here as pages are migrated from the if/else chain to path-based routes.
 */
const LEGACY_REDIRECTS: Record<string, string> = {
  api_ref: "api-reference",
  "api-reference": "api-reference",
};

function CreateKeyPageContent() {
  const [userRole, setUserRole] = useState("");
  const [premiumUser, setPremiumUser] = useState(false);
  const [disabledPersonalKeyCreation, setDisabledPersonalKeyCreation] = useState(false);
  const [userEmail, setUserEmail] = useState<null | string>(null);
  const [teams, setTeams] = useState<Team[] | null>(null);
  const [keys, setKeys] = useState<null | any[]>([]);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [userModels, setUserModels] = useState<string[]>([]);
  const [proxySettings, setProxySettings] = useState<ProxySettings>({
    PROXY_BASE_URL: "",
    PROXY_LOGOUT_URL: "",
  });

  const [showSSOBanner, setShowSSOBanner] = useState<boolean>(true);
  const router = useRouter();
  const searchParams = useSearchParams()!;
  const [modelData, setModelData] = useState<any>({ data: [] });
  const [token, setToken] = useState<string | null>(null);
  const [createClicked, setCreateClicked] = useState<boolean>(false);
  const [authLoading, setAuthLoading] = useState(true);
  const [userID, setUserID] = useState<string | null>(null);

  // Zentris removes upstream feedback nudges from the branded dashboard.
  const [showSurveyPrompt, setShowSurveyPrompt] = useState(false);
  const [showSurveyModal, setShowSurveyModal] = useState(false);

  // Claude Code feedback state
  const [isClaudeCode, setIsClaudeCode] = useState(false);
  const [showClaudeCodePrompt, setShowClaudeCodePrompt] = useState(false);
  const [showClaudeCodeModal, setShowClaudeCodeModal] = useState(false);

  // Dark mode state
  const [isDarkMode, setIsDarkMode] = useState(false);
  const toggleDarkMode = () => {
    setIsDarkMode(!isDarkMode);
  };

  const invitation_id = searchParams.get("invitation_id");

  // Parse URL query parameters for pre-filling the create key form
  // Includes validation to prevent injection and DoS attacks
  const autoOpenCreate = searchParams.get("create") === "true";
  const prefillData: CreateKeyPrefillData | undefined = useMemo(() => {
    if (!autoOpenCreate) return undefined;

    const ownedBy = searchParams.get("owned_by");
    const teamId = searchParams.get("team_id");
    const keyAlias = searchParams.get("key_alias");
    const modelsParam = searchParams.get("models");
    const keyType = searchParams.get("key_type");

    // Only return prefill data if at least one field is provided
    if (!ownedBy && !teamId && !keyAlias && !modelsParam && !keyType) {
      return undefined;
    }

    // Validate owned_by against allowed values
    const validOwnedByValues = ["you", "service_account", "another_user"];
    const validatedOwnedBy = ownedBy && validOwnedByValues.includes(ownedBy)
      ? (ownedBy as CreateKeyPrefillData["owned_by"])
      : undefined;

    // Validate key_type against allowed values
    const validKeyTypes = ["default", "llm_api", "management"];
    const validatedKeyType = keyType && validKeyTypes.includes(keyType)
      ? (keyType as CreateKeyPrefillData["key_type"])
      : undefined;

    // Sanitize key_alias (limit length, trim whitespace)
    const sanitizedKeyAlias = keyAlias
      ? keyAlias.trim().slice(0, 256) // Reasonable max length
      : undefined;

    // Sanitize models (limit array size and individual model name length)
    const sanitizedModels = modelsParam
      ? modelsParam
          .split(",")
          .slice(0, 100) // Limit number of models to prevent DoS
          .map(m => m.trim().slice(0, 256)) // Limit individual model name length
          .filter(m => m.length > 0) // Remove empty strings
      : undefined;

    return {
      owned_by: validatedOwnedBy,
      team_id: teamId?.trim() || undefined,
      key_alias: sanitizedKeyAlias,
      models: sanitizedModels && sanitizedModels.length > 0 ? sanitizedModels : undefined,
      key_type: validatedKeyType,
    };
  }, [searchParams, autoOpenCreate]);

  // Get page from URL, default to 'llm-playground' if not present
  const [page, setPage] = useState(() => {
    return searchParams.get("page") || "llm-playground";
  });

  // Custom setPage function that updates URL
  const updatePage = (newPage: string) => {
    // Update URL without full page reload
    const newSearchParams = new URLSearchParams(searchParams);
    newSearchParams.set("page", newPage);

    // Use Next.js router to update URL
    window.history.pushState(null, "", `?${newSearchParams.toString()}`);

    setPage(newPage);
  };

  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  // Track if we've already attempted a return URL redirect to prevent race conditions
  const hasAttemptedReturnRedirectRef = useRef(false);

  const toggleSidebar = () => {
    setSidebarCollapsed(!sidebarCollapsed);
  };

  const addKey = (data: any) => {
    setKeys((prevData) => (prevData ? [...prevData, data] : [data]));
    setCreateClicked(() => !createClicked);
  };
  const redirectToLogin = authLoading === false && token === null && invitation_id === null;
  const hasDashboardPageRequest = searchParams.has("page");
  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        await getUiConfig(); // ensures proxyBaseUrl etc. are ready
      } catch {
        // proceed regardless; we still need to decide auth state
      }

      if (cancelled) return;

      const raw = getCookie("token");
      let valid = raw && !isJwtExpired(raw) && !isLegacyInvalidAccessToken(raw) ? raw : null;

      if (!valid) {
        try {
          const res = await fetch(`${getProxyBaseUrl()}/public/dashboard-token`, { cache: "no-store" });
          if (res.ok) {
            const data = await res.json();
            if (data?.token) {
              document.cookie = `token=${data.token}; path=/; SameSite=Lax`;
              valid = data.token;
            }
          }
        } catch {
          // backend unreachable — dashboard will show limited UI
        }
      }

      if (!cancelled) {
        setToken(valid);
        setAuthLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  // Redirect legacy query-param pages to their new path-based routes
  const isLegacyRedirect = page in LEGACY_REDIRECTS;
  useEffect(() => {
    if (!redirectToLogin || !hasDashboardPageRequest) {
      return;
    }

    const target = `/ui/?${searchParams.toString()}`;
    router.replace(`/ui/login?redirect_to=${encodeURIComponent(target)}`);
  }, [hasDashboardPageRequest, redirectToLogin, router, searchParams]);

  useEffect(() => {
    if (!authLoading && isLegacyRedirect) {
      const base = (proxyBaseUrl || "") + "/ui";
      router.replace(`${base}/${LEGACY_REDIRECTS[page]}`);
    }
  }, [authLoading, isLegacyRedirect, page, router]);

  // Check for a stored return URL after successful authentication
  // This handles the case where user comes back from SSO and we need to redirect to the original URL
  useEffect(() => {
    // Skip if still loading, no token, or we've already attempted a redirect
    if (authLoading || !token || hasAttemptedReturnRedirectRef.current) {
      return;
    }

    // Mark that we've attempted the redirect to prevent race conditions
    // This prevents duplicate redirects if token changes (e.g., refresh)
    hasAttemptedReturnRedirectRef.current = true;

    // Check for a stored return URL
    const returnUrl = consumeReturnUrl();
    if (returnUrl && isValidReturnUrl(returnUrl)) {
      const currentUrl = window.location.href;
      const normalizedReturnUrl = normalizeUrlForCompare(returnUrl);
      const normalizedCurrentUrl = normalizeUrlForCompare(currentUrl);
      // Only redirect if the return URL is different from the current URL
      // This prevents infinite redirect loops
      if (normalizedReturnUrl !== normalizedCurrentUrl) {
        window.location.replace(returnUrl);
      }
    }
  }, [authLoading, token]);

  useEffect(() => {
    if (!token) {
      hasAttemptedReturnRedirectRef.current = false;
    }
  }, [token]);

  useEffect(() => {
    if (!token) {
      return;
    }

    // Defensive: re-check expiry in case cookie changed after mount
    if (isJwtExpired(token)) {
      deleteCookie("token", "/");
      setToken(null);
      return;
    }

    let decoded: any = null;
    try {
      decoded = jwtDecode(token);
    } catch {
      // Malformed token → treat as unauthenticated
      deleteCookie("token", "/");
      setToken(null);
      return;
    }

    if (decoded) {
      // set accessToken
      setAccessToken(decoded.login_method === "public_access" ? token : decoded.key);

      setDisabledPersonalKeyCreation(decoded.disabled_non_admin_personal_key_creation);

      // check if userRole is defined
      if (decoded.user_role) {
        const formattedUserRole = formatUserRole(decoded.user_role);
        setUserRole(formattedUserRole);
        if (formattedUserRole == "Admin Viewer") {
          setPage("usage");
        }
      }

      if (decoded.user_email) {
        setUserEmail(decoded.user_email);
      }

      if (decoded.login_method) {
        setShowSSOBanner(decoded.login_method == "username_password" ? true : false);
      }

      if (decoded.premium_user) {
        setPremiumUser(decoded.premium_user);
      }

      if (decoded.auth_header_name) {
        setGlobalZentrisHeaderName(decoded.auth_header_name);
      }

      if (decoded.user_id) {
        setUserID(decoded.user_id);
      }
    }
  }, [token]);

  useEffect(() => {
    if (accessToken && userID && userRole) {
      fetchUserModels(userID, userRole, accessToken, setUserModels);
    }
    if (accessToken && userID && userRole) {
      v2TeamListCall(accessToken, 1, 100, {
        userID: userRole !== "Admin" && userRole !== "Admin Viewer" ? userID : null,
      }).then((response) => setTeams(response.teams ?? [])).catch(console.error);
    }
    if (accessToken) {
      fetchOrganizations(accessToken, setOrganizations);
    }
  }, [accessToken, userID, userRole]);

  // Fetch in-product nudges configuration from backend
  useEffect(() => {
    if (accessToken && token) {
      (async () => {
        try {
          const nudgesConfig = await getInProductNudgesCall(accessToken);
          const isUsingClaudeCode = nudgesConfig?.is_claude_code_enabled || false;
          setIsClaudeCode(isUsingClaudeCode);

          // Show Claude Code prompt on login if enabled
          if (isUsingClaudeCode) {
            setShowClaudeCodePrompt(true);
            // Don't show the regular survey prompt if showing Claude Code prompt
            setShowSurveyPrompt(false);
          }
        } catch (error) {
          console.error("Failed to fetch in-product nudges:", error);
          // Silently fail and don't show Claude Code nudge
        }
      })();
    }
  }, [accessToken, token]);

  // Auto-dismiss survey prompt after 15 seconds
  useEffect(() => {
    if (showSurveyPrompt && !showSurveyModal) {
      const timer = setTimeout(() => {
        setShowSurveyPrompt(false);
      }, 15000);
      return () => clearTimeout(timer);
    }
  }, [showSurveyPrompt, showSurveyModal]);

  // Auto-dismiss Claude Code prompt after 15 seconds
  useEffect(() => {
    if (showClaudeCodePrompt && !showClaudeCodeModal) {
      const timer = setTimeout(() => {
        setShowClaudeCodePrompt(false);
      }, 15000);
      return () => clearTimeout(timer);
    }
  }, [showClaudeCodePrompt, showClaudeCodeModal]);

  const handleOpenSurvey = () => {
    setShowSurveyPrompt(false);
    setShowSurveyModal(true);
  };

  const handleDismissSurveyPrompt = () => {
    setShowSurveyPrompt(false);
  };

  const handleSurveyComplete = () => {
    setShowSurveyModal(false);
  };

  const handleSurveyModalClose = () => {
    // If they close the modal without completing, show the prompt again
    setShowSurveyModal(false);
    setShowSurveyPrompt(true);
  };

  const handleOpenClaudeCode = () => {
    setShowClaudeCodePrompt(false);
    setShowClaudeCodeModal(true);
  };

  const handleDismissClaudeCodePrompt = () => {
    setShowClaudeCodePrompt(false);
  };

  const handleClaudeCodeComplete = () => {
    setShowClaudeCodeModal(false);
  };

  const handleClaudeCodeModalClose = () => {
    // If they close the modal without completing, show the prompt again
    setShowClaudeCodeModal(false);
    setShowClaudeCodePrompt(true);
  };

  if (authLoading || isLegacyRedirect) {
    return <LoadingScreen />;
  }

  if (redirectToLogin) {
    if (hasDashboardPageRequest) {
      return <LoadingScreen />;
    }
    return <LoginPage />;
  }

  return (
    <Suspense fallback={<LoadingScreen />}>
      <ConfigProvider theme={{
          algorithm: isDarkMode ? theme.darkAlgorithm : theme.defaultAlgorithm,
        }}>
          <ThemeProvider accessToken={accessToken}>
            <ZentrisBrandingEnforcer />
            {invitation_id ? (
              <UserDashboard
                userID={userID}
                userRole={userRole}
                premiumUser={premiumUser}
                teams={teams}
                keys={keys}
                setUserRole={setUserRole}
                userEmail={userEmail}
                setUserEmail={setUserEmail}
                setTeams={setTeams}
                setKeys={setKeys}
                organizations={organizations}
                addKey={addKey}
                createClicked={createClicked}
              />
            ) : (
              <div className="flex flex-col min-h-screen">
                <Navbar
                  userID={userID}
                  userRole={userRole}
                  premiumUser={premiumUser}
                  userEmail={userEmail}
                  setProxySettings={setProxySettings}
                  proxySettings={proxySettings}
                  accessToken={accessToken}
                  isPublicPage={false}
                  sidebarCollapsed={sidebarCollapsed}
                  onToggleSidebar={toggleSidebar}
                  isDarkMode={isDarkMode}
                  toggleDarkMode={toggleDarkMode}
                />
                <div className="flex flex-1">
                  <div className="mt-2">
                  <SidebarProvider setPage={updatePage} defaultSelectedKey={page} sidebarCollapsed={sidebarCollapsed} />
                </div>
                  {page == "api-keys" ? (
                    <UserDashboard
                      userID={userID}
                      userRole={userRole}
                      premiumUser={premiumUser}
                      teams={teams}
                      keys={keys}
                      setUserRole={setUserRole}
                      userEmail={userEmail}
                      setUserEmail={setUserEmail}
                      setTeams={setTeams}
                      setKeys={setKeys}
                      organizations={organizations}
                      addKey={addKey}
                      createClicked={createClicked}
                      autoOpenCreate={autoOpenCreate}
                      prefillData={prefillData}
                    />
                  ) : page == "models" ? (
                    <OldModelDashboard
                      token={token}
                      keys={keys}
                      modelData={modelData}
                      setModelData={setModelData}
                      premiumUser={premiumUser}
                      teams={teams}
                    />
                  ) : page == "llm-playground" ? (
                    <PlaygroundPage />
                  ) : page == "users" ? (
                    <ViewUserDashboard
                      userID={userID}
                      userRole={userRole}
                      token={token}
                      keys={keys}
                      teams={teams}
                      accessToken={accessToken}
                      setKeys={setKeys}
                    />
                  ) : page == "teams" ? (
                    <OldTeams
                      teams={teams}
                      setTeams={setTeams}
                      accessToken={accessToken}
                      userID={userID}
                      userRole={userRole}
                      organizations={organizations}
                      premiumUser={premiumUser}
                      searchParams={searchParams}
                    />
                  ) : page == "organizations" ? (
                    <Organizations
                      organizations={organizations}
                      setOrganizations={setOrganizations}
                      userModels={userModels}
                      accessToken={accessToken}
                      userRole={userRole}
                      premiumUser={premiumUser}
                    />
                  ) : page == "admin-panel" ? (
                    <AdminPanel
                      proxySettings={proxySettings}
                    />
                  ) : page == "logging-and-alerts" ? (
                    <Settings userID={userID} userRole={userRole} accessToken={accessToken} premiumUser={premiumUser} />
                  ) : page == "budgets" ? (
                    <BudgetPanel accessToken={accessToken} />
                  ) : page == "guardrails" ? (
                    <GuardrailsPanel accessToken={accessToken} userRole={userRole} />
                  ) : page == "zentris-security" ? (
                    <ZentrisSecurityDashboard />
                  ) : page == "policies" ? (
                    <PoliciesPanel accessToken={accessToken} userRole={userRole} />
                  ) : page == "agents" ? (
                    <AgentsPanel accessToken={accessToken} userRole={userRole} teams={teams} />
                  ) : page == "prompts" ? (
                    <PromptsPanel accessToken={accessToken} userRole={userRole} />
                  ) : page == "transform-request" ? (
                    <TransformRequestPanel accessToken={accessToken} />
                  ) : page == "router-settings" ? (
                    <GeneralSettings
                      userID={userID}
                      userRole={userRole}
                      accessToken={accessToken}
                      modelData={modelData}
                    />
                  ) : page == "ui-theme" ? (
                    <UIThemeSettings userID={userID} userRole={userRole} accessToken={accessToken} />
                  ) : page == "cost-tracking" ? (
                    <CostTrackingSettings userID={userID} userRole={userRole} accessToken={accessToken} />
                  ) : page == "model-hub-table" ? (
                    isAdminRole(userRole) ? (
                      <ModelHubTable
                        accessToken={accessToken}
                        publicPage={false}
                        premiumUser={premiumUser}
                        userRole={userRole}
                      />
                    ) : (
                      <PublicModelHub accessToken={accessToken} isEmbedded={true} />
                    )
                  ) : page == "caching" ? (
                    <CacheDashboard
                      userID={userID}
                      userRole={userRole}
                      token={token}
                      accessToken={accessToken}
                      premiumUser={premiumUser}
                    />
                  ) : page == "pass-through-settings" ? (
                    <PassThroughSettings
                      userID={userID}
                      userRole={userRole}
                      accessToken={accessToken}
                      modelData={modelData}
                      premiumUser={premiumUser}
                    />
                  ) : page == "logs" ? (
                    <SpendLogsTable
                      userID={userID}
                      userRole={userRole}
                      token={token}
                      accessToken={accessToken}
                      allTeams={(teams as Team[]) ?? []}
                      premiumUser={premiumUser}
                    />
                  ) : page == "mcp-servers" ? (
                    <MCPServers accessToken={accessToken} userRole={userRole} userID={userID} />
                  ) : page == "search-tools" ? (
                    <SearchTools accessToken={accessToken} userRole={userRole} userID={userID} />
                  ) : page == "tag-management" ? (
                    <TagManagement accessToken={accessToken} userRole={userRole} userID={userID} />
                  ) : page == "claude-code-plugins" ? (
                    <ClaudeCodePluginsPanel accessToken={accessToken} userRole={userRole} />
                  ) : page == "access-groups" ? (
                    <AccessGroupsPage />
                  ) : page == "projects" ? (
                    <ProjectsPage />
                  ) : page == "vector-stores" ? (
                    <VectorStoreManagement accessToken={accessToken} userRole={userRole} userID={userID} />
                  ) : page == "tool-policies" ? (
                    <ToolPoliciesView accessToken={accessToken} userRole={userRole} />
                  ) : page == "guardrails-monitor" ? (
                    <GuardrailsMonitorView accessToken={accessToken} />
                  ) : page == "new_usage" ? (
                    <NewUsagePage
                      teams={(teams as Team[]) ?? []}
                      organizations={(organizations as Organization[]) ?? []}
                    />
                  ) : (
                    <Usage
                      userID={userID}
                      userRole={userRole}
                      token={token}
                      accessToken={accessToken}
                      keys={keys}
                      premiumUser={premiumUser}
                    />
                  )}
                </div>

              </div>
            )}
          </ThemeProvider>
        </ConfigProvider>
    </Suspense>
  );
}

export default function CreateKeyPage() {
  return (
    <Suspense fallback={<LoadingScreen />}>
      <CreateKeyPageContent />
    </Suspense>
  );
}



