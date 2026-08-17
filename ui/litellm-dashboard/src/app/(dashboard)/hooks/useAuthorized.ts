"use client";

import { getProxyBaseUrl } from "@/components/networking";
import { clearTokenCookies, getCookie } from "@/utils/cookieUtils";
import { checkTokenValidity, decodeToken } from "@/utils/jwtUtils";
import { buildLoginUrlWithReturn, storeReturnUrl } from "@/utils/returnUrlUtils";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { formatUserRole } from "@/utils/roles";
import { useUIConfig } from "./uiConfig/useUIConfig";

const isLegacyInvalidAccessToken = (token: string): boolean => {
  const [headerSegment, , signatureSegment] = token.split(".");
  if (!headerSegment || !signatureSegment) return true;
  try {
    const padded = headerSegment.padEnd(headerSegment.length + ((4 - (headerSegment.length % 4)) % 4), "=");
    const header = JSON.parse(atob(padded.replace(/-/g, "+").replace(/_/g, "/")));
    return header?.alg !== "HS256" || signatureSegment === "public";
  } catch {
    return true;
  }
};

const fetchPublicToken = async (): Promise<string | null> => {
  try {
    const res = await fetch(`${getProxyBaseUrl()}/public/dashboard-token`, { cache: "no-store" });
    if (!res.ok) return null;
    const data = await res.json();
    if (data?.token) {
      document.cookie = `token=${data.token}; path=/; SameSite=Lax`;
      return data.token;
    }
    return null;
  } catch {
    return null;
  }
};

const useAuthorized = () => {
  const router = useRouter();
  const { data: uiConfig, isLoading: isUIConfigLoading } = useUIConfig();

  const rawCookie = typeof document !== "undefined" ? getCookie("token") : null;
  const isRawValid =
    rawCookie != null &&
    !isLegacyInvalidAccessToken(rawCookie) &&
    checkTokenValidity(rawCookie);

  const [token, setToken] = useState<string | null>(isRawValid ? rawCookie : null);
  const [fetchingToken, setFetchingToken] = useState(!isRawValid);

  useEffect(() => {
    if (isRawValid) {
      setToken(rawCookie);
      setFetchingToken(false);
      return;
    }
    setFetchingToken(true);
    fetchPublicToken().then((t) => {
      setToken(t);
      setFetchingToken(false);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const decoded = useMemo(() => decodeToken(token), [token]);
  const isTokenValid = useMemo(() => checkTokenValidity(token), [token]);
  const isLoading = isUIConfigLoading || fetchingToken;
  const isAuthorized = isTokenValid && !uiConfig?.admin_ui_disabled;

  const redirectToLogin = useCallback(() => {
    storeReturnUrl();
    const baseLoginUrl =
      typeof window !== "undefined" && window.location.port === "3001"
        ? `${window.location.origin}/login`
        : `${getProxyBaseUrl()}/ui/login`;
    const loginUrlWithReturn = buildLoginUrlWithReturn(baseLoginUrl);
    router.replace(loginUrlWithReturn);
  }, [router]);

  useEffect(() => {
    if (isLoading) return;
    if (!isAuthorized) {
      if (token) clearTokenCookies();
      redirectToLogin();
    }
  }, [isLoading, isAuthorized, token, redirectToLogin]);

  return {
    isLoading,
    isAuthorized,
    token: isAuthorized ? token : null,
    accessToken: decoded?.login_method === "public_access" ? token : (decoded?.key ?? null),
    userId: decoded?.user_id ?? null,
    userEmail: decoded?.user_email ?? null,
    userRole: formatUserRole(decoded?.user_role),
    premiumUser: decoded?.premium_user ?? null,
    disabledPersonalKeyCreation: decoded?.disabled_non_admin_personal_key_creation ?? null,
    showSSOBanner: decoded?.login_method === "username_password",
  };
};

export default useAuthorized;
