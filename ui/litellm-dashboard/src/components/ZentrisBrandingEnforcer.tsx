"use client";

import { useEffect } from "react";

const BLOCKED_LABELS = ["Join Slack", "Star us on GitHub", "Quick feedback", "Share feedback", "Don't ask me again"];

function enforceZentrisBranding() {
  document.title = document.title.replace(/LiteLLM/g, "Zentris");

  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const textNodes: Text[] = [];
  while (walker.nextNode()) {
    const node = walker.currentNode as Text;
    if (node.nodeValue?.includes("LiteLLM")) {
      textNodes.push(node);
    }
  }
  textNodes.forEach((node) => {
    node.nodeValue = node.nodeValue?.replace(/LiteLLM/g, "Zentris") ?? node.nodeValue;
  });

  document.querySelectorAll("a, button, [role='button']").forEach((element) => {
    const label = element.textContent?.trim();
    if (label && BLOCKED_LABELS.some((blocked) => label.includes(blocked))) {
      element.remove();
    }
  });
}

export default function ZentrisBrandingEnforcer() {
  useEffect(() => {
    enforceZentrisBranding();
    const observer = new MutationObserver(enforceZentrisBranding);
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    const timer = window.setInterval(enforceZentrisBranding, 500);
    return () => {
      observer.disconnect();
      window.clearInterval(timer);
    };
  }, []);

  return null;
}
