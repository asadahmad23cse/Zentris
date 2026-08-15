"use client";

import { useMemo, useState } from "react";

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
  timestamp: number;
};

const API_BASE_URL = process.env.NEXT_PUBLIC_ZENTRIS_API_URL || "https://zentris-api.onrender.com";

export default function PublicChatPage() {
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [status, setStatus] = useState<"idle" | "loading" | "error">("idle");
  const [notice, setNotice] = useState("");
  const sessionId = useMemo(() => `web-${Math.random().toString(36).slice(2, 12)}`, []);

  const sendMessage = async () => {
    const trimmed = input.trim();
    if (!trimmed || status === "loading") return;

    const nextMessages: ChatMessage[] = [
      ...messages,
      { role: "user", content: trimmed, timestamp: Date.now() },
    ];

    setMessages(nextMessages);
    setInput("");
    setStatus("loading");
    setNotice("");

    try {
      const response = await fetch(`${API_BASE_URL}/v1/public/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionId,
          message: trimmed,
          history: messages.slice(-10),
        }),
      });

      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.reason || data.error || `Request failed with ${response.status}`);
      }

      if (data.requiresConfirmation) {
        setNotice("This request needs confirmation because Zentris marked it as high risk.");
      }

      setMessages([
        ...nextMessages,
        {
          role: "assistant",
          content: data.response || data.message || "No response returned.",
          timestamp: Date.now(),
        },
      ]);
      setNotice(`Risk: ${data.riskLevel || "unknown"} | Request: ${data.requestId || "n/a"}`);
      setStatus("idle");
    } catch (error) {
      setStatus("error");
      setNotice(error instanceof Error ? error.message : "Chat request failed");
    }
  };

  return (
    <main className="min-h-screen bg-slate-50 text-slate-950">
      <header className="h-16 border-b border-slate-200 bg-white px-6 md:px-12 flex items-center justify-between">
        <a href="/ui/" className="flex items-center gap-3 font-extrabold text-lg">
          <img src="/assets/logos/zentris_logo.svg" alt="Zentris" className="h-8 w-8" />
          Zentris
        </a>
        <nav className="flex items-center gap-4 text-sm font-semibold">
          <a href="/ui/?page=llm-playground" className="text-slate-600 hover:text-slate-950">Main dashboard</a>
          <a href="/ui/model_hub" className="text-slate-600 hover:text-slate-950">Models</a>
          <span className="rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-emerald-700">Live</span>
        </nav>
      </header>

      <section className="mx-auto max-w-5xl px-5 py-8 md:py-12">
        <div className="mb-6">
          <p className="mb-2 text-sm font-bold uppercase text-teal-700">Public AI Gateway</p>
          <h1 className="text-3xl md:text-5xl font-black tracking-normal">Test Zentris chat</h1>
          <p className="mt-3 max-w-2xl text-slate-600">
            Send a prompt through the production backend with prompt-injection checks, policy gating,
            rate limits, and upstream model routing.
          </p>
        </div>

        <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
          <div className="h-[52vh] min-h-[360px] overflow-y-auto p-5 md:p-6 space-y-4">
            {messages.length === 0 ? (
              <div className="grid h-full place-items-center text-center text-slate-500">
                <div>
                  <p className="font-semibold text-slate-700">Ask a question to test the live backend.</p>
                  <p className="mt-1 text-sm">Example: "Explain what Zentris protects against in 4 bullets."</p>
                </div>
              </div>
            ) : (
              messages.map((message, index) => (
                <div
                  key={`${message.timestamp}-${index}`}
                  className={`flex ${message.role === "user" ? "justify-end" : "justify-start"}`}
                >
                  <div
                    className={`max-w-[82%] rounded-lg px-4 py-3 text-sm leading-6 ${
                      message.role === "user"
                        ? "bg-slate-950 text-white"
                        : "border border-slate-200 bg-slate-50 text-slate-900"
                    }`}
                  >
                    {message.content}
                  </div>
                </div>
              ))
            )}
            {status === "loading" && (
              <div className="text-sm font-semibold text-slate-500">Generating response...</div>
            )}
          </div>

          {notice && (
            <div className={`border-t px-5 py-3 text-sm ${status === "error" ? "border-red-100 bg-red-50 text-red-700" : "border-slate-100 bg-slate-50 text-slate-600"}`}>
              {notice}
            </div>
          )}

          <div className="border-t border-slate-200 p-4">
            <div className="flex flex-col gap-3 md:flex-row">
              <textarea
                value={input}
                onChange={(event) => setInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    void sendMessage();
                  }
                }}
                placeholder="Type your message..."
                className="min-h-24 flex-1 resize-none rounded-lg border border-slate-300 px-4 py-3 text-sm outline-none focus:border-slate-950"
              />
              <button
                onClick={() => void sendMessage()}
                disabled={status === "loading" || input.trim().length === 0}
                className="h-12 rounded-lg bg-slate-950 px-6 text-sm font-bold text-white disabled:cursor-not-allowed disabled:bg-slate-300 md:self-end"
              >
                Send
              </button>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
