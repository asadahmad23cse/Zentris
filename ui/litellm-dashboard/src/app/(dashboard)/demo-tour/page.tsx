"use client";

import Link from "next/link";
import { ArrowRight, CheckCircle2, PlayCircle, ShieldCheck, Sparkles } from "lucide-react";

const steps = [
  {
    number: "01",
    title: "Try a safe AI request",
    detail: "Open the Playground, choose the preselected model and send one of the sample prompts.",
    href: "/ui/test-key",
    cta: "Open Playground",
    icon: PlayCircle
  },
  {
    number: "02",
    title: "Show the available models",
    detail: "Use Model Hub to explain providers, capabilities and endpoint health without opening technical settings.",
    href: "/ui/model-hub",
    cta: "View Model Hub",
    icon: Sparkles
  },
  {
    number: "03",
    title: "Demonstrate security controls",
    detail: "Walk through injection blocking, PII protection and approval gates in the Zentris Security dashboard.",
    href: "/ui/zentris-security",
    cta: "Open Security Center",
    icon: ShieldCheck
  }
];

export default function DemoTourPage() {
  return (
    <main className="mx-auto w-full max-w-6xl p-6 md:p-10">
      <section className="rounded-3xl border border-sky-100 bg-gradient-to-br from-slate-950 via-slate-900 to-sky-900 p-8 text-white shadow-xl md:p-12">
        <p className="mb-3 text-sm font-semibold uppercase tracking-[0.22em] text-sky-300">Zentris live demo</p>
        <h1 className="max-w-3xl text-4xl font-bold tracking-tight md:text-5xl">Show secure AI in three clear steps.</h1>
        <p className="mt-5 max-w-2xl text-base leading-7 text-slate-200 md:text-lg">
          This guided flow is designed for an interview or product demonstration. Each step uses the live Zentris deployment.
        </p>
        <div className="mt-7 flex flex-wrap gap-3 text-sm">
          <span className="rounded-full bg-emerald-400/15 px-4 py-2 text-emerald-200"><CheckCircle2 className="mr-2 inline h-4 w-4" />Live API connected</span>
          <span className="rounded-full bg-sky-400/15 px-4 py-2 text-sky-100">Model routing + guardrails + audit visibility</span>
        </div>
      </section>

      <section className="mt-8 grid gap-5 md:grid-cols-3">
        {steps.map(({ number, title, detail, href, cta, icon: Icon }) => (
          <article key={number} className="flex min-h-72 flex-col rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="flex items-center justify-between"><span className="text-sm font-bold tracking-wider text-sky-700">STEP {number}</span><Icon className="h-6 w-6 text-sky-600" /></div>
            <h2 className="mt-8 text-xl font-bold text-slate-900">{title}</h2>
            <p className="mt-3 flex-1 text-sm leading-6 text-slate-600">{detail}</p>
            <Link href={href} className="mt-6 inline-flex items-center justify-center gap-2 rounded-xl bg-slate-900 px-4 py-3 text-sm font-semibold text-white transition hover:bg-sky-700">
              {cta}<ArrowRight className="h-4 w-4" />
            </Link>
          </article>
        ))}
      </section>

      <section className="mt-8 rounded-2xl border border-amber-200 bg-amber-50 p-6 text-amber-950">
        <h2 className="font-bold">Suggested 90-second interview script</h2>
        <p className="mt-2 text-sm leading-6">“Zentris is an AI security gateway. First, it provides controlled access to models. Next, it observes and governs requests. Finally, it blocks prompt injections, protects PII, and requires approval for high-impact actions.”</p>
      </section>
    </main>
  );
}
