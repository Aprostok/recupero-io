"use client";

import { useEffect } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { Brand } from "@/components/Brand";

/** Auth guard + top nav for every /dashboard route. */
export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { token, ready, logout } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (ready && !token) router.replace("/login");
  }, [ready, token, router]);

  if (!ready || !token) {
    return (
      <div className="container">
        <p className="muted">Loading…</p>
      </div>
    );
  }

  const tab = (href: string, label: string) => {
    // Exact match for the Home tab; prefix match for sections so a sub-page
    // (e.g. a case at /dashboard/traces/<id>) still highlights "Traces".
    const active =
      pathname === href || (href !== "/dashboard" && pathname.startsWith(`${href}/`));
    return (
      <Link
        href={href}
        style={{
          color: active ? "var(--text)" : "var(--muted)",
          fontWeight: active ? 600 : 400,
        }}
      >
        {label}
      </Link>
    );
  };

  return (
    <>
      <nav className="nav">
        <Brand size={24} />
        {tab("/dashboard", "Home")}
        {tab("/dashboard/traces", "Traces")}
        {tab("/dashboard/guard", "Wallet Guard")}
        {tab("/dashboard/assistant", "Assistant")}
        {tab("/dashboard/keys", "API Keys")}
        {tab("/dashboard/members", "Members")}
        {tab("/dashboard/activity", "Activity")}
        {tab("/dashboard/billing", "Billing")}
        <span className="spacer" />
        <button
          className="ghost"
          onClick={() => {
            logout();
            router.replace("/login");
          }}
        >
          Sign out
        </button>
      </nav>
      <div className="container">{children}</div>
    </>
  );
}
