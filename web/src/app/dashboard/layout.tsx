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

  const tab = (href: string, label: string) => (
    <Link
      href={href}
      style={{
        color: pathname === href ? "var(--text)" : "var(--muted)",
        fontWeight: pathname === href ? 600 : 400,
      }}
    >
      {label}
    </Link>
  );

  return (
    <>
      <nav className="nav">
        <Brand size={24} />
        {tab("/dashboard", "Traces")}
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
