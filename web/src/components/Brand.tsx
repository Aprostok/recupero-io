import Link from "next/link";

/**
 * Recupero brand lockup — a rounded badge mark (a "trace" glyph: two nodes
 * joined by a routed path, i.e. following the funds) plus the wordmark. The
 * blue→violet gradient is the one place the brand gradient is used in chrome.
 */
export function BrandMark({ size = 26 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <defs>
        <linearGradient id="rc-brand" x1="0" y1="0" x2="32" y2="32" gradientUnits="userSpaceOnUse">
          <stop stopColor="#4D84FF" />
          <stop offset="1" stopColor="#8A63FF" />
        </linearGradient>
      </defs>
      <rect width="32" height="32" rx="9" fill="url(#rc-brand)" />
      <path
        d="M10 22.5c3.2 0 3.2-6.5 6.4-6.5s3.2-6.5 6.4-6.5"
        stroke="#fff"
        strokeWidth="2"
        strokeLinecap="round"
        opacity="0.95"
      />
      <circle cx="10" cy="22.5" r="2.6" fill="#fff" />
      <circle cx="22.8" cy="9.5" r="2.6" fill="#fff" />
    </svg>
  );
}

/** Full brand lockup; links home unless `asLink={false}`. */
export function Brand({
  asLink = true,
  size = 26,
  style,
}: {
  asLink?: boolean;
  size?: number;
  style?: React.CSSProperties;
}) {
  const inner = (
    <>
      <BrandMark size={size} />
      Recupero
    </>
  );
  if (!asLink) {
    return (
      <span className="brand" style={style}>
        {inner}
      </span>
    );
  }
  return (
    <Link href="/" className="brand" style={style}>
      {inner}
    </Link>
  );
}
