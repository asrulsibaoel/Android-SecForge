import { Link, Outlet, useLocation } from 'react-router-dom';
import { useEffect, useState } from 'react';

// Root shell: top bar + theme toggle. Theme is a UI preference only (§20) — no
// analytical truth is stored client-side.
export function RootLayout() {
  const [theme, setTheme] = useState<string>(() => {
    try {
      return localStorage.getItem('asf-theme') || 'system';
    } catch {
      return 'system';
    }
  });

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'system') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', theme);
    try {
      localStorage.setItem('asf-theme', theme);
    } catch {
      /* storage may be unavailable */
    }
  }, [theme]);

  const loc = useLocation();

  return (
    <div className="app">
      <header className="topbar">
        <Link to="/" className="brand">
          <span className="brand__mark">◈</span> AndroidSecForge
          <span className="brand__sub">Investigation Workspace</span>
        </Link>
        <nav className="topbar__nav" aria-label="Primary">
          <Link to="/" className={loc.pathname === '/' ? 'active' : ''}>Dashboard</Link>
          <Link to="/analyses/new" className={loc.pathname.startsWith('/analyses/new') ? 'active' : ''}>New Analysis</Link>
          <Link to="/investigations" className={loc.pathname.startsWith('/investigations') ? 'active' : ''}>Investigations</Link>
        </nav>
        <div className="topbar__right">
          <label className="theme-toggle">
            <span className="sr-only">Theme</span>
            <select value={theme} onChange={(e) => setTheme(e.target.value)} aria-label="Theme">
              <option value="system">System</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
          </label>
        </div>
      </header>
      <main className="content">
        <Outlet />
      </main>
      <footer className="footer muted">
        Presentation layer over the canonical backend. The database and knowledge graph remain authoritative — the UI
        creates no analytical truth and introduces no “exploitable” conclusion.
      </footer>
    </div>
  );
}
