import { startTransition, useEffect, useState } from "react";
import { BrowserRouter, Link, NavLink, Outlet, Route, Routes } from "react-router-dom";

import { DocsPage } from "./pages/docs-page";
import { DirectoryPage } from "./pages/directory-page";
import { ImageDetailPage } from "./pages/image-detail-page";
import { LandingPage } from "./pages/landing-page";

function useThemeMode() {
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    const stored = window.localStorage.getItem("otter-theme");
    if (stored === "light" || stored === "dark") {
      return stored;
    }
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    window.localStorage.setItem("otter-theme", theme);
  }, [theme]);

  return {
    theme,
    toggleTheme: () => {
      startTransition(() => {
        setTheme((current) => (current === "dark" ? "light" : "dark"));
      });
    }
  };
}

function Layout() {
  const { theme, toggleTheme } = useThemeMode();

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-30 border-b border-ink-200 bg-white dark:border-ink-800 dark:bg-ink-950">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-6 px-4 py-3 sm:px-6 lg:px-8">
          <div className="flex items-center gap-4">
            <Link to="/" className="inline-flex items-center gap-3">
              <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-ink-900 font-display text-lg text-white dark:bg-tide">
                O
              </span>
              <div>
                <p className="font-display text-lg tracking-tight text-ink-900 dark:text-white">Otter</p>
                <p className="text-xs text-ink-500 dark:text-ink-400">Container image analyzer</p>
              </div>
            </Link>
            <nav className="hidden items-center gap-1 text-sm md:flex">
              <NavLink
                to="/"
                className={({ isActive }) =>
                  `rounded-md px-3 py-1.5 ${isActive ? "bg-ink-900 text-white dark:bg-white dark:text-ink-900" : "text-ink-600 hover:text-ink-900 dark:text-ink-300 dark:hover:text-white"}`
                }
              >
                Home
              </NavLink>
              <NavLink
                to="/directory"
                className={({ isActive }) =>
                  `rounded-md px-3 py-1.5 ${isActive ? "bg-ink-900 text-white dark:bg-white dark:text-ink-900" : "text-ink-600 hover:text-ink-900 dark:text-ink-300 dark:hover:text-white"}`
                }
              >
                Directory
              </NavLink>
              <NavLink
                to="/docs"
                className={({ isActive }) =>
                  `rounded-md px-3 py-1.5 ${isActive ? "bg-ink-900 text-white dark:bg-white dark:text-ink-900" : "text-ink-600 hover:text-ink-900 dark:text-ink-300 dark:hover:text-white"}`
                }
              >
                Docs
              </NavLink>
              <a
                href="/browse"
                className="rounded-md px-3 py-1.5 text-ink-600 hover:text-ink-900 dark:text-ink-300 dark:hover:text-white"
              >
                HTML fallback
              </a>
            </nav>
          </div>
          <button
            type="button"
            onClick={toggleTheme}
            className="rounded-md border border-ink-200 px-3 py-1.5 text-sm text-ink-700 transition hover:border-ink-900 hover:text-ink-900 dark:border-ink-700 dark:text-ink-200 dark:hover:border-white dark:hover:text-white"
            aria-label="Toggle color mode"
          >
            {theme === "dark" ? "Light mode" : "Dark mode"}
          </button>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <Outlet />
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<LandingPage />} />
          <Route path="/directory" element={<DirectoryPage />} />
          <Route path="/docs" element={<DocsPage />} />
          <Route path="/images/:orgId/:imageId" element={<ImageDetailPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
