import { startTransition, useEffect, useState } from "react";
import { BrowserRouter, Link, NavLink, Outlet, Route, Routes } from "react-router-dom";

import { DirectoryPage } from "./pages/directory-page";
import { ImageDetailPage } from "./pages/image-detail-page";

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
      <header className="sticky top-0 z-30 border-b border-white/60 bg-white/75 backdrop-blur-xl dark:border-white/10 dark:bg-ink-900/70">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-6 px-4 py-4 sm:px-6 lg:px-8">
          <div className="flex items-center gap-4">
            <Link to="/" className="inline-flex items-center gap-3">
              <span className="flex h-10 w-10 items-center justify-center rounded-2xl bg-ink-900 font-display text-lg text-white shadow-haze dark:bg-tide">
                O
              </span>
              <div>
                <p className="font-display text-xl tracking-tight text-ink-900 dark:text-white">Otter</p>
                <p className="text-sm text-ink-500 dark:text-ink-300">Container image analyzer</p>
              </div>
            </Link>
            <nav className="hidden items-center gap-2 rounded-full border border-white/70 bg-white/70 p-1 text-sm shadow-haze dark:border-white/10 dark:bg-ink-900/85 md:flex">
              <NavLink
                to="/"
                className={({ isActive }) =>
                  `rounded-full px-4 py-2 ${isActive ? "bg-ink-900 text-white dark:bg-white dark:text-ink-900" : "text-ink-600 hover:text-ink-900 dark:text-ink-300 dark:hover:text-white"}`
                }
              >
                Directory
              </NavLink>
              <a
                href="/browse"
                className="rounded-full px-4 py-2 text-ink-600 hover:text-ink-900 dark:text-ink-300 dark:hover:text-white"
              >
                HTML fallback
              </a>
            </nav>
          </div>
          <button
            type="button"
            onClick={toggleTheme}
            className="rounded-full border border-ink-300 px-4 py-2 text-sm text-ink-700 transition hover:border-ink-900 hover:text-ink-900 dark:border-ink-700 dark:text-ink-200 dark:hover:border-white dark:hover:text-white"
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
          <Route path="/" element={<DirectoryPage />} />
          <Route path="/images/:orgId/:imageId" element={<ImageDetailPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
