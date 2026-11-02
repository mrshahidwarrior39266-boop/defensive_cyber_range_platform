import { useCallback, useEffect, useRef, useState } from "react";

export function useReveal<T extends HTMLElement>(delay = 0) {
  const ref = useRef<T | null>(null);

  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    node.style.setProperty("--reveal-delay", `${delay}ms`);
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      node.classList.add("is-in");
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            node.classList.add("is-in");
            observer.disconnect();
          }
        });
      },
      { rootMargin: "0px 0px -12% 0px", threshold: 0.08 },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [delay]);

  return ref;
}

export function useDocumentTitle(title: string) {
  useEffect(() => {
    const previous = document.title;
    document.title = title;
    return () => {
      document.title = previous;
    };
  }, [title]);
}

export function useMediaQuery(query: string) {
  const [matches, setMatches] = useState(() =>
    typeof window === "undefined" ? false : window.matchMedia(query).matches,
  );

  useEffect(() => {
    const list = window.matchMedia(query);
    const handler = () => setMatches(list.matches);
    handler();
    list.addEventListener("change", handler);
    return () => list.removeEventListener("change", handler);
  }, [query]);

  return matches;
}

export function useScrolled(threshold = 24) {
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => {
    const handler = () => setScrolled(window.scrollY > threshold);
    handler();
    window.addEventListener("scroll", handler, { passive: true });
    return () => window.removeEventListener("scroll", handler);
  }, [threshold]);
  return scrolled;
}

/**
 * Prevents accidental duplicate execution of a critical action. The lock is
 * acquired synchronously, so a rapid double click cannot run the action twice.
 */
export function useActionLock(cooldown = 700) {
  const locked = useRef(false);
  const [busy, setBusy] = useState(false);

  const release = useCallback(() => {
    locked.current = false;
    setBusy(false);
  }, []);

  const run = useCallback(
    async <T,>(action: () => T | Promise<T>): Promise<T | undefined> => {
      if (locked.current) return undefined;
      locked.current = true;
      setBusy(true);
      try {
        return await action();
      } finally {
        window.setTimeout(release, cooldown);
      }
    },
    [cooldown, release],
  );

  return { busy, run };
}
