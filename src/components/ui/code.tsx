import type { ReactNode } from "react";
import { useId } from "react";
import { cn } from "../../lib/utils";
import { CopyButton } from "./primitives";
import "./ui.css";

const KEYWORDS = new Set([
  "def",
  "class",
  "return",
  "if",
  "elif",
  "else",
  "for",
  "while",
  "in",
  "not",
  "and",
  "or",
  "None",
  "True",
  "False",
  "try",
  "except",
  "finally",
  "raise",
  "with",
  "as",
  "import",
  "from",
  "pass",
  "lambda",
  "yield",
  "assert",
  "global",
  "async",
  "await",
  "is",
  "self",
]);

function highlightPython(line: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const pattern =
    /(#[^\n]*)|("""[\s\S]*?"""|'''[\s\S]*?'''|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|\b([A-Za-z_][A-Za-z0-9_]*)\b|\b(\d+(?:\.\d+)?)\b/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let key = 0;

  while ((match = pattern.exec(line)) !== null) {
    if (match.index > lastIndex) {
      nodes.push(line.slice(lastIndex, match.index));
    }
    const [text, comment, string, word, number] = match;
    if (comment) {
      nodes.push(
        <span className="tok-com" key={key++}>
          {text}
        </span>,
      );
    } else if (string) {
      nodes.push(
        <span className="tok-str" key={key++}>
          {text}
        </span>,
      );
    } else if (number) {
      nodes.push(
        <span className="tok-num" key={key++}>
          {text}
        </span>,
      );
    } else if (word) {
      const isKeyword = KEYWORDS.has(word);
      const isCall = /^\s*\(/.test(line.slice(match.index + text.length));
      if (isKeyword) {
        nodes.push(
          <span className="tok-kw" key={key++}>
            {text}
          </span>,
        );
      } else if (isCall) {
        nodes.push(
          <span className="tok-fn" key={key++}>
            {text}
          </span>,
        );
      } else {
        nodes.push(text);
      }
    } else {
      nodes.push(text);
    }
    lastIndex = match.index + text.length;
  }
  if (lastIndex < line.length) nodes.push(line.slice(lastIndex));
  return nodes;
}

function highlightJson(line: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const pattern =
    /("(?:[^"\\]|\\.)*")(\s*:)?|\b(true|false|null)\b|\b(-?\d+(?:\.\d+)?)\b/g;
  let last = 0;
  let match: RegExpExecArray | null;
  let key = 0;
  while ((match = pattern.exec(line)) !== null) {
    if (match.index > last) nodes.push(line.slice(last, match.index));
    if (match[1]) {
      nodes.push(
        <span
          className={match[2] ? "tok-fn" : "tok-str"}
          key={key++}
        >
          {match[1]}
        </span>,
      );
      if (match[2]) nodes.push(match[2]);
    } else if (match[3]) {
      nodes.push(
        <span className="tok-kw" key={key++}>
          {match[3]}
        </span>,
      );
    } else if (match[4]) {
      nodes.push(
        <span className="tok-num" key={key++}>
          {match[4]}
        </span>,
      );
    }
    last = match.index + match[0].length;
  }
  if (last < line.length) nodes.push(line.slice(last));
  return nodes;
}

export function CodeBlock({
  code,
  language = "python",
  filename,
  markLines = [],
  maxHeight,
  startLine = 1,
  className,
  showLineNumbers = true,
  actions,
}: {
  code: string;
  language?: "python" | "json";
  filename?: string;
  markLines?: number[];
  maxHeight?: number;
  startLine?: number;
  className?: string;
  showLineNumbers?: boolean;
  actions?: ReactNode;
}) {
  const lines = code.replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");
  const marks = new Set(markLines);

  return (
    <div className={cn("code-shell", className)}>
      {filename && (
        <div className="code-head">
          <div className="code-head__file">
            <span className="code-head__dot" />
            <span className="mono">{filename}</span>
          </div>
          <div className="row gap-8">
            {actions}
            <CopyButton value={code} label="Copy" />
          </div>
        </div>
      )}
      <pre className="code" style={maxHeight ? { maxHeight } : undefined}>
        <code>
          {lines.map((line, index) => {
            const lineNumber = startLine + index;
            return (
              <div
                className={cn(
                  "code__line",
                  marks.has(lineNumber) && "code__line--marked",
                )}
                key={index}
              >
                {showLineNumbers && (
                  <span className="code__num">{lineNumber}</span>
                )}
                <span className="code__text">
                  {language === "json"
                    ? highlightJson(line)
                    : highlightPython(line)}
                </span>
              </div>
            );
          })}
        </code>
      </pre>
    </div>
  );
}

export function DiffView({
  diff,
  filename,
  maxHeight = 380,
}: {
  diff: string;
  filename?: string;
  maxHeight?: number;
}) {
  const id = useId().replace(/:/g, "");
  const lines = diff.replace(/\r\n/g, "\n").split("\n");
  const added = lines.filter(
    (line) => line.startsWith("+") && !line.startsWith("+++"),
  ).length;
  const removed = lines.filter(
    (line) => line.startsWith("-") && !line.startsWith("---"),
  ).length;
  const hasBody = lines.some((line) => line.startsWith("@@"));
  const file =
    filename ??
    lines
      .find((line) => line.startsWith("+++"))
      ?.replace("+++ b/", "") ??
    "patch";

  return (
    <div className="diff" key={id}>
      <div className="diff__file">
        <span className="diff__path">{file}</span>
        <span className="diff__stat diff__stat--add">+{added}</span>
        <span className="diff__stat diff__stat--del">−{removed}</span>
      </div>
      <div className="diff__body" style={{ maxHeight }}>
        {!hasBody ? (
          <div className="diff__line diff__line--meta">
            No textual changes · patch equals the current source.
          </div>
        ) : (
          lines.map((line, index) => {
            if (line.startsWith("---") || line.startsWith("+++")) return null;
            const type = line.startsWith("@@")
              ? "hunk"
              : line.startsWith("+")
                ? "add"
                : line.startsWith("-")
                  ? "del"
                  : line.startsWith("\\")
                    ? "meta"
                    : "context";
            return (
              <div
                className={cn(
                  "diff__line",
                  type === "add" && "diff__line--add",
                  type === "del" && "diff__line--del",
                  type === "hunk" && "diff__line--hunk",
                  type === "meta" && "diff__line--meta",
                )}
                key={index}
              >
                {line || " "}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
