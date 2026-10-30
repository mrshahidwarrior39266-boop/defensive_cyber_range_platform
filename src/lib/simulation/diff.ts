/* Minimal unified-diff generator used by the patch ledger. */

type Op = { type: "eq" | "del" | "add"; text: string };

function operations(before: string[], after: string[]): Op[] {
  const n = before.length;
  const m = after.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () =>
    new Array<number>(m + 1).fill(0),
  );

  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] =
        before[i] === after[j]
          ? lcs[i + 1][j + 1] + 1
          : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }

  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (before[i] === after[j]) {
      ops.push({ type: "eq", text: before[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      ops.push({ type: "del", text: before[i] });
      i++;
    } else {
      ops.push({ type: "add", text: after[j] });
      j++;
    }
  }
  while (i < n) ops.push({ type: "del", text: before[i++] });
  while (j < m) ops.push({ type: "add", text: after[j++] });
  return ops;
}

export function createUnifiedDiff(
  filePath: string,
  beforeText: string,
  afterText: string,
  context = 3,
): string {
  if (beforeText === afterText) return "";
  const before = beforeText.replace(/\r\n/g, "\n").split("\n");
  const after = afterText.replace(/\r\n/g, "\n").split("\n");
  const ops = operations(before, after);

  const changeIndexes: number[] = [];
  ops.forEach((op, idx) => {
    if (op.type !== "eq") changeIndexes.push(idx);
  });
  if (!changeIndexes.length) return "";

  const groups: Array<{ start: number; end: number }> = [];
  let start = changeIndexes[0];
  let last = changeIndexes[0];
  for (const idx of changeIndexes.slice(1)) {
    if (idx - last > context * 2 + 1) {
      groups.push({ start, end: last });
      start = idx;
    }
    last = idx;
  }
  groups.push({ start, end: last });

  const lines: string[] = [`--- a/${filePath}`, `+++ b/${filePath}`];

  for (const group of groups) {
    const from = Math.max(0, group.start - context);
    const to = Math.min(ops.length - 1, group.end + context);
    const slice = ops.slice(from, to + 1);

    let oldLine = 1;
    let newLine = 1;
    for (let i = 0; i < from; i++) {
      if (ops[i].type !== "add") oldLine++;
      if (ops[i].type !== "del") newLine++;
    }

    const oldCount = slice.filter((op) => op.type !== "add").length;
    const newCount = slice.filter((op) => op.type !== "del").length;
    lines.push(
      `@@ -${oldLine},${oldCount} +${newLine},${newCount} @@`,
    );
    for (const op of slice) {
      if (op.type === "eq") lines.push(` ${op.text}`);
      else if (op.type === "del") lines.push(`-${op.text}`);
      else lines.push(`+${op.text}`);
    }
  }

  return lines.join("\n") + "\n";
}
