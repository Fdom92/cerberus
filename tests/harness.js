const tests = [];

export function test(name, fn) {
  tests.push({ name, fn });
}

export function assert(cond, message) {
  if (!cond) throw new Error(message || "assertion failed");
}

export function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message || "not equal"}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

export async function runAll(renderEl) {
  const results = [];
  for (const { name, fn } of tests) {
    try {
      await fn();
      results.push({ name, pass: true });
    } catch (err) {
      results.push({ name, pass: false, error: err.message || String(err) });
    }
  }

  const passCount = results.filter((r) => r.pass).length;
  const failCount = results.length - passCount;

  if (renderEl) {
    renderEl.innerHTML = `
      <p><strong>${passCount} pasaron, ${failCount} fallaron</strong> (${results.length} total)</p>
      <ul>
        ${results
          .map(
            (r) =>
              `<li style="color:${r.pass ? "#34d399" : "#f87171"}">${r.pass ? "✓" : "✗"} ${escapeHtml(r.name)}${
                r.error ? ` — ${escapeHtml(r.error)}` : ""
              }</li>`
          )
          .join("")}
      </ul>
    `;
  }

  console.log(`${passCount}/${results.length} tests passed`);
  for (const r of results.filter((r) => !r.pass)) console.error(`FAIL: ${r.name} — ${r.error}`);

  return { passCount, failCount, results };
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}
