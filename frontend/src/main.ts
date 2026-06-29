type JsonMap = Record<string, unknown>;

async function hydrateTopology(element: HTMLElement): Promise<void> {
  const src = element.dataset.src;
  if (!src) return;
  const data = (await fetch(src).then((r) => r.json())) as {
    nodes?: JsonMap[];
    edges?: JsonMap[];
  };
  const nodes = data.nodes ?? [];
  const width = 720;
  const height = Math.max(160, nodes.length * 70);
  const rows = nodes
    .map((node, index) => {
      const y = 40 + index * 62;
      const label = String(
        node.display_name ?? node.loop_id ?? node.id ?? "loop",
      );
      const status = String(node.status ?? "unknown");
      return `<g><rect x="20" y="${y - 24}" width="260" height="44" rx="10" fill="#182850" stroke="#7cd4ff"/><text x="36" y="${y}" fill="#eef3ff">${label} · ${status}</text></g>`;
    })
    .join("");
  element.innerHTML = `<svg role="img" aria-label="Loop topology" viewBox="0 0 ${width} ${height}">${rows}</svg>`;
}

async function hydrateTimeline(element: HTMLElement): Promise<void> {
  const src = element.dataset.src;
  if (!src) return;
  const data = (await fetch(src).then((r) => r.json())) as {
    timeline?: JsonMap[];
    events?: JsonMap[];
  };
  const items = data.timeline ?? data.events ?? [];
  element.innerHTML = `<ol class="timeline">${items
    .slice(0, 50)
    .map(
      (item) =>
        `<li><strong>${String(item.event_type ?? item.item_type ?? "event")}</strong> ${String(item.summary ?? "")}</li>`,
    )
    .join("")}</ol>`;
}

async function hydrateImpact(element: HTMLElement): Promise<void> {
  const src = element.dataset.src;
  if (!src) return;
  const report = (await fetch(src).then((r) => r.json())) as JsonMap;
  element.innerHTML = `<p class="${String(report.verdict ?? "")}">Deterministic verdict: <strong>${String(report.verdict ?? "inconclusive")}</strong></p>`;
}

for (const element of document.querySelectorAll<HTMLElement>(
  '[id$="-island"]',
)) {
  if (element.id.includes("topology")) void hydrateTopology(element);
  else if (element.id.includes("impact")) void hydrateImpact(element);
  else void hydrateTimeline(element);
}
