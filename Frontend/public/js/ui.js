const STATUS_CLASSES = {
    ONLINE: "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
    OFFLINE: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
};

const EVENT_TYPE_CLASSES = {
    MODIFIED: "text-yellow-600 dark:text-yellow-400",
    DELETED: "text-red-600 dark:text-red-400",
};

const ACTION_CLASSES = {
    BLOCKED: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
    DETECTED: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
};

const SEVERITY_CLASSES = {
    Critical: "bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300 ring-1 ring-rose-200 dark:ring-rose-800",
    High: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300 ring-1 ring-amber-200 dark:ring-amber-800",
    Medium: "bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300 ring-1 ring-sky-200 dark:ring-sky-800",
};

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function formatReportBody(text) {
    const lines = text.split("\n");
    let html = "";
    let i = 0;

    const labelRe = /^\[(.+)\]$/;
    const numRe = /^(\d+)\.\s+(.+)$/;
    const bulletRe = /^•\s+(.+)$/;
    const accentRe = /^■\s+(.+)$/;
    const codePrefixRe = /^\[([^\]]+)\]\s*(.*)$/;

    function isBlockStart(s) {
        return labelRe.test(s) || numRe.test(s) || bulletRe.test(s) || accentRe.test(s);
    }

    while (i < lines.length) {
        const raw = lines[i];
        const t = raw.trim();

        if (t === "") { i++; continue; }

        // [label] subheading on its own line
        const lm = t.match(labelRe);
        if (lm) {
            html += `<div class="mt-4 mb-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-gray-500 dark:text-gray-400">${escapeHtml(lm[1])}</div>`;
            i++;
            continue;
        }

        // ■ heading (with optional indented description)
        const am = t.match(accentRe);
        if (am) {
            const heading = am[1];
            i++;
            const descLines = [];
            while (i < lines.length && /^\s{2,}\S/.test(lines[i])) {
                descLines.push(lines[i].trim());
                i++;
            }
            const desc = descLines.join(" ");
            const codeMatch = heading.match(codePrefixRe);
            if (codeMatch) {
                html += `<div class="mb-3 pl-3 border-l-2 border-blue-500/60 dark:border-blue-400/50 report-divider">
                    <div class="flex items-baseline gap-2 flex-wrap mb-1">
                        <span class="report-code text-[11px] font-mono font-semibold text-blue-700 dark:text-blue-300">${escapeHtml(codeMatch[1])}</span>
                        <span class="text-[13px] font-semibold text-gray-900 dark:text-gray-100">${escapeHtml(codeMatch[2])}</span>
                    </div>
                    ${desc ? `<p class="text-[13px] text-gray-600 dark:text-gray-400 leading-relaxed">${escapeHtml(desc)}</p>` : ""}
                </div>`;
            } else {
                html += `<div class="mb-3 pl-3 border-l-2 border-gray-300 dark:border-gray-600 report-divider">
                    <div class="text-[13px] font-semibold text-gray-900 dark:text-gray-100 mb-1">${escapeHtml(heading)}</div>
                    ${desc ? `<p class="text-[13px] text-gray-600 dark:text-gray-400 leading-relaxed">${escapeHtml(desc)}</p>` : ""}
                </div>`;
            }
            continue;
        }

        // Bullet list (collect consecutive bullets)
        if (bulletRe.test(t)) {
            const items = [];
            while (i < lines.length) {
                const ln = lines[i].trim();
                if (ln === "") { i++; continue; }
                const m = ln.match(bulletRe);
                if (!m) break;
                items.push(m[1]);
                i++;
            }
            html += `<ul class="list-disc list-outside pl-5 space-y-1 mb-3 text-[13px] text-gray-700 dark:text-gray-300 marker:text-gray-400 dark:marker:text-gray-500">`;
            for (const it of items) html += `<li class="leading-relaxed">${escapeHtml(it)}</li>`;
            html += `</ul>`;
            continue;
        }

        // Numbered list (allow blank lines and multi-line continuation)
        if (numRe.test(t)) {
            const items = [];
            while (i < lines.length) {
                const ln = lines[i].trim();
                if (ln === "") { i++; continue; }
                const m = ln.match(numRe);
                if (!m) break;
                let body = m[2];
                i++;
                while (i < lines.length) {
                    const next = lines[i].trim();
                    if (next === "" || isBlockStart(next)) break;
                    body += " " + next;
                    i++;
                }
                items.push({ n: m[1], body });
            }
            html += `<ol class="space-y-2.5 mb-3">`;
            for (const it of items) {
                html += `<li class="flex gap-3 text-[13px] text-gray-700 dark:text-gray-300 leading-relaxed">
                    <span class="flex-shrink-0 inline-flex items-center justify-center w-5 h-5 rounded text-[11px] font-semibold text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-900/30 tabular-nums report-num">${it.n}</span>
                    <span class="flex-1">${escapeHtml(it.body)}</span>
                </li>`;
            }
            html += `</ol>`;
            continue;
        }

        // Plain paragraph (collect until blank or block-start)
        const paraLines = [];
        while (i < lines.length) {
            const ln = lines[i].trim();
            if (ln === "" || isBlockStart(ln)) break;
            paraLines.push(ln);
            i++;
        }
        if (paraLines.length > 0) {
            html += `<p class="text-[13px] leading-relaxed text-gray-700 dark:text-gray-300 mb-3">${escapeHtml(paraLines.join(" "))}</p>`;
        }
    }

    return html;
}

const REPORT_BTN_CLASSES = {
    generate: "text-xs px-3 py-1 rounded-md font-medium bg-gray-100 text-gray-900 hover:bg-gray-200 dark:bg-gray-700 dark:text-gray-100 dark:hover:bg-gray-600",
    view: "text-xs px-3 py-1 rounded-md font-medium bg-green-100 text-green-700 hover:bg-green-200 dark:bg-green-900/30 dark:text-green-400 dark:hover:bg-green-900/50",
    loading: "text-xs px-3 py-1 rounded-md font-medium bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400 cursor-not-allowed",
};

const Dropdown = {
    init(el, options, placeholder, onChange) {
        const btn = el.querySelector("button");
        const menu = el.querySelector(".dropdown-menu");

        this.setOptions(el, options, placeholder);

        btn.addEventListener("click", (e) => {
            e.stopPropagation();
            document.querySelectorAll(".dropdown-menu").forEach(m => {
                if (m !== menu) m.classList.add("hidden");
            });
            menu.classList.toggle("hidden");
        });

        menu.addEventListener("click", (e) => {
            const item = e.target.closest("[data-option-value]");
            if (!item) return;
            const value = item.dataset.optionValue;
            const text = item.textContent;
            const label = el.querySelector(".dropdown-label");
            el.dataset.value = value;
            label.textContent = text;
            label.className = value
                ? "dropdown-label text-gray-900 dark:text-white"
                : "dropdown-label text-gray-500 dark:text-gray-400";
            menu.classList.add("hidden");
            if (onChange) onChange(value);
        });
    },

    setOptions(el, options, placeholder) {
        const menu = el.querySelector(".dropdown-menu");
        const label = el.querySelector(".dropdown-label");

        menu.innerHTML = `<li data-option-value="" class="px-3 py-2 text-sm text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-600 cursor-pointer">${placeholder}</li>`
            + options.map(o => `<li data-option-value="${o.value}" class="px-3 py-2 text-sm text-gray-900 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-600 cursor-pointer">${o.label}</li>`).join("");

        el.dataset.value = "";
        label.textContent = placeholder;
        label.className = "dropdown-label text-gray-500 dark:text-gray-400";
    },

    getValue(el) {
        return el.dataset.value;
    },
};

document.addEventListener("click", () => {
    document.querySelectorAll(".dropdown-menu").forEach(m => m.classList.add("hidden"));
});

const UI = {
    renderAgents(agents) {
        const tbody = document.getElementById("agents-tbody");

        tbody.innerHTML = agents.map(a => `
            <tr class="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50">
                <td class="px-6 py-3 font-medium">${a.id}</td>
                <td class="px-6 py-3">${a.hostname}</td>
                <td class="px-6 py-3">${a.ip}</td>
                <td class="px-6 py-3">
                    <span class="px-2 py-1 rounded-full text-xs font-medium ${STATUS_CLASSES[a.status] || ""}">${a.status}</span>
                </td>
            </tr>
        `).join("");

        const agentOptions = agents.map(a => ({ value: a.id, label: a.hostname }));

        Dropdown.init(document.getElementById("filter-agent"), agentOptions, "All Agents", () => App.resetAndRender());
        Dropdown.init(document.getElementById("filter-type"), [
            { value: "MODIFIED", label: "MODIFIED" },
            { value: "DELETED", label: "DELETED" },
        ], "All Types", () => App.resetAndRender());
    },

    renderEvents(events, page, perPage) {
        const tbody = document.getElementById("events-tbody");
        const start = (page - 1) * perPage;
        const paged = events.slice(start, start + perPage);

        tbody.innerHTML = paged.map(e => {
            const hasReport = Api.hasReport(e.id);
            const btnClass = hasReport ? REPORT_BTN_CLASSES.view : REPORT_BTN_CLASSES.generate;
            const btnLabel = hasReport ? "보고서 열람" : "보고서 생성";
            const btnAction = hasReport ? "view-report" : "generate-report";
            return `
            <tr class="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50">
                <td class="px-6 py-3">${e.time}</td>
                <td class="px-6 py-3">${e.agent}</td>
                <td class="px-6 py-3 ${EVENT_TYPE_CLASSES[e.type] || ""}">${e.event}</td>
                <td class="px-6 py-3"><span class="px-2 py-1 rounded-full text-xs font-medium ${ACTION_CLASSES[e.action] || ""}">${e.action}</span></td>
                <td class="px-6 py-3"><button class="${btnClass}" data-action="${btnAction}" data-event-id="${e.id}">${btnLabel}</button></td>
            </tr>
        `;
        }).join("");

        const totalPages = Math.ceil(events.length / perPage) || 1;
        document.getElementById("page-info").textContent = `Page ${page} of ${totalPages} (${events.length} events)`;

        const pagination = document.getElementById("pagination");
        pagination.innerHTML = "";

        for (let i = 1; i <= totalPages; i++) {
            const btn = document.createElement("button");
            btn.textContent = i;
            btn.className = i === page
                ? "px-3 py-1 rounded-md text-sm font-medium bg-blue-600 text-white"
                : "px-3 py-1 rounded-md text-sm font-medium text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700";
            btn.addEventListener("click", () => App.goToPage(i));
            pagination.appendChild(btn);
        }
    },

    setReportButtonLoading(eventId) {
        const btn = document.querySelector(`button[data-event-id="${eventId}"]`);
        if (!btn) return;
        btn.className = REPORT_BTN_CLASSES.loading;
        btn.disabled = true;
        btn.textContent = "생성 중...";
        btn.removeAttribute("data-action");
    },

    openReportModal(eventId) {
        const event = Api.getEvents().find(e => e.id === eventId);
        const report = Api.getReport(eventId);
        if (!event || !report) return;

        document.getElementById("report-modal-path").textContent = event.path;
        document.getElementById("report-modal-host").textContent = event.agent;
        document.getElementById("report-modal-time").textContent = event.time;
        document.getElementById("report-modal-generated").textContent = report.generatedAt;

        const sev = document.getElementById("report-modal-severity");
        sev.textContent = report.severity;
        sev.className = `px-3 py-1 rounded-full text-xs font-semibold ${SEVERITY_CLASSES[report.severity] || ""}`;

        document.getElementById("report-modal-body").innerHTML = report.sections.map(s => {
            const m = s.title.match(/^(\d+)\.\s*(.*)$/);
            const num = m ? m[1].padStart(2, "0") : "";
            const title = m ? m[2] : s.title;
            return `
                <section>
                    <header class="flex items-center gap-3 mb-3 pb-2 border-b border-gray-200 dark:border-gray-700 report-divider">
                        <span class="report-num inline-flex items-center justify-center w-7 h-7 rounded-md text-[11px] font-bold tabular-nums text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-900/30">${num}</span>
                        <h4 class="text-[15px] font-semibold text-gray-900 dark:text-white">${escapeHtml(title)}</h4>
                    </header>
                    <div class="pl-10">${formatReportBody(s.body)}</div>
                </section>
            `;
        }).join("");

        document.getElementById("report-modal").classList.remove("hidden");
    },

    closeReportModal() {
        document.getElementById("report-modal").classList.add("hidden");
    },
};
