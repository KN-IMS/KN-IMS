const STATUS_CLASSES = {
    ONLINE: "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
    OFFLINE: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
};

const EVENT_TYPE_CLASSES = {
    OK: "text-green-600 dark:text-green-400",
    MODIFIED: "text-yellow-600 dark:text-yellow-400",
    DELETED: "text-red-600 dark:text-red-400",
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

        Dropdown.init(document.getElementById("agent-select"), agentOptions, "Select Agent");
        Dropdown.init(document.getElementById("filter-agent"), agentOptions, "All Agents", () => App.resetAndRender());
        Dropdown.init(document.getElementById("filter-type"), [
            { value: "MODIFIED", label: "MODIFIED" },
            { value: "DELETED", label: "DELETED" },
            { value: "OK", label: "OK" },
        ], "All Types", () => App.resetAndRender());
    },

    renderEvents(events, page, perPage) {
        const tbody = document.getElementById("events-tbody");
        const start = (page - 1) * perPage;
        const paged = events.slice(start, start + perPage);

        tbody.innerHTML = paged.map(e => `
            <tr class="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50">
                <td class="px-6 py-3">${e.time}</td>
                <td class="px-6 py-3">${e.agent}</td>
                <td class="px-6 py-3 ${EVENT_TYPE_CLASSES[e.type] || ""}">${e.event}</td>
            </tr>
        `).join("");

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
};
