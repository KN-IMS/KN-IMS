const Theme = {
    init() {
        const saved = localStorage.getItem("theme");
        if (saved === "dark" || (!saved && window.matchMedia("(prefers-color-scheme: dark)").matches)) {
            document.documentElement.classList.add("dark");
        }
        this.updateIcon();

        document.getElementById("theme-toggle").addEventListener("click", () => this.toggle());
    },

    toggle() {
        document.documentElement.classList.toggle("dark");
        const isDark = document.documentElement.classList.contains("dark");
        localStorage.setItem("theme", isDark ? "dark" : "light");
        this.updateIcon();
    },

    updateIcon() {
        const isDark = document.documentElement.classList.contains("dark");
        document.getElementById("icon-sun").classList.toggle("hidden", !isDark);
        document.getElementById("icon-moon").classList.toggle("hidden", isDark);
    },
};

const App = {
    currentPage: 1,
    perPage: 10,
    refreshIntervalMs: 5000,

    async init() {
        Theme.init();

        await this.refreshAndRender();
        // 주기적으로 Mirror Server 데이터 동기화
        setInterval(() => this.refreshAndRender().catch(err => console.error("refresh failed", err)), this.refreshIntervalMs);

        document.getElementById("search-path").addEventListener("input", () => this.resetAndRender());

        document.getElementById("events-tbody").addEventListener("click", (e) => this.handleReportButton(e));

        document.getElementById("report-modal-close").addEventListener("click", () => UI.closeReportModal());
        document.getElementById("report-modal").addEventListener("click", (e) => {
            if (e.target.id === "report-modal") UI.closeReportModal();
        });
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape") UI.closeReportModal();
        });

        document.getElementById("report-print").addEventListener("click", () => window.print());
    },

    async refreshAndRender() {
        try {
            await Api.refresh();
            this.setConnectionStatus(true);
        } catch (err) {
            console.error("Api.refresh failed:", err);
            this.setConnectionStatus(false);
        }
        UI.renderAgents(Api.getAgents());
        this.renderFilteredEvents();
    },

    setConnectionStatus(ok) {
        const dot = document.getElementById("connection-dot");
        const label = document.getElementById("connection-label");
        if (!dot || !label) return;
        // 빌드된 tailwind.css에 없는 클래스(bg-green-500 등)를 피해 inline style 사용
        if (ok) {
            dot.style.backgroundColor = "#22c55e"; // green-500
            dot.style.boxShadow = "0 0 8px rgba(34,197,94,0.9)";
        } else {
            dot.style.backgroundColor = "#ef4444"; // red-500
            dot.style.boxShadow = "0 0 8px rgba(239,68,68,0.9)";
        }
        label.textContent = ok ? "Connected" : "Disconnected";
    },

    async handleReportButton(e) {
        const btn = e.target.closest("button[data-action]");
        if (!btn) return;
        const eventId = btn.dataset.eventId;
        const action = btn.dataset.action;

        if (action === "view-report") {
            UI.openReportModal(eventId);
            return;
        }

        if (action === "generate-report") {
            UI.setReportButtonLoading(eventId);
            await Api.generateReport(eventId);
            this.renderFilteredEvents();
            UI.openReportModal(eventId);
        }
    },

    getFilteredEvents() {
        const agentFilter = Dropdown.getValue(document.getElementById("filter-agent"));
        const typeFilter = Dropdown.getValue(document.getElementById("filter-type"));
        const searchQuery = document.getElementById("search-path").value.toLowerCase();

        return Api.getEvents().filter(e => {
            if (agentFilter && e.agent !== agentFilter) return false;
            if (typeFilter && e.type !== typeFilter) return false;
            if (searchQuery) {
                const haystack = `${e.time} ${e.agent} ${e.event} ${e.path}`.toLowerCase();
                if (!haystack.includes(searchQuery)) return false;
            }
            return true;
        });
    },

    renderFilteredEvents() {
        const filtered = this.getFilteredEvents();
        UI.renderEvents(filtered, this.currentPage, this.perPage);
    },

    resetAndRender() {
        this.currentPage = 1;
        this.renderFilteredEvents();
    },

    goToPage(page) {
        this.currentPage = page;
        this.renderFilteredEvents();
    },
};

document.addEventListener("DOMContentLoaded", () => App.init());
