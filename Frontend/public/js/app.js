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

    init() {
        Theme.init();

        const agents = Api.getAgents();
        UI.renderAgents(agents);
        this.renderFilteredEvents();

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
