const MOCK_AGENTS = [
    { id: "PC_1", hostname: "PC_1", ip: "192.168.0.21", status: "ONLINE" },
    { id: "PC_2", hostname: "PC_2", ip: "192.168.0.22", status: "OFFLINE" },
    { id: "PC_3", hostname: "PC_3", ip: "192.168.0.23", status: "ONLINE" },
];

const MOCK_EVENTS = [
    { time: "2026-03-24 14:21:02", agent: "PC_1", event: "Integrity Check OK", type: "OK", path: "" },
    { time: "2026-03-24 14:23:10", agent: "PC_1", event: "/etc/myapp/config.yaml MODIFIED", type: "MODIFIED", path: "/etc/myapp/config.yaml" },
    { time: "2026-03-24 14:25:03", agent: "PC_1", event: "/usr/local/bin/my.service MODIFIED", type: "MODIFIED", path: "/usr/local/bin/my.service" },
    { time: "2026-03-24 14:26:11", agent: "PC_1", event: "/var/log/myapp.log DELETED", type: "DELETED", path: "/var/log/myapp.log" },
    { time: "2026-03-24 14:30:00", agent: "PC_3", event: "Integrity Check OK", type: "OK", path: "" },
    { time: "2026-03-24 14:32:45", agent: "PC_3", event: "/etc/nginx/nginx.conf MODIFIED", type: "MODIFIED", path: "/etc/nginx/nginx.conf" },
    { time: "2026-03-24 14:35:22", agent: "PC_1", event: "/opt/app/bin/worker MODIFIED", type: "MODIFIED", path: "/opt/app/bin/worker" },
    { time: "2026-03-24 14:38:07", agent: "PC_3", event: "/var/log/syslog DELETED", type: "DELETED", path: "/var/log/syslog" },
    { time: "2026-03-24 14:40:55", agent: "PC_1", event: "/etc/crontab MODIFIED", type: "MODIFIED", path: "/etc/crontab" },
    { time: "2026-03-24 14:42:30", agent: "PC_3", event: "/usr/lib/libcrypto.so MODIFIED", type: "MODIFIED", path: "/usr/lib/libcrypto.so" },
    { time: "2026-03-24 14:45:18", agent: "PC_1", event: "Integrity Check OK", type: "OK", path: "" },
    { time: "2026-03-24 14:47:01", agent: "PC_3", event: "/etc/passwd MODIFIED", type: "MODIFIED", path: "/etc/passwd" },
    { time: "2026-03-24 14:50:33", agent: "PC_1", event: "/tmp/.hidden_script.sh DELETED", type: "DELETED", path: "/tmp/.hidden_script.sh" },
    { time: "2026-03-24 14:52:10", agent: "PC_3", event: "Integrity Check OK", type: "OK", path: "" },
    { time: "2026-03-24 14:55:44", agent: "PC_1", event: "/etc/ssh/sshd_config MODIFIED", type: "MODIFIED", path: "/etc/ssh/sshd_config" },
    { time: "2026-03-24 14:58:20", agent: "PC_3", event: "/var/www/html/index.html MODIFIED", type: "MODIFIED", path: "/var/www/html/index.html" },
    { time: "2026-03-24 15:01:05", agent: "PC_1", event: "/etc/shadow MODIFIED", type: "MODIFIED", path: "/etc/shadow" },
    { time: "2026-03-24 15:03:41", agent: "PC_3", event: "/opt/app/config/db.env DELETED", type: "DELETED", path: "/opt/app/config/db.env" },
    { time: "2026-03-24 15:06:15", agent: "PC_1", event: "/usr/bin/sudo MODIFIED", type: "MODIFIED", path: "/usr/bin/sudo" },
    { time: "2026-03-24 15:08:50", agent: "PC_3", event: "/etc/resolv.conf MODIFIED", type: "MODIFIED", path: "/etc/resolv.conf" },
];

const Api = {
    getAgents() {
        return MOCK_AGENTS;
    },

    getEvents() {
        return MOCK_EVENTS;
    },
};
