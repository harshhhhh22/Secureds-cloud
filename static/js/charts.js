
document.addEventListener("DOMContentLoaded", () => {
    // Chart.js must be loaded in dashboard.html first.
    if (typeof Chart === "undefined") {
        console.warn("Chart.js is not loaded.");
        return;
    }

    const trendCanvas = document.getElementById("scanTrendChart");
    const severityCanvas = document.getElementById("severityChart");

    // Scan history graph
    if (trendCanvas) {
        const labels = JSON.parse(
            trendCanvas.dataset.labels || "[]"
        );
        const values = JSON.parse(
            trendCanvas.dataset.values || "[]"
        );

        new Chart(trendCanvas, {
            type: "line",
            data: {
                labels,
                datasets: [{
                    label: "Scans",
                    data: values,
                    borderColor: "#2563eb",
                    backgroundColor: "rgba(37, 99, 235, 0.12)",
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0 }
                    }
                }
            }
        });
    }

    // Findings by severity
    if (severityCanvas) {
        const values = JSON.parse(
            severityCanvas.dataset.values || "{}"
        );

        new Chart(severityCanvas, {
            type: "doughnut",
            data: {
                labels: ["Critical", "High", "Medium", "Low", "Other"],
                datasets: [{
                    data: [
                        values.critical || 0,
                        values.high || 0,
                        values.medium || 0,
                        values.low || 0,
                        values.other || 0
                    ],
                    backgroundColor: [
                        "#991b1b",
                        "#dc2626",
                        "#f59e0b",
                        "#16a34a",
                        "#64748b"
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
    }
});
