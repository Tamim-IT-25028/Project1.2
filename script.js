// Helper function to print messages into the Terminal Box
function printLog(message, type = "info") {
    const terminal = document.getElementById("logTerminal");
    const entry = document.createElement("div");
    
    // Set text color depending on message type
    if (type === "success") {
        entry.className = "log-success";
    } else if (type === "error") {
        entry.className = "log-error";
    } else {
        entry.className = "log-info";
    }

    const time = new Date().toLocaleTimeString();
    entry.innerText = "[" + time + "] " + message;
    
    terminal.appendChild(entry);
    terminal.scrollTop = terminal.scrollHeight; // Auto-scroll to bottom
}

// Main function called when clicking "Start Scan"
async function startScan() {
    // 1. Get user input values from the HTML inputs
    const ip = document.getElementById("targetIp").value;
    const startPort = document.getElementById("startPort").value;
    const endPort = document.getElementById("endPort").value;
    const threads = document.getElementById("threadCount").value;

    const button = document.getElementById("scanBtn");
    const tableBody = document.getElementById("resultsBody");

    // 2. Simple check to make sure IP isn't empty
    if (!ip) {
        alert("Please enter a Target IP address!");
        return;
    }

    // Disable button while scanning
    button.disabled = true;
    button.innerText = "⏳ Scanning...";
    tableBody.innerHTML = ""; // Clear old results

    printLog("Starting port scan on " + ip + " (Ports " + startPort + "-" + endPort + ")...");

    // 3. Request data from your C++ backend server running on port 8080
    try {
        const apiUrl = "http://localhost:8080/scan?ip=" + ip + 
                       "&startPort=" + startPort + 
                       "&endPort=" + endPort + 
                       "&threads=" + threads;

        const response = await fetch(apiUrl);
        const results = await response.json(); // Convert C++ response to JS array

        // 4. Render results in the table
        if (results.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="5" class="empty-msg">Scan finished. No open ports found.</td></tr>';
            printLog("Scan finished. No open ports found.");
        } else {
            results.forEach(function(item) {
                // Determine risk badge style
                let badgeStyle = "badge-low";
                if (item.risk === "High" || item.risk === "Critical") {
                    badgeStyle = "badge-high";
                } else if (item.risk === "Medium") {
                    badgeStyle = "badge-medium";
                }

                // Add row to table
                const row = document.createElement("tr");
                row.innerHTML = 
                    "<td><strong>" + item.port + "</strong></td>" +
                    "<td>TCP</td>" +
                    "<td>" + item.service + "</td>" +
                    "<td><code>" + (item.banner || "N/A") + "</code></td>" +
                    "<td><span class='badge " + badgeStyle + "'>" + item.risk + "</span></td>";

                tableBody.appendChild(row);
                printLog("Found Open Port: " + item.port + " (" + item.service + ")", "success");
            });
            printLog("Scan complete! Found " + results.length + " open port(s).", "success");
        }

    } catch (error) {
        // Handle server failure (e.g. if C++ main.cpp is not running)
        printLog("Error: Unable to connect to C++ server on http://localhost:8080", "error");
        tableBody.innerHTML = '<tr><td colspan="5" class="empty-msg" style="color: red;">Failed to reach C++ backend server.</td></tr>';
        alert("Could not reach C++ backend server! Make sure main.cpp is running.");
    } finally {
        // Re-enable button when finished
        button.disabled = false;
        button.innerText = "▶ Start Scan";
    }
}