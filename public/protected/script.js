let memoryDoughnut;
let loadBar;
let tempMaxes = {};
let maxVoltages  = {};        
let maxFanInputs = {};        

async function startChart() {
    try {
        const response = await fetch('/api/chartInformation');
        const chartInformation = await response.json();

        const loadResponse = await fetch('/api/loadAvg');
        const loadAvg = await loadResponse.json();

        const doughnutData = {
            labels: ["Free Memory", "Used Memory"],
            datasets: [{
                label: 'GB',
                data: [chartInformation[0], chartInformation[1]],
                backgroundColor: ['#4caf50', '#c41e3a'],
                borderWidth: 0,
                hoverOffset: 4
            }]
        };

        const loadData = {
            labels: ["1 Min", "5 Min", "15 Min"],
            datasets: [{
                label: 'Processes',
                data: [loadAvg[0], loadAvg[1], loadAvg[2]],
                backgroundColor: ["#ff1744","#ff4569","#ff8095"],
                borderWidth: 0,
                hoverOffset: 4
            }]
        };

        const sharedOptions = {
            plugins: {
                legend: {
                    labels: {
                        color: '#e0e0e0'
                    }
                },
                title: {
                    color: '#e0e0e0',
                    display: true,
                    font: {
                        size: 16,
                        weight: 500
                    }
                }
            }
        };

        const doughnutConfig = {
            type: 'doughnut',
            data: doughnutData,
            options: {
                ...sharedOptions,
                plugins: {
                    ...sharedOptions.plugins,
                    title: {
                        ...sharedOptions.plugins.title,
                        text: "Memory Usage"
                    }
                }
            }
        };

        const loadConfig = {
            type: "bar",
            data: loadData,
            options: {
                ...sharedOptions,
                plugins: {
                    ...sharedOptions.plugins,
                    title: {
                        ...sharedOptions.plugins.title,
                        text: "Load Average"
                    }
                },
                scales: {
                    y: {
                        ticks: { color: '#e0e0e0' },
                        grid: { color: '#333333' }
                    },
                    x: {
                        ticks: { color: '#e0e0e0' },
                        grid: { color: '#333333' }
                    }
                }
            }
        };

        const memctx = document.getElementById("memoryDoughnut").getContext('2d');
        memoryDoughnut = new Chart(memctx, doughnutConfig);

        const loadctx = document.getElementById("loadBar").getContext("2d");
        loadBar = new Chart(loadctx, loadConfig);
    } catch (error) {
        console.error(`Error starting chart: ${error.message}`);
    }
}

async function updateValues() {
    try {
        const chartResponse = await fetch('/api/chartInformation');
        const chartInformation = await chartResponse.json();

        memoryDoughnut.data.datasets[0].data = [chartInformation[0], chartInformation[1]];
        memoryDoughnut.update();

        const loadResponse = await fetch('/api/loadAvg');
        const loadAvg = await loadResponse.json();

        loadBar.data.datasets[0].data = [loadAvg[0], loadAvg[1], loadAvg[2]];
        loadBar.update();

        const [tempResponse, motherboardResponse] = await Promise.all([
            fetch('/api/temperatures'),
            fetch('/api/motherboard')
        ]);

        const temperatures = await tempResponse.json();
        const motherboard = await motherboardResponse.json();

        const tableBody = document.getElementById('readingsBody');
        tableBody.innerHTML = '';

        const combinedReadings = [
            ...temperatures.filter(reading => reading.LABEL.includes('_input') || reading.LABEL.includes('_label')),
            ...motherboard.filter(reading => reading.LABEL.includes('_input') || reading.LABEL.includes('_target'))
        ];

        const tempRegex = /temp\d+_input/;
        const voltRegex = /in\d+_input/;

        combinedReadings.forEach(reading => {
            const row = document.createElement('tr');
            if (reading.LABEL.includes("fan")) {
                    if (!maxFanInputs[reading.LABEL] || reading.VALUE > maxFanInputs[reading.LABEL]) {
                        maxFanInputs[reading.LABEL] = reading.VALUE;
                    }
                    row.innerHTML = `
                    <td>${reading.LABEL}</td>
                    <td>${reading.VALUE} RPM</td>
                    <td>${maxFanInputs[reading.LABEL]} RPM</td>
                `;
            } else if (voltRegex.test(reading.LABEL)) {
                if (!maxVoltages[reading.LABEL] || reading.VALUE > maxVoltages[reading.LABEL]) {
                        maxVoltages[reading.LABEL] = reading.VALUE;
                    }
                    row.innerHTML = `
                    <td>${reading.LABEL}</td>
                    <td>${reading.VALUE} V</td>
                    <td>${maxVoltages[reading.LABEL]} V</td>
                `;
            } else if (tempRegex.test(reading.LABEL)) {
                if (!tempMaxes[reading.LABEL] || reading.VALUE > tempMaxes[reading.LABEL]) {
                        tempMaxes[reading.LABEL] = reading.VALUE;
                    }
                    row.innerHTML = `
                    <td>${reading.LABEL}</td>
                    <td>${reading.VALUE} °C</td>
                    <td>${tempMaxes[reading.LABEL]} °C</td>
                `;
            } else {
                row.innerHTML = `
                <td>${reading.LABEL}</td>
                <td>${reading.VALUE}</td>
                `;
            }
            tableBody.appendChild(row);
        });

        const uptimeResponse = await fetch('/api/uptime');
        const uptime = await uptimeResponse.json();

        const uptimeHolder = document.getElementById('uptimeHolder');
        uptimeHolder.innerHTML = `${uptime[0]}:${uptime[1]}:${uptime[2]}:${uptime[3]}`;

    } catch (error) {
        console.error(`Error updating values: ${error.message}`);
    }
}
startChart();
updateValues();
setInterval(updateValues, 3000);