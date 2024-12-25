const os = require("node:os");

function getCurrentMemory() {
    const freeMem = os.freemem();

    const freeMemInGb = bytesToGb(freeMem);

    return freeMemInGb;    
}

function getTotalMemory() {
    const totalMem = os.totalmem();

    const totalMemInGb = bytesToGb(totalMem);

    return totalMemInGb;
}

function getUptime() {
    const uptime = os.uptime();

    return uptime;
}

function bytesToGb(memInBytes) {
    const memInGb = memInBytes / 1e9; // Dividing the bytes by a billion

    return memInGb;
}

function splitUptime(uptime) {
    const days = Math.floor(uptime / 86400);
    uptime -= 86400 * days; // Subtracting time from time to calculate to account for whats already been calculated
    const hrs = Math.floor(uptime / 3600);
    uptime -= 3600 * hrs;
    const mins = Math.floor(uptime / 60);
    uptime -= 60 * mins;
    const seconds = Math.floor(uptime);
    const uptimeSplitArray = [days, hrs, mins, seconds]; // Days, Hrs, Mins, Seconds

    return uptimeSplitArray;
}

function getLoadAvg() {
    const loadAvg = os.loadavg();
    
    return loadAvg;
}

function convert(data) {
    const voltageRegex = /in\d+_\w+/
    const tempRegex = /temp\d+_input/
    data.forEach(value => {
        if (voltageRegex.test(value.LABEL)) { // If is millivolts converts to Volts
            value.VALUE = value.VALUE / 1000; // millivolts / 1000 = V
        } else if (tempRegex.test(value.LABEL)) {
            value.VALUE = value.VALUE / 1000; // millidegrees C / 10000 = C
        } 
    });
    return data; // After converting regular units returns the new object array with converted values
}

module.exports = {getCurrentMemory, getUptime, getTotalMemory, splitUptime, getLoadAvg, convert};