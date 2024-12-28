/**
 * Used for reading system information
 */
const os = require("node:os");
/**
 * Gets the free memory (unused) on the system in bytes
 * @returns {Number} - Free memory in bytes 
 */
function getCurrentMemory() {
    const freeMem = os.freemem();

    const freeMemInGb = bytesToGb(freeMem);

    return freeMemInGb;    
}
/**
 * Gets total memory on the system
 * @returns {Number} - Total Memory on the system
 */
function getTotalMemory() {
    const totalMem = os.totalmem();

    const totalMemInGb = bytesToGb(totalMem);

    return totalMemInGb;
}
/**
 * Gets uptime in Milliseconds
 * @returns {Array} - Uptime Averages
 */
function getUptime() {
    const uptime = os.uptime();

    return uptime;
}
/**
 * Converts Memory in bytes to gigabytes
 * @param {Number} memInBytes - Memory in bytes
 * @returns {Number} - Memory in Gigabytes
 */
function bytesToGb(memInBytes) {
    const memInGb = memInBytes / 1e9; // Dividing the bytes by a billion

    return memInGb;
}
/**
 * Splits uptime MS into Days, Hours, Minutes, Seconds
 * @param {Number} uptime - Uptime in Milliseconds
 * @returns {Array} - [Days, Hours, Minutes, Seconds]
 */
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
/**
 * Gets load average array from node:os ONLY ON UNIX
 * @returns {Array} - [1 Minute, 5 Minute, 15 Minute] Load Averages
 */
function getLoadAvg() {
    const loadAvg = os.loadavg();
    
    return loadAvg;
}
/**
 * Converts Milli readings values to base 10
 * @param {Object[]} data - Object array of readings names and values 
 * @returns {Object[]} - Returns new object array with converted readings values
 */
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