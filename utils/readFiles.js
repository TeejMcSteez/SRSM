/**
 * Functions to read directories and files
 */
const fs = require('node:fs');
const path = require('node:path');
const logger = require('pino')();
/**
 * Takes array full of folder names and reads the contents on each folder
 * @param {Array} dir - directory full of folders
 * @returns {Array} - Returns array of read file names 
 */
function readFolder(dir) { 
    return new Promise((resolve, reject) => {
        fs.readdir(dir, (err, buffer) => {
            logger.info(`Readings files from ${dir}`);
            if (err) {
                reject(`Could not read files from ${dir}`);
            } else {
                resolve(buffer);
            }
        });
    });
}
/**
 * Finds the temperature files within the temperature directory
 * @param {Object[]} dirContents - Files in the temperature directory
 * @returns {Object[]} - Returns object array of temperature files worth reading
 */
function findTemperatureFiles(dirContents) {
    const tempRegex = /temp\d+_\w+/; // Finds all files with temperature reading 
    let matches = dirContents.filter(filename => tempRegex.test(filename)); // Reseach .filter()

    if (!matches) {
        logger.info("There is no temperature information in this directory");
    }
    return matches.map(match => ({ // Research .map()
        LABEL: match
    }));// Returns object array of all labels in the dir
}
/**
 * Find the motherboard files worth reading within the array
 * @param {Object[]} dirContents - Files in the motherboard directory
 * @returns {Object[]} - Returns useful information in the motherboard directory
 */
function findMotherboardFiles(dirContents) {
    const voltageRegex = /in\d+_\w+/;
    const fanRegex = /fan\d+_\w+/;

    let voltMatches = dirContents.filter(filename => voltageRegex.test(filename));
    let fanMatches = dirContents.filter(filename => fanRegex.test(filename));

    let matches = voltMatches.concat(fanMatches);
    
    if (!matches) {
        logger.info("There are no temperatures to map in this directory");
    } 

    return matches.map(match => ({
        LABEL: match 
    }));
}
/**
 * Finds the values of all useful directories
 * @param {String} dir - Directory to read the file
 * @param {String} label - Name of the file to read
 * @returns {Object[Label: label, VALUE: value]} - Returns useful names and values to display
 */
async function findValues(dir, label) {
    return new Promise((resolve, reject) => {
        const filePath = path.join(dir, label);

        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                logger.info(`Could not read file ${label}`);
                reject(err);
            } else {
                resolve({LABEL: label, VALUE: data.trim()});
            }
        });
    });
}

module.exports = {readFolder, findTemperatureFiles, findMotherboardFiles, findValues};