const fs = require('node:fs');
const path = require('node:path');
const logger = require('pino')();
// Reads the content of a folder
function readFolder(dir) { // Callback inside of a callback oh boy this should be food
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

// Finds the files containing temperature values within the directory
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

// Finds useful motherboard files from the directory and returns the labels
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

// Finds the values of the temperature values from the files within the directory
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