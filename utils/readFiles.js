"use strict";

/**
 * @fileoverview Functions to read directories and files.
 */

const fs = require("node:fs");
const path = require("node:path");
const logger = require("pino")();

/**
 * Reads the contents of a directory (folder) and returns an array of filenames.
 * @async
 * @function readFolder
 * @param {string} dir - A file path to the directory to read.
 * @returns {Promise<Array<string>>} A promise that resolves to an array of filenames.
 */
function readFolder(dir) {
  return new Promise((resolve, reject) => {
    fs.readdir(dir, (err, buffer) => {
      logger.info(`Reading files from: ${dir}`);
      if (err) {
        reject(new Error(`Could not read files from ${dir}`));
      } else {
        resolve(buffer);
      }
    });
  });
}

/**
 * Finds the temperature files within the temperature directory.
 *
 * @function findTemperatureFiles
 * @param {Array<string>} dirContents - An array of filenames in the temperature directory.
 * @returns {Array.<{ LABEL: string }>} An array of objects, each containing a `LABEL` property.
 */
function findTemperatureFiles(dirContents) {
  const tempRegex = /temp\d+_\w+/; 
  const matches = dirContents.filter((filename) => tempRegex.test(filename));

  if (!matches || matches.length === 0) {
    logger.info("There is no temperature information in this directory");
  }

  return matches.map((match) => ({ LABEL: match }));
}

/**
 * Finds motherboard files worth reading (voltages and fans) within the array.
 *
 * @function findMotherboardFiles
 * @param {Array<string>} dirContents - An array of filenames in the motherboard directory.
 * @returns {Array.<{ LABEL: string }>} An array of objects, each containing a `LABEL` property.
 */
function findMotherboardFiles(dirContents) {
  const voltageRegex = /in\d+_\w+/;
  const fanRegex = /fan\d+_\w+/;

  const voltMatches = dirContents.filter((filename) => voltageRegex.test(filename));
  const fanMatches = dirContents.filter((filename) => fanRegex.test(filename));

  const matches = voltMatches.concat(fanMatches);

  if (!matches || matches.length === 0) {
    logger.info("There are no temperature or fan files to map in this directory");
  }

  return matches.map((match) => ({ LABEL: match }));
}

/**
 * @typedef {Object} LabeledValue
 * @property {string} LABEL - The name of the file read
 * @property {string} VALUE - The trimmed file data
 */

/**
 * Reads the file corresponding to the given label in the specified directory 
 * and returns the label/value pair.
 *
 * @async
 * @function findValues
 * @param {string} dir - A file path to the directory that contains the file.
 * @param {string} label - Name of the file to read.
 * @returns {Promise<LabeledValue>} Promise resolving to an object with label and value.
 */
async function findValues(dir, label) {
  const filePath = path.join(dir, label);
  return new Promise((resolve, reject) => {
    fs.readFile(filePath, "utf8", (err, data) => {
      if (err) {
        logger.info(`Could not read file: ${label}`);
        reject(err);
      } else {
        // remove trailing spaces / newlines
        resolve({ LABEL: label, VALUE: data.trim() });
      }
    });
  });
}

module.exports = {
  readFolder,
  findTemperatureFiles,
  findMotherboardFiles,
  findValues,
};
