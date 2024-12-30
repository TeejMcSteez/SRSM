"use strict";

/**
 * @fileoverview AuthService Class for MongoDB-based user authentication.
 * @description
 *  The AuthService handles the following tasks:
 *   - Connecting to a MongoDB database with TLS.
 *   - Validating user credentials.
 *   - Closing the database connection.
 * 
 *  Security considerations:
 *   - Ensure that passwords are hashed and compared with argon2 (or bcrypt).
 *   - Avoid logging sensitive data like plaintext passwords or secrets.
 *   - Use environment variables and secure file permissions for credentials.
 * 
 * @version 1.0.0
 * @since 2024-12-28
 */

const { MongoClient } = require("mongodb"); // DOC: https://www.npmjs.com/package/mongodb
const argon2 = require("argon2");           // DOC: https://www.npmjs.com/package/argon2
const logger = require("pino")();
require("dotenv").config();

const COLLECTION = process.env.USER_DATABASE;

/**
 * @typedef {Object} ValidateUserResult
 * @property {boolean} valid - Whether the credentials are valid.
 * @property {string} [reason] - The reason for a failed validation.
 * @property {Object} [user] - The user object from MongoDB, if validation is successful.
 */

/**
 * Connects, Validates, and Closes MongoDB database of users.
 * 
 * @class AuthService
 */
class AuthService {
  /**
   * Creates an instance of AuthService.
   * 
   * @param {string} uri - The MongoDB connection URI.
   * @param {Object} [options={}] - Additional MongoDB client options (e.g., TLS config).
   * @property {string} uri - The MongoDB URI stored for later connection.
   * @property {Object} options - Configuration object for TLS, timeouts, etc.
   * @property {?MongoClient} client - The MongoDB client instance (once connected).
   * @property {?Object} db - The connected MongoDB database instance.
   *
   * @example
   * const uri = 'mongodb://myMongoHost:27017/?authMechanism=MONGODB-X509';
   * const options = {
   *   tls: true,
   *   tlsCertificateKeyFile: '/path/to/client.pem',
   *   tlsCAFile: '/path/to/ca.pem'
   * };
   * const authService = new AuthService(uri, options);
   */
  constructor(uri, options = {}) {
    this.uri = uri;
    this.options = options;
    this.client = null;
    this.db = null;
  }

  /**
   * Connects to MongoDB and instantiates a client for use.
   * 
   * @async
   * @throws {Error} If the connection fails.
   * @returns {Promise<void>} Resolves on successful connection.
   *
   * @example
   * await authService.connect();
   */
  async connect() {
    if (this.client) return;

    try {
      this.client = new MongoClient(this.uri, this.options);
      await this.client.connect();
      logger.info("Connected to MongoDB via TLS");
      this.db = this.client.db("AuthDatabase");
    } catch (error) {
      logger.error(`Failed to connect to MongoDB with error: ${error}`);
      throw error;
    }
  }

  /**
   * Validates a user within the database using the stored credentials.
   * You must call {@link AuthService#connect} first or `this.db` will be `null`.
   *
   * @async
   * @param {string} USERNAME - The username to look up in the database.
   * @param {string} password - The plaintext password (or hashed password in a real system).
   * @throws {Error} If no client is connected.
   * @returns {Promise<ValidateUserResult>} An object with the validation result, plus a reason or user.
   *
   * @example
   * const result = await authService.validateUser("alice", "securePassword");
   * if (result.valid) {
   *   console.log("User is valid:", result.user);
   * } else {
   *   console.log("Validation failed:", result.reason);
   * }
   */
  async validateUser(USERNAME, password) {
    if (!this.db) {
      logger.error("There is no client. Call connect() first...");
      throw new Error("No client...");
    }

    const trimmedUsername = USERNAME.trim();
    try {
      logger.info("Searching for user...");
      const user = await this.db.collection(COLLECTION).findOne({ username: trimmedUsername });
      logger.info(`Returned user: ${user?.username}`);

      if (!user) {
        return { valid: false, reason: "User does not exist" };
      }

      // Example argon2 usage in production (uncomment if your DB stores hashed pwds):
      // const isValid = await argon2.verify(user.pwd, password);
      // For now, just do a direct compare:
      let isValid = false;
      if (password === user.pwd) {
        isValid = true;
      }

      logger.info(`Password verification: ${isValid}`);

      if (isValid) {
        return { valid: true, user };
      } else {
        return { valid: false, reason: "Invalid password." };
      }

      // In case the if/else is never reached (unlikely):
      // return { valid: false, reason: "Unknown validation error" };
    } catch (error) {
      logger.error(`Error validating user: ${error.message}`);
      throw error;
    }
  }

  /**
   * Closes the database session. THIS IS NECESSARY!
   * Otherwise, the client will leave unclosed sessions on the server.
   * 
   * @async
   * @returns {Promise<void>} Resolves when the session has closed.
   *
   * @example
   * await authService.close();
   */
  async close() {
    if (this.client) {
      await this.client.close();
      logger.info("Connection Closed");
      this.client = null;
      this.db = null;
    }
  }
}

module.exports = AuthService;
