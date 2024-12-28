/**
 * @fileoverview AuthService Class for MongoDB-based user authentication.
 * @description
 *  The AuthService handles the following tasks:
 *   - Connecting to a MongoDB database with TLS.
 *   - Validating user credentials.
 *   - Closing the database connection.
 * 
 *  Security considerations:
 *   - Ensure that passwords are hashed and compared with bcrypt.
 *   - Avoid logging sensitive data like plaintext passwords or secrets.
 *   - Use environment variables and secure file permissions for credentials.
 * 
 * @version 1.0.0
 * @since 2024-12-28
 */
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const logger = require('pino')();
require('dotenv').config();

const COLLECTION = process.env.USER_DATABASE;
/**
 * Connects, Validates, and Closes Mongodb database of users 
 * 
 * @class
 */
class AuthService {
    /**
     * Creates an instance of AuthService.
     * 
     * @param {string} uri - The MongoDB connection URI.
     * @param {object} [options={}] - Additional MongoDB client options.
     * @property {string} this.uri - The MongoDB URI stored for later connection.
     * @property {object} this.options - Configuration object for TLS, timeouts, etc.
     * @property {?MongoClient} this.client - The MongoDB client instance (once connected).
     * @property {?object} this.db - The connected MongoDB database instance.
     * 
     * @example
     * const uri = 'mongodb://myMongoHost:27017/?authMechanism=MONGODB-X509';
     * const options = {
     *     tls: true,
     *     tlsCertificateKeyFile: '/path/to/client.pem',
     *     tlsCAFile: '/path/to/ca.pem'
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
     * Connects to Mongodb and instantiates client to use
     * 
     * @async 
     * @throws {Error}
     * @returns {Promise<void>}
     * 
     * @example
     * await authService.connect();
     */
    async connect() {
        if (this.client) return;

        try {
            this.client = new MongoClient(this.uri, this.options);
            await this.client.connect();
            logger.info('Connected to MongoDB via TLS');
            this.db = this.client.db('AuthDatabase');
        } catch (error) {
            logger.error(`Failed to connect to MongoDB with error: ${error}`);
            throw error;
        }
    }
    /**
     * Validates user within the database using client information
     * CALL CONNECT FIRST!
     * @param {String} USERNAME 
     * @param {String} password 
     * @throws {Error} if no client is connected throws error
     * @returns {Promise<{ valid: boolean, reason?: string, user?: object }>} - Returns object with validation boolean and reason for validation choice
     * 
     * @example 
     * const result = await authService.validateUser('alice', 'securePassword');
     * if (result.valid) {
     *   console.log('User is valid:', result.user);
     * } else {
     *   console.log('Validation failed:', result.reason);
     * }
     */
    async validateUser(USERNAME, password) {
        if (!this.db) {
            logger.error('There is no client call connect() first . . .');
            throw new Error("No client . . .");
        }
        const trimmedUsername = USERNAME.trim();
        try {
            logger.info('Searching for user . . .');
            const user = await this.db.collection(COLLECTION).findOne({username: trimmedUsername});
            logger.info(`Returned: ${user.username}`);
            if (!user) {
                return {valid: false, reason: 'User does not exist'};
            }
            // In prod I need to replace my database password when encrypted passwords to compare with bcrypt
            // const isValid = (await bcrypt.compare(password, user.pwd));
            let isValid = false;
            if (password === user.pwd) {
                isValid = true;
            } else {
                isValid = false;
            }

            logger.info(`Bcrypt verification: ${(isValid)}`);

            if (isValid) {
                return {valid: true, user};
            } else {
                return {valid: false, reason: 'Invalid password.'};
            }
            return {valid: false, reason: 'Validation logic failed, user is false for security . . .'}; // Added incase if else statement are never hit program will return false
        } catch (error) {
            logger.error(`Error validating user: ${error.message}`);
            throw error;
        }
    }
    /**
     * Closes session THIS IS NECESSARY! Otherwise client will leave unclosed sessions on server
     * 
     * @async 
     * @returns {Promise<void>}
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