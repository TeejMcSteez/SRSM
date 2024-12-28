// TODO: Replace password comparison when I fix password values on the database
const { MongoClient } = require('mongodb');
const fs = require('fs');
const bcrypt = require('bcrypt');
const logger = require('pino')();
require('dotenv').config();

/*
URI and Configuration example . . .
const uri = `mongodb://${MONGODB_HOST}:27017/?authMechanism=MONGODB-X509`; //27017 is the default port for mongodb
const options = {
    tls: true,
    tlsCertificateKeyFile: CLIENT_KEY_PATH,
    tlsCAFile: CA_PATH
};
*/ 

const COLLECTION = process.env.USER_DATABASE;

class AuthService {
    constructor(uri, options = {}) {
        this.uri = uri;
        this.options = options;
        this.client = null;
        this.db = null;
    }

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

        } catch (error) {
            logger.error(`Error validating user: ${error.message}`);
            throw error;
        }
    }
    
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