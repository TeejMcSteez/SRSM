const { MongoClient } = require('mongodb');
const fs = require('fs');
const bcrypt = require('bcrypt');

/*
URI and Configuration example . . .
const uri = 'mongodb://<your-host>:27017/AuthDatabase';
const options = {
  sslKey: fs.readFileSync('/path/to/client.pem'),
  sslCert: fs.readFileSync('/path/to/client.pem'),
  sslCA: fs.readFileSync('/path/to/ca.pem'),
  useUnifiedTopology: true,
};
*/ 

const USER_DATABASE = process.env.USER_DATABASE;

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
            console.log('Connected to MongoDB via TLS');
            this.db = this.client.db('AuthDatabase');
        } catch (error) {
            console.error(`Failed to connect to MongoDB with error: ${error}`);
            throw error;
        }
    }

    async validateUser(username, password) {
        if (!this.db) {
            throw new Error('Database not initialized. Call connect() first');
        }

        try {
            const user = await this.db.collection(USER_DATABASE).findOne({username});

            if (!user) {
                return {valid: false, reason: 'User does not exist'};
            }
            const isValid = await bcrypt.compare(password, user.pwd);
            if (!isValid) {
                return {valid: false, reason: 'Invalid password.'};
            }

            return {valid: true, user};
        } catch (error) {
            console.error(`Error validating user: ${error.message}`);
            throw error;
        }
    }
    
    async close() {
        if (this.client) {
            await this.client.close();
            console.log("Connection Closed");
            this.client = null;
            this.db = null;
        }
    }
}

module.exports = AuthService;