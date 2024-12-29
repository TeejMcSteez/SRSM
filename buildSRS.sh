#!/bin/bash
# hwmon
hwmon = '/sys/class/hwmon'
env_file='.env'

echo 'Starting build . . .'

#clears or creates .env
> .env

echo 'Please enter the hostname for the HTTPS server (Example: localhost, 127.0.0.1, 192.168.1.1). . .'
read HOSTNAME
echo 'Please enter the port for the server to listen on . . .'
read PORT

echo 'Building node enviroment and packages. . .'

npm init -y 
echo "NPM initialized installing packages"
npm i express uuid argon2 jsonwebtoken dotenv express-http-to-https express-rate-limit pino helmet express-validator
echo "Packages installed starting file detection . . ."

for dir in "$hwmon"/*; do
    if [[ ! -d "$dir" ]]; then 
        continue
    fi

     # Read the "name" file inside the directory
    content=$(cat "$dir/name" 2>>buildErrors.log)
    # Looking for CPU Thermal Sensor
    if [[ "$content" == "coretemp" ]]; then # Intel Thermal sensor
        echo "CPU_TEMPERATURE_DIRECTORY=$dir" >> "$env_file"
        echo "Appended $content to $env_file"
    fi
    if [[ "$content" == "k10temp" ]]; then # Old AMD Thermal sensor
        echo "CPU_TEMPERATURE_DIRECTORY=$dir" >> "$env_file"
        echo "Appended $content to $env_file"
    fi
    if [[ "$content" == "zenpopwer" ]]; then # Modern AMD Thermal sensor
        echo "CPU_TEMPERATURE_DIRECTORY=$dir" >> "$env_file"
        echo "Appended $content to $env_file"
    fi
    # Looking for Motherboard Super I/O Chip Sensorcd
    if [[ "$content" =~ nct[0-9]+ ]]; then # Nuvoton
        echo "MOTHERBOARD_DIRECTORY=$dir" >> "$env_file"
        echo "Appended $content to $env_file"
    fi
    if [[ "$content" =~ IT[0-9]+ ]]; then # ITE
        echo "MOTHERBOARD_DIRECTORY=$dir" >> "$env_file"
        echo "Appended $content to $env_file"
    fi
    if [[ "$content" =~ F[0-9]+ ]]; then # Fintek
        echo "MOTHERBOARD_DIRECTORY=$dir" >> "$env_file"
        echo "Appended $content to $env_file"
    fi
    if [[ "$content" =~ SMSC[0-9]+ ]]; then # SMSC
        echo "MOTHERBOARD_DIRECTORY=$dir" >> "$env_file"
        echo "Appended $content to $env_file"
    fi
    if [[ "$content" =~ CX[0-9]+ ]]; then # Chips and Technologies
        echo "MOTHERBOARD_DIRECTORY=$dir" >> "$env_file"
        echo "Appended $content to $env_file"
    fi
    if [[ "$content" =~ w837[0-9]+ ]]; then # Winbond
        echo "MOTHERBOARD_DIRECTORY=$dir" >> "$env_file"
        echo "Appended $content to $env_file"
    fi
    if [[ "$content" =~ rt[0-9]+ ]]; then # Realtek
        echo "MOTHERBOARD_DIRECTORY=$dir" >> "$env_file"
        echo "Appended $content to $env_file"
    fi
done

echo "Adding hostname and port to env variables . . ."
echo "HOSTNAME=$HOSTNAME" >> "$env_file"
echo "PORT=$PORT" >> "$env_file"

echo "Please enter paths for certificates and keys (Example: ./src/crts/CA.crt) . . ."
echo "Enter HTTPS Key Path (Example: ./src/https/private.key) . . ."
read HTTPS_KEY_PATH
echo "HTTPS_KEY_PATH = $HTTPS_KEY_PATH" >> "$env_file"

echo "Enter HTTPS Certificate Path (Example: ./src/https/server.crt). . ."
read HTTPS_CERT_PATH
echo "HTTPS_CERT_PATH=$HTTPS_CERT_PATH" >> "$env_file"

echo "Enter Json Web Token Key Path (Example: ./src/jwt/private.key). . ."
read SECRET_PATH
echo "SECRET_PATH = $SECRET_PATH" >> "$env_file"

echo "Enter Json Web Token Certificate Path (Example: ./src/jwt/public.key) . . ."
read JWT_PATH
echo "JWT_PATH = $JWT_PATH" >> "$env_file"

echo "Enter MongoDB Client Key Path (Example: ./src/mongo/client.pem). . ."
read CLIENT_KEY_PATH
echo "CLIENT_KEY_PATH = $CLIENT_KEY_PATH"

echo "Enter MongoDB Certificate Path (Example: ./src/mongo/ca.crt). . ."
read CA_PATH
echo "CA_PATH = $CA_PATH" >> "$env_file"

echo "Now entering MongoDB information for requests . . ."
echo "Enter the MongoDB URI to send requests to (Example: mongodb://<hostname>:27017/?authMechanism=MONGODB-X509)"
read MONGODB_URI
echo "MONGODB_URI = $MONGODB_URI" >> "$env_file"

echo "Enter name of the user collection (database [ex: UserDatabase]) . . ."
read USER_DATABASE
echo "USER_DATABASE = $USER_DATABASE" >> "$env_file"

echo "Starting git clone . . ."
mkdir src
cd src 
git init
git remote add origin https://github.com/TeejMcSteez/AuthedRemoteServer
git pull origin master
rm buildSRS.sh 
echo "Removed build file from pull . . ."

echo "Creating certificate directories for credentials . . ."
mkdir https
mkdir jwt
mkdir mongo
echo "Directories made, exiting src directory. . ."
cd ..

echo -e "\nRepo pulled, build successful . . ."
echo -e "\nHTTPS, JWT, and MongoDB credentials directories still needed to be populated in src! . . .\n"
echo -e "\n!*!*!*!*!*!*!*!*!*!*!*!*\nDelete this build file!\n!*!*!*!*!*!*!*!*!*!*!*!"
