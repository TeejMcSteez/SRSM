#!/bin/bash
# hwmon
hwmon = '/sys/class/hwmon'
env_file='.env'
#clears or creates .env
> .env

echo 'Starting build . . .'

echo 'Please enter the hostname for the HTTPS server'
read HOSTNAME
echo 'Please enter the port for the server to listen on . . .'
read PORT

echo 'Building node . . .'

npm init -y 
echo "NPM initialized installing packages"
npm i express uuid bcrypt jsonwebtoken dotenv express-http-to-https
echo "Packages installed starting file detection for env variables"

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
echo "Enter HTTPS Key Path . . ."
read HTTPS_KEY_PATH
echo "HTTPS_KEY_PATH = $HTTPS_KEY_PATH" >> "$env_file"

echo "Enter HTTPS Certificate Path . . ."
read HTTPS_CERT_PATH
echo "HTTPS_CERT_PATH=$HTTPS_CERT_PATH" >> "$env_file"

echo "Enter Json Web Token Key Path . . ."
read SECRET_PATH
echo "SECRET_PATH = $SECRET_PATH" >> "$env_file"

echo "Enter Json Web Token Certificate Path . . ."
read JWT_PATH
echo "JWT_PATH = $JWT_PATH" >> "$env_file"

echo "Enter MongoDB Client Key Path . . ."
read CLIENT_KEY_PATH
echo "CLIENT_KEY_PATH = $CLIENT_KEY_PATH"

echo "Enter MongoDB Certificate Path . . ."
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

echo "Creating certificate directories for credentials . . ."
mkdir https
mkdir jwt
mkdir mongo
echo "Directories made, exiting src directory. . ."
cd ..

echo -e "\nRepo pulled, build successful . . ."
echo -e "\nHTTPS, JWT, and MongoDB credentials directories still needed to be populated in src! . . .\n"
echo "Delete this build file!"