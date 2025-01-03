#!/bin/bash
hwmon_root='/sys/class/hwmon'
env_file='.env'

echo 'Starting .env re-configuration'

for dir in "$hwmon_root"/*; do
    if [[ ! -d "$dir" ]]; then
        continue
    fi

    content=$(cat "$dir/name" 2>>buildErrors.log)

    # Check for CPU Sensors
    if [["$content" == "coretemp" || "$content" == "k10temp" || "$content" == "zenpopwer" ]]; then
        if grep -q "^CPU_TEMPERATURE_DIRECTORY=" "$env_file"; then
            sed -i "s|^CPU_TEMPERATURE_DIRECTORY=.*|CPU_TEMPERATURE_DIRECTORY=$dir|" "$env_file"
            echo "Updated CPU_TEMERATURE_DIRECTORY to $dir in $env_file"
        else 
            echo "CPU_TEMPERATURE_DIRECTORY=$dir" >> "$env_file"
            echo "Appended CPU_TEMPERATURE_DIRECTORY to $env_file"
        fi
    fi

    # Check for Motherboard Sensors
    if [[ "$content" =~ nct[0-9]+ || "$content" =~ IT[0-9]+ || "$content" =~ F[0-9]+ || "$content" =~ SMSC[0-9]+ || "$content" =~ CX[0-9]+ || "$content" =~ w837[0-9]+ || "$content" =~ rt[0-9]+ ]]; then
        if grep -q "^MOTHERBOARD_DIRECTORY=" "$env_file"; then
            # Update the existing line
            sed -i "s|^MOTHERBOARD_DIRECTORY=.*|MOTHERBOARD_DIRECTORY=$dir|" "$env_file"
            echo "Updated MOTHERBOARD_DIRECTORY to $dir in $env_file"
        else
            # Append the line if it doesn't exist
            echo "MOTHERBOARD_DIRECTORY=$dir" >> "$env_file"
            echo "Appended MOTHERBOARD_DIRECTORY to $env_file"
        fi
    fi
done

echo 'Done with .env re-config good to launch . . ."