#!/bin/bash

CONFIG_FILE="config.cfg"

# Function to handle tag errors
handle_tag_error() {
    local response="$1"
    if [[ "$response" =~ "invalid or not permitted" ]]; then
        echo -e "\e[33mError: The specified tag(s) are not defined in your Tailscale ACL policy.\e[0m"
        echo -e "To fix this:"
        echo "1. Open your Tailscale ACL policy file"
        echo "2. Add the tag(s) to the 'tagOwners' section like this:"
        echo -e "   \"tagOwners\": {\n     \"tag:NAME\": [\"autogroup:admin\"],\n     ...\n   }"
        echo "3. Push/submit the updated ACL policy"
        echo "4. Try applying the tags again"
        return 1
    fi
    return 0
}

# Default connection settings if not in config
DEFAULT_CONNECT_TIMEOUT=60
DEFAULT_MAX_TIME=120
DEFAULT_RETRY=3
DEFAULT_RETRY_DELAY=5
DEFAULT_RETRY_MAX_TIME=300

# Add after DEFAULT settings
DEBUG_MODE=false
DEBUG_FILE="requests.txt"
MATCH_BY="name"  # Default match by name

# Function to list all devices
list_devices() {
    echo "Fetching devices from Tailscale..."
    response=$(curl -s \
        --connect-timeout "$(printf '%.0f' "$CONNECT_TIMEOUT")" \
        --max-time "$(printf '%.0f' "$MAX_TIME")" \
        --retry "$(printf '%.0f' "$RETRY")" \
        --retry-delay "$(printf '%.0f' "$RETRY_DELAY")" \
        --retry-max-time "$(printf '%.0f' "$RETRY_MAX_TIME")" \
        --request GET \
        --url "https://api.tailscale.com/api/v2/tailnet/${TAILNET_ORG}/devices" \
        --header "Authorization: Bearer ${API_KEY}")
    
    if [ $? -eq 0 ]; then
        echo "Available devices:"
        if echo "$response" | jq -e '.devices' >/dev/null 2>&1; then
            echo "$response" | jq -r '.devices[] | "\(.name) (\(.addresses[0])) - Tags: \(.tags[]?)"'
        else
            echo "Error: Invalid response format"
            echo "$response" | jq '.' 2>/dev/null || echo "$response"
        fi
    else
        echo "Error fetching devices"
    fi
}

collect_tags() {
    tags=()
    echo -e "\nNow, let's set ACL Tags for each pattern..."
    
    for i in "${!custom_values[@]}"; do
        local pattern="${custom_values[i]}"
        echo -e "\nSetting up tags for pattern: '$pattern'"
        local tag_list=()
        
        fetch_available_tags
        
        while true; do
            echo -e "\nEnter tag name (without 'tag:' prefix, or empty to finish):"
            echo "You can either select an existing tag number or type a new tag name."
            read tag_name
            
            if [ -z "$tag_name" ]; then
                break
            fi
            
            # Check if input is a number referring to an existing tag
            if [[ "$tag_name" =~ ^[0-9]+$ ]]; then
                if [ "$tag_name" -le "${#available_tags[@]}" ] && [ "$tag_name" -gt 0 ]; then
                    tag_name="${available_tags[$((tag_name-1))]}"
                else
                    echo "Invalid tag number. Please try again."
                    continue
                fi
            fi
            
            # Validate tag name
            if [[ $tag_name =~ ^[a-zA-Z0-9_-]+$ ]]; then
                tag_list+=("tag:$tag_name")
                echo -e "\e[32mAdded tag: $tag_name\e[0m"
            else
                echo "Invalid tag name. Use only letters, numbers, underscores, and hyphens."
            fi
        done
        
        if [ ${#tag_list[@]} -gt 0 ]; then
            tags+=("${tag_list[*]}")
            export "TAGS_$((i+1))=${tag_list[*]}"
            echo -e "\e[32mTags setup complete for '$pattern': ${tag_list[*]}\e[0m"
        else
            echo "No tags were added for this pattern."
            tags+=("")
            export "TAGS_$((i+1))="
        fi
    done
}

# Function to fetch and display available ACL tags
fetch_available_tags() {
    echo "Fetching available ACL tags from Tailscale..."
    local api_response=$(curl -s \
        --connect-timeout "$(printf '%.0f' "$CONNECT_TIMEOUT")" \
        --max-time "$(printf '%.0f' "$MAX_TIME")" \
        --retry "$(printf '%.0f' "$RETRY")" \
        --retry-delay "$(printf '%.0f' "$RETRY_DELAY")" \
        --retry-max-time "$(printf '%.0f' "$RETRY_MAX_TIME")" \
        --request GET \
        --url "https://api.tailscale.com/api/v2/tailnet/${TAILNET_ORG}/devices" \
        --header "Authorization: Bearer ${API_KEY}")
    
    if [ $? -eq 0 ]; then
        echo -e "\nExisting ACL tags in use:"
        available_tags=($(echo "$api_response" | jq -r '.devices[].tags[]?' | sort -u | sed 's/^tag://'))
        if [ ${#available_tags[@]} -gt 0 ]; then
            printf '%s\n' "${available_tags[@]}" | nl -w2 -s'. '
        else
            echo "No existing ACL tags found."
        fi
    else
        echo "Error fetching ACL tags"
    fi
}

apply_tags() {
    echo -e "\nReady to apply the following tags:"
    for i in "${!custom_values[@]}"; do
        echo -e "\nPattern: '${custom_values[i]}'"
        IFS=' ' read -r -a tag_array <<< "${tags[i]}"
        echo "└─ Tags: ${tag_array[*]}"
    done

    echo -n -e "\nDo you want to proceed with applying these tags? (y/n): "
    read confirm
    if [[ ! "$confirm" =~ ^[Yy] ]]; then
        echo "Operation cancelled."
        return 1
    fi

    for i in "${!custom_values[@]}"; do
        if [ -f "nodeids_${custom_values[i]}.tmp" ]; then
            while IFS= read -r line; do
                for nodeid in $line; do
                    echo "Applying tags to device $nodeid..."
                    
                    # Prepare JSON data for tags with proper formatting
                    IFS=' ' read -r -a tag_array <<< "${tags[i]}"
                    json_data="{\n  \"tags\": [\n"
                    for ((j=0; j<${#tag_array[@]}; j++)); do
                        json_data+="    \"${tag_array[j]}\""
                        if [ $j -lt $((${#tag_array[@]}-1)) ]; then
                            json_data+=","
                        fi
                        json_data+="\n"
                    done
                    json_data+="  ]\n}"
                    
                    url="https://api.tailscale.com/api/v2/device/${nodeid}/tags"
                    log_debug "$url" "$json_data"
                    response=$(curl -s \
                        --connect-timeout "$(printf '%.0f' "$CONNECT_TIMEOUT")" \
                        --max-time "$(printf '%.0f' "$MAX_TIME")" \
                        --retry "$(printf '%.0f' "$RETRY")" \
                        --retry-delay "$(printf '%.0f' "$RETRY_DELAY")" \
                        --retry-max-time "$(printf '%.0f' "$RETRY_MAX_TIME")" \
                        --request POST \
                        --url "$url" \
                        --header "Authorization: Bearer ${API_KEY}" \
                        --header 'Content-Type: application/json' \
                        --data-raw "$(echo -e "$json_data")")
                    
                    if [ "$response" = "null" ] || [ -z "$response" ]; then
                        echo -e "\e[32m✓ Successfully applied tags to device $nodeid\e[0m"
                    else
                        echo -e "\e[31m✗ Failed to apply tags to device $nodeid\e[0m"
                        echo -e "\e[33mResponse:\e[0m"
                        echo "$response" | jq -r . 2>/dev/null || echo "$response"
                        # Extract message field and check for error
                        error_msg=$(echo "$response" | jq -r '.message' 2>/dev/null)
                        if [[ "$error_msg" == *"invalid or not permitted"* ]]; then
                            handle_tag_error "$error_msg"
                            break 3  # Exit all loops after showing the error
                        fi
                    fi
                    
                    sleep 1
                done
            done < "nodeids_${custom_values[i]}.tmp"
            rm "nodeids_${custom_values[i]}.tmp"
        fi
    done
}

# Function to display menu
show_menu() {
    echo -e "\n\033[1;35mTailscale Auto-Posture Menu\033[0m"
    echo -e "\033[1;36m1. List all devices\033[0m"
    echo -e "\033[1;33m2. Start Auto-Tagging\033[0m"
    echo -e "\033[1;32m3. Configure API Settings\033[0m"
    echo -e "\033[1;34m4. Configure Connection Settings\033[0m"
    echo -e "\033[1;31m5. Toggle Debug Mode (${DEBUG_MODE})\033[0m"
    echo -e "\033[1;37m0. Exit\033[0m"
    echo -n "Select an option: "
}

# Function to prompt for configuration values
get_config_values() {
    if [ -z "$API_KEY" ]; then
        echo "Please enter your Tailscale API key (input will be hidden for security):"
        read -s API_KEY
        while [ -z "$API_KEY" ] || [ ${#API_KEY} -ne 61 ]; do
            if [ -z "$API_KEY" ]; then
                echo "API key cannot be empty. Please try again:"
            else
                echo "Invalid API key length. Tailscale API keys must be 61 characters. Please try again:"
            fi
            read -s API_KEY
        done
        echo -e "\e[32mAPI key validation successful! Valid 61-character key received. ✓\e[0m"
        echo
    fi

    if [ -z "$TAILNET_ORG" ]; then
        echo "Please enter your Tailnet organization name (e.g., example.github):"
        read TAILNET_ORG
        while [ -z "$TAILNET_ORG" ]; do
            echo "Tailnet organization name cannot be empty. Please try again:"
            read TAILNET_ORG
        done
    fi

    # Update config file with new values
    update_config_file
    echo -e "\e[32m$TAILNET_ORG\e[0m"
    echo "Configuration loaded successfully!"
}

# Function to get matching device nodeIds
get_matching_devices() {
    local custom_value=$1
    local case_sensitive=$2
    local exclude_value=$3
    local matches=()
    local jq_filter
    
    if [ "$case_sensitive" = "true" ]; then
        jq_filter=".devices[] | select(.${MATCH_BY} | contains(\"$custom_value\"))"
    else
        jq_filter=".devices[] | select(.${MATCH_BY} | ascii_downcase | contains(\"${custom_value,,}\"))"
    fi
    
    if [ -n "$exclude_value" ] && [ "$exclude_value" != "null" ]; then
        jq_filter+=" | select(.${MATCH_BY} | ascii_downcase | contains(\"${exclude_value,,}\") | not)"
    fi
    
    response=$(curl -s \
        --connect-timeout "$(printf '%.0f' "$CONNECT_TIMEOUT")" \
        --max-time "$(printf '%.0f' "$MAX_TIME")" \
        --retry "$(printf '%.0f' "$RETRY")" \
        --retry-delay "$(printf '%.0f' "$RETRY_DELAY")" \
        --retry-max-time "$(printf '%.0f' "$RETRY_MAX_TIME")" \
        --request GET \
        --url "https://api.tailscale.com/api/v2/tailnet/${TAILNET_ORG}/devices" \
        --header "Authorization: Bearer ${API_KEY}")
    
    if [ $? -eq 0 ]; then
        if [ "$DEBUG_MODE" = true ]; then
            echo "API Response: $response"  # Debugging line
        fi
        matches=($(echo "$response" | jq -r "$jq_filter | .id"))
        
        if [ ${#matches[@]} -gt 0 ]; then
            echo "Found ${#matches[@]} matching devices for pattern '$custom_value' (case ${case_sensitive:+sensitive:insensitive}):"
            echo "$response" | jq -r "$jq_filter | \"\(.${MATCH_BY}) (\(.id))\""
            echo "${matches[@]}" > "nodeids_${custom_value}.tmp"
        else
            echo "No devices found matching pattern '$custom_value'"
        fi
    else
        echo "Error fetching devices"
        return 1
    fi
}


# Function to validate ISO 8601 date format
validate_date() {
    local date_str=$1
    if [[ $date_str =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to validate attribute name
validate_attribute_name() {
    local name=$1
    # Check length including 'custom:' prefix
    if [ ${#name} -gt 43 ]; then  # 50 - len('custom:')
        echo "Attribute name too long (max 43 chars excluding 'custom:' prefix)"
        return 1
    fi
    # Check for valid characters
    if ! [[ $name =~ ^[a-zA-Z0-9_]+$ ]]; then
        echo "Attribute name can only contain letters, numbers, and underscores"
        return 1
    fi
    return 0
}

# Function to validate attribute value
validate_attribute_value() {
    local value=$1
    # For string values
    if [[ ! "$value" =~ ^[0-9]+$ ]] && [[ ! "$value" =~ ^(true|false)$ ]]; then
        if ((${#value} > 50)); then
            echo "String value too long (max 50 chars)"
            return 1
        fi
        if ! [[ $value =~ ^[a-zA-Z0-9_\.]+$ ]]; then
            echo "String value can only contain letters, numbers, underscores, and periods"
            return 1
        fi
    fi
    # For numbers
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        if ((value > 9007199254740991)); then  # 2^53 - 1
            echo "Number value too large (max 2^53 - 1)"
            return 1
        fi
    fi
    return 0
}

# Function to collect custom attributes
collect_custom_attributes() {
    custom_attributes=()
    attribute_names=()
    expiry_dates=()
    echo -e "\nNow, let's set Custom Attributes for each pattern..."
    
    for i in "${!custom_values[@]}"; do
        local pattern="${custom_values[i]}"
        echo -e "\nSetting up attributes for pattern: '$pattern'"
        
        # Get attribute name
        while true; do
            echo "Enter attribute name (letters, numbers, underscores only, max 43 chars):"
            read attr_name
            if validate_attribute_name "$attr_name"; then
                attribute_names+=("$attr_name")
                export "ATTR_NAME_$((i+1))=$attr_name"
                break
            fi
        done

        # Get attribute value
        while true; do
            echo "Enter attribute value (string, number, or boolean):"
            read attribute
            if validate_attribute_value "$attribute"; then
                custom_attributes+=("$attribute")
                export "CUSTOM_ATTR_$((i+1))=$attribute"
                break
            fi
        done

        # Get expiry date if wanted
        echo -n "Do you want this attribute to expire? (y/n): "
        read wants_expiry
        if [[ "$wants_expiry" =~ ^[Yy] ]]; then
            while true; do
                echo "Enter expiry date in format YYYY-MM-DDThh:mm:ssZ (e.g., 2024-12-01T05:23:30Z):"
                read expiry_date
                if validate_date "$expiry_date"; then
                    expiry_dates+=("$expiry_date")
                    export "EXPIRY_$((i+1))=$expiry_date"
                    break
                else
                    echo "Invalid date format. Please try again."
                fi
            done
        else
            expiry_dates+=("")
            export "EXPIRY_$((i+1))="
        fi
        
        echo -e "\e[32mAttribute setup complete for '$pattern'\e[0m"
    done
}

# Function to collect custom values
collect_custom_values() {
    custom_values=()
    case_sensitive_flags=()
    exclude_values=()
    
    while true; do
        echo -n "Input regular expression that matches part of your names: "
        read custom_value
        
        if [ -n "$custom_value" ]; then
            echo -n "Make this pattern case sensitive? (y/n): "
            read case_choice
            
            echo -n "Input regular expression to exclude from matching names (optional): "
            read exclude_value
            
            custom_values+=("$custom_value")
            if [[ "$case_choice" =~ ^[Yy] ]]; then
                case_sensitive_flags+=("true")
            else
                case_sensitive_flags+=("false")
            fi
            exclude_values+=("$exclude_value")
            
            echo -n "Do you want to input another custom value? (y/n): "
            read another
            if [[ ! "$another" =~ ^[Yy] ]]; then
                break
            fi
        else
            echo "Value cannot be empty. Please try again."
        fi
    done

    # Export custom values and their case sensitivity flags
    for i in "${!custom_values[@]}"; do
        export "CUSTOM_VALUE_$((i+1))=${custom_values[i]}"
        export "CASE_SENSITIVE_$((i+1))=${case_sensitive_flags[i]}"
        export "EXCLUDE_VALUE_$((i+1))=${exclude_values[i]}"
    done
    
    echo -e "\nCustom values saved:"
    for i in "${!custom_values[@]}"; do
        echo "CUSTOM_VALUE_$((i+1)): ${custom_values[i]} (Case ${case_sensitive_flags[i]:+Sensitive:Insensitive})"
        echo "EXCLUDE_VALUE_$((i+1)): ${exclude_values[i]}"
    done

    echo -e "\nFinding matching devices for each pattern..."
    for i in "${!custom_values[@]}"; do
        get_matching_devices "${custom_values[i]}" "${case_sensitive_flags[i]}" "${exclude_values[i]}"
    done
}

# Function to apply attributes to devices
apply_attributes() {
    echo -e "\nReady to apply the following attributes:"
    for i in "${!custom_values[@]}"; do
        echo -e "\nPattern: '${custom_values[i]}'"
        echo "├─ Attribute Name: ${attribute_names[i]}"
        echo "├─ Value: ${custom_attributes[i]}"
        if [ -n "${expiry_dates[i]}" ]; then
            echo "└─ Expires: ${expiry_dates[i]}"
        else
            echo "└─ No expiry date"
        fi
    done

    echo -n -e "\nDo you want to proceed with applying these attributes? (y/n): "
    read confirm
    if [[ ! "$confirm" =~ ^[Yy] ]]; then
        echo "Operation cancelled."
        return 1
    fi

    # Apply attributes to matching devices
    for i in "${!custom_values[@]}"; do
        if [ -f "nodeids_${custom_values[i]}.tmp" ]; then
            # Read nodeIds line by line and process each one separately
            while IFS= read -r line; do
                # Split the line into individual nodeIds
                for nodeid in $line; do
                    echo "Applying attribute '${attribute_names[i]}' to device $nodeid..."
                    
                    # Prepare JSON data
                    json_data="{"
                    if [[ "${custom_attributes[i]}" =~ ^[0-9]+$ ]]; then
                        json_data+="\"value\": ${custom_attributes[i]}"
                    elif [[ "${custom_attributes[i],,}" == "true" || "${custom_attributes[i],,}" == "false" ]]; then
                        json_data+="\"value\": ${custom_attributes[i],,}"
                    else
                        json_data+="\"value\": \"${custom_attributes[i]}\""
                    fi

                    if [ -n "${expiry_dates[i]}" ]; then
                        json_data+=",\"expiry\": \"${expiry_dates[i]}\""
                    fi
                    json_data+="}"

                    # Make API call for individual nodeId
                    url="https://api.tailscale.com/api/v2/device/${nodeid}/attributes/custom:${attribute_names[i]}"
                    log_debug "$url" "$json_data"
                    response=$(curl -s \
                        --connect-timeout "$(printf '%.0f' "$CONNECT_TIMEOUT")" \
                        --max-time "$(printf '%.0f' "$MAX_TIME")" \
                        --retry "$(printf '%.0f' "$RETRY")" \
                        --retry-delay "$(printf '%.0f' "$RETRY_DELAY")" \
                        --retry-max-time "$(printf '%.0f' "$RETRY_MAX_TIME")" \
                        --request POST \
                        --url "$url" \
                        --header "Authorization: Bearer ${API_KEY}" \
                        --header 'Content-Type: application/json' \
                        --data "$json_data")
                    
                    # Check for successful response
                    if [ "$response" = "null" ] || [ -z "$response" ]; then
                        echo -e "\e[32m✓ Successfully applied attribute to device $nodeid\e[0m"
                    else
                        echo -e "\e[31m✗ Failed to apply attribute to device $nodeid\e[0m"
                        echo -e "\e[33mResponse:\e[0m"
                        echo "$response" | jq -r . 2>/dev/null || echo "$response"
                    fi
                    
                    # Add small delay between requests
                    sleep 1
                done
            done < "nodeids_${custom_values[i]}.tmp"
            rm "nodeids_${custom_values[i]}.tmp"
        fi
    done
}

# Add new debug logging function
log_debug() {
    local url=$1
    local data=$2
    if [ "$DEBUG_MODE" = true ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Request:" >> "$DEBUG_FILE"
        echo "URL: $url" >> "$DEBUG_FILE"
        echo "Data: $data" >> "$DEBUG_FILE"
        echo "----------------------------------------" >> "$DEBUG_FILE"
    fi
}

# Function to update connection settings
update_connection_settings() {
    echo -e "\nCurrent Connection Settings:"
    echo "1. Connect Timeout: $CONNECT_TIMEOUT seconds"
    echo "2. Max Time: $MAX_TIME seconds"
    echo "3. Retry Count: $RETRY attempts"
    echo "4. Retry Delay: $RETRY_DELAY seconds"
    echo "5. Retry Max Time: $RETRY_MAX_TIME seconds"
    echo "6. Match By: $MATCH_BY"
    echo "0. Back to main menu"
    
    echo -n "Select setting to change (0-6): "
    read setting_choice

    case $setting_choice in
        1)
            echo -n "Enter new connect timeout (seconds): "
            read new_value
            CONNECT_TIMEOUT=${new_value%.*}
            ;;
        2)
            echo -n "Enter new max time (seconds): "
            read new_value
            MAX_TIME=${new_value%.*}
            ;;
        3)
            echo -n "Enter new retry count: "
            read new_value
            RETRY=${new_value%.*}
            ;;
        4)
            echo -n "Enter new retry delay (seconds): "
            read new_value
            RETRY_DELAY=${new_value%.*}
            ;;
        5)
            echo -n "Enter new retry max time (seconds): "
            read new_value
            RETRY_MAX_TIME=${new_value%.*}
            ;;
        6)
            echo -n "Enter new match by value [Machine name / OS Hostname] Enter: "name" or "hostname": "
            read new_value
            if [[ "$new_value" == "name" || "$new_value" == "hostname" ]]; then
                MATCH_BY=$new_value
            else
                echo "Invalid value. Please enter 'name' or 'hostname'."
            fi
            ;;
        0)
            return
            ;;
        *)
            echo "Invalid option"
            return
            ;;
    esac

    # Update config file
    update_config_file
    echo "Settings updated successfully!"
}

# Function to update API settings
update_api_settings() {
    echo -e "\nCurrent API Settings:"
    echo "1. API Key: ${API_KEY:0:10}... (hidden)"
    echo "2. Tailnet Organization: $TAILNET_ORG"
    echo "0. Back to main menu"
    
    echo -n "Select setting to change (0-2): "
    read setting_choice

    case $setting_choice in
        1)
            echo "Please enter new Tailscale API key (input will be hidden):"
            read -s API_KEY
            while [ -z "$API_KEY" ] || [ ${#API_KEY} -ne 61 ]; do
                echo "Invalid API key length. Must be 61 characters."
                read -s API_KEY
            done
            echo "API key updated successfully!"
            ;;
        2)
            echo "Please enter new Tailnet organization name:"
            read TAILNET_ORG
            while [ -z "$TAILNET_ORG" ]; do
                echo "Organization name cannot be empty."
                read TAILNET_ORG
            done
            echo "Organization updated successfully!"
            ;;
        0)
            return
            ;;
        *)
            echo "Invalid option"
            return
            ;;
    esac

    # Update config file
    update_config_file
}

# Function to update config file
update_config_file() {
    {
        echo "API_KEY='${API_KEY}'"
        echo "TAILNET_ORG='${TAILNET_ORG}'"
        echo "CONNECT_TIMEOUT=${CONNECT_TIMEOUT}"
        echo "MAX_TIME=${MAX_TIME}"
        echo "RETRY=${RETRY}"
        echo "RETRY_DELAY=${RETRY_DELAY}"
        echo "RETRY_MAX_TIME=${RETRY_MAX_TIME}"
        echo "DEBUG_MODE=${DEBUG_MODE}"
        echo "MATCH_BY=${MATCH_BY}"
    } > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
}

# Function to initialize/load configuration
initialize_config() {
    if [ -f "$CONFIG_FILE" ]; then
        echo "Loading existing configuration..."
        source "$CONFIG_FILE"
    fi

    # Set defaults for any missing values
    CONNECT_TIMEOUT=${CONNECT_TIMEOUT:-$DEFAULT_CONNECT_TIMEOUT}
    MAX_TIME=${MAX_TIME:-$DEFAULT_MAX_TIME}
    RETRY=${RETRY:-$DEFAULT_RETRY}
    RETRY_DELAY=${RETRY_DELAY:-$DEFAULT_RETRY_DELAY}
    RETRY_MAX_TIME=${RETRY_MAX_TIME:-$DEFAULT_RETRY_MAX_TIME}
    DEBUG_MODE=${DEBUG_MODE:-false}

    # Prompt for API settings if missing
    if [ -z "$API_KEY" ] || [ -z "$TAILNET_ORG" ]; then
        get_config_values
    fi

    update_config_file
}

# Check if config file exists
if [ -f "$CONFIG_FILE" ]; then
    echo "Config file found. Loading existing configuration..."
    source "$CONFIG_FILE"
    # Validate and prompt for any missing values
    get_config_values
else
    echo "Welcome to the Tailscale Auto-Posture!"
    echo "This script will automatically tag hosts in Tailscale based on their name."
    get_config_values
fi

# Verify we have both values
if [ -z "$API_KEY" ] || [ -z "$TAILNET_ORG" ]; then
    echo "Error: Missing required configuration values"
    exit 1
fi

# Main menu loop
while true; do
    show_menu
    read choice

    case $choice in
        1)
            list_devices
            ;;
        2)
            echo -n "Do you want to start auto-tagging? (y/n): "
            read start_tagging
            if [[ "$start_tagging" =~ ^[Yy] ]]; then
                echo -e "\nChoose tagging type:"
                echo "1. ACL Tags"
                echo "2. Custom Attributes"
                read -p "Enter choice (1-2): " tag_type
                
                case $tag_type in
                    1)
                        collect_custom_values
                        collect_tags
                        apply_tags
                        ;;
                    2)
                        collect_custom_values
                        collect_custom_attributes
                        apply_attributes
                        ;;
                    *)
                        echo "Invalid choice"
                        ;;
                esac
                echo -e "\nAuto-tagging process complete!"
            fi
            ;;
        3)
            update_api_settings
            ;;
        4)
            update_connection_settings
            ;;
        5)
            if [ "$DEBUG_MODE" = true ]; then
                DEBUG_MODE=false
                echo "Debug mode disabled"
            else
                DEBUG_MODE=true
                echo "Debug mode enabled"
            fi
            update_config_file
            ;;
        0)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option"
            ;;
    esac
done
