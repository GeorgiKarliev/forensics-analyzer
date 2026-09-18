#!/bin/bash

# Student name: Georgi Karliev
# Student code: s4
# Class code: TCB-2506
# Lecturers: Ivan Blagoev, Yuri Tsenkov

# Colors for better terminal output
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

function BANNER()
{
    # Display an ASCII banner when the script starts
    # Banner idea inspired by Rotem Bacal/R0t3m's GhostLogin project post on LinkedIn
    # Credit: https://www.linkedin.com/posts/rotembacal_i-built-an-automated-python-script-as-part-activity-7463850296725733376-lHHE
    echo -e "${CYAN}"
    cat << "EOF"
     _                _                       
    / \   _ __   __ _| |_   _ _______ _ __    
   / _ \ | '_ \ / _` | | | | |_  / _ \ '__|   
  / ___ \| | | | (_| | | |_| |/ /  __/ |      
 /_/   \_\_| |_|\__,_|_|\__, /___\___|_|      
                        |___/                 
EOF
    echo -e "${YELLOW}                         Forensics Analyzer by B3awrot${NC}"
    echo ""
}

function START()
{
    # Save the start time of the analysis
    START_TIME=$(date)

    # Check if the script is running as root
    if [ "$(whoami)" != "root" ]
    then
        echo -e "${RED}[!] Must run as root. Exiting the script.${NC}"
        exit
    fi

    # Ask the user to enter the file that will be analyzed
    read -p "[*] Enter the filename you want to analyze: " FILE

    # Check if the entered file exists
    if [ -f "$FILE" ]
    then
        echo -e "${GREEN}[+] File exists: $FILE${NC}"
    else
        echo -e "${RED}[!] File does not exist. Exiting.${NC}"
        exit
    fi
}

function CREATE_OUTPUT_DIR()
{
    # Create a unique output directory using the current date and time
    OUTPUT_DIR="Analysis_Results_$(date +%Y%m%d_%H%M%S)"
    mkdir "$OUTPUT_DIR"

    # Create the report file inside the output directory
    REPORT="$OUTPUT_DIR/report.txt"

    echo -e "${GREEN}[+] Output directory created: $OUTPUT_DIR${NC}"

    # Write basic information about the analysis in the report
    echo "Simple Forensic Analyzer Report" > "$REPORT"
    echo "================================" >> "$REPORT"
    echo "Analyzed file: $FILE" >> "$REPORT"
    echo "Start time: $START_TIME" >> "$REPORT"
    echo "" >> "$REPORT"
}

function FILE_HASH()
{
    # Calculate SHA-256 hash of the analyzed file for integrity checking
    echo -e "${CYAN}[*] Calculating SHA-256 file hash...${NC}"

    # Save the SHA-256 hash into a separate file
    sha256sum "$FILE" > "$OUTPUT_DIR/file_hash.txt"

    echo -e "${GREEN}[+] SHA-256 file hash saved in: $OUTPUT_DIR/file_hash.txt${NC}"

    # Add the hash file location to the report
    echo "" >> "$REPORT"
    echo "File hash: $OUTPUT_DIR/file_hash.txt" >> "$REPORT"
}

function INSTALL_TOOLS()
{
    # Install or check the required forensic tools
    echo -e "${CYAN}[*] Installing/checking required tools...${NC}"

    # Update package information and save the output in a log file
    apt-get update > "$OUTPUT_DIR/install_log.txt" 2>&1

    # binutils contains the strings command
    # foremost, binwalk and bulk-extractor are used for file carving and extraction
    # zip is used to compress the final results
    apt-get install -y binutils foremost binwalk bulk-extractor zip >> "$OUTPUT_DIR/install_log.txt" 2>&1

    echo -e "${GREEN}[+] Tools are installed/checked.${NC}"

    # Save information about installed/checked tools in the report
    echo "" >> "$REPORT"
    echo "Tools installed/checked: binutils, foremost, binwalk, bulk-extractor, zip" >> "$REPORT"
    echo "Install log: $OUTPUT_DIR/install_log.txt" >> "$REPORT"
}

function RUN_CARVERS()
{
    # Run different file carving tools to extract files from the image
    echo -e "${MAGENTA}========== FILE CARVING ==========${NC}"
    echo -e "${CYAN}[*] Running carving tools...${NC}"

    # Create a directory for carving results
    mkdir "$OUTPUT_DIR/carving"

    # Run Foremost to extract files based on headers and footers
    echo -e "${CYAN}[*] 1. Running foremost...${NC}"
    foremost -i "$FILE" -o "$OUTPUT_DIR/carving/foremost" > /dev/null 2>&1

    # Run Binwalk to search for and extract embedded files
	# Binwalk command inspired by Rotem Bacal / R0t3m,
	# because I had issues making Binwalk extract correctly with root privileges.
	# Credit: https://github.com/R0t3m/Windows-Forensics-Project---Analyzer/blob/main/Analyzer.sh
    echo -e "${CYAN}[*] 2. Running binwalk...${NC}"
    binwalk -e -C "$OUTPUT_DIR/carving/binwalk" --run-as=root "$FILE" > /dev/null 2>&1

    # Run Bulk Extractor to extract forensic artifacts from the file
    echo -e "${CYAN}[*] 3. Running bulk_extractor...${NC}"
    bulk_extractor -o "$OUTPUT_DIR/carving/bulk_extractor" "$FILE" > /dev/null 2>&1

    echo -e "${GREEN}[+] File carving finished.${NC}"

    # Save carving result locations in the report
    echo "" >> "$REPORT"
    echo "File carving results:" >> "$REPORT"
    echo "Foremost: $OUTPUT_DIR/carving/foremost" >> "$REPORT"
    echo "Binwalk: $OUTPUT_DIR/carving/binwalk" >> "$REPORT"
    echo "Bulk Extractor: $OUTPUT_DIR/carving/bulk_extractor" >> "$REPORT"
}

function FIND_NETWORK_TRAFFIC()
{
    # Search for extracted network traffic files
    echo -e "${MAGENTA}========== NETWORK TRAFFIC ==========${NC}"
    echo -e "${CYAN}[*] Searching for network traffic file...${NC}"

    # Bulk Extractor usually saves extracted traffic as packets.pcap
    location=$(find "$OUTPUT_DIR" -type f -name "packets.pcap" 2>/dev/null | head -n 1)

    echo "" >> "$REPORT"
    echo "Network Traffic:" >> "$REPORT"

    # Check if packets.pcap was found
    if [ -f "$location" ]
    then
        # Get the name and size of the network traffic file
        pcap_name=$(basename "$location")
        size=$(du -h "$location" | cut -f1)

        # Display network traffic file information to the user
        echo -e "${GREEN}[+] Network traffic file found.${NC}"
        echo -e "${YELLOW}Name: $pcap_name${NC}"
        echo -e "${YELLOW}Location: $location${NC}"
        echo -e "${YELLOW}Size: $size${NC}"

        # Save network traffic file information in the report
        echo "Network traffic file found." >> "$REPORT"
        echo "Name: $pcap_name" >> "$REPORT"
        echo "Location: $location" >> "$REPORT"
        echo "Size: $size" >> "$REPORT"
    else
        # Inform the user and the report if no network traffic file was found
        echo -e "${RED}[-] Network traffic not found.${NC}"
        echo "Network traffic not found." >> "$REPORT"
    fi
}

function RUN_STRINGS()
{
    # Extract and search human-readable strings from the analyzed file
    echo -e "${MAGENTA}========== STRINGS ANALYSIS ==========${NC}"
    echo -e "${CYAN}[*] Running strings analysis...${NC}"

    # Create a directory for strings results
    mkdir "$OUTPUT_DIR/strings"

    # Search for interesting strings and save them into separate files
    strings "$FILE" | grep -i "exe" > "$OUTPUT_DIR/strings/Strings_exe.txt"
    strings "$FILE" | grep -i "password" > "$OUTPUT_DIR/strings/Strings_password.txt"
    strings "$FILE" | grep -i "username" > "$OUTPUT_DIR/strings/Strings_username.txt"
    strings "$FILE" | grep -i "user" > "$OUTPUT_DIR/strings/Strings_user.txt"
    strings "$FILE" | grep -i "http" > "$OUTPUT_DIR/strings/Strings_http.txt"

    # Search for email addresses using a regular expression
    strings "$FILE" | grep -E "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}" > "$OUTPUT_DIR/strings/Strings_email.txt"

    echo -e "${GREEN}[+] Strings analysis finished.${NC}"

    # Save strings result file locations in the report
    echo "" >> "$REPORT"
    echo "Strings Analysis:" >> "$REPORT"
    echo "EXE strings: $OUTPUT_DIR/strings/Strings_exe.txt" >> "$REPORT"
    echo "Passwords: $OUTPUT_DIR/strings/Strings_password.txt" >> "$REPORT"
    echo "Usernames: $OUTPUT_DIR/strings/Strings_username.txt" >> "$REPORT"
    echo "Users: $OUTPUT_DIR/strings/Strings_user.txt" >> "$REPORT"
    echo "HTTP/URLs: $OUTPUT_DIR/strings/Strings_http.txt" >> "$REPORT"
    echo "Emails: $OUTPUT_DIR/strings/Strings_email.txt" >> "$REPORT"
}

function RUN_VOLATILITY()
{
    # Run Volatility memory analysis
    echo -e "${MAGENTA}========== VOLATILITY ANALYSIS ==========${NC}"
    echo -e "${CYAN}[*] Running Volatility analysis...${NC}"

    # Create a directory for Volatility results
    mkdir "$OUTPUT_DIR/volatility"

    echo "" >> "$REPORT"
    echo "Volatility Analysis:" >> "$REPORT"

    # Use local Volatility executable called vol
    VOL="./vol"

    # Check if the local Volatility file exists
    if [ ! -f "$VOL" ]
    then
        echo -e "${RED}[!] Volatility file ./vol not found.${NC}"
        echo "Volatility file ./vol not found." >> "$REPORT"
        return
    fi

    # Run imageinfo to check if the file can be analyzed and to find the memory profile
    echo -e "${CYAN}[*] Checking if the file can be analyzed with Volatility...${NC}"
    "$VOL" -f "$FILE" imageinfo > "$OUTPUT_DIR/volatility/imageinfo.txt" 2>&1

    # Extract the first suggested Volatility profile from the imageinfo output
    PROFILE=$(grep "Suggested Profile" "$OUTPUT_DIR/volatility/imageinfo.txt" | cut -d ":" -f2 | cut -d "," -f1 | xargs)

    # If no profile is found, skip the rest of the Volatility analysis
    if [ "$PROFILE" = "" ]
    then
        echo -e "${RED}[!] Profile not found.${NC}"
        echo "Profile not found." >> "$REPORT"
        return
    fi

    # Display and save the detected memory profile
    echo -e "${GREEN}[+] Profile found: $PROFILE${NC}"
    echo "Profile: $PROFILE" >> "$REPORT"

    # Extract running processes from the memory dump
    echo -e "${CYAN}[*] Extracting running processes...${NC}"
    "$VOL" -f "$FILE" --profile="$PROFILE" pslist > "$OUTPUT_DIR/volatility/pslist.txt" 2>&1

    # Extract network connections from the memory dump
    echo -e "${CYAN}[*] Extracting network connections...${NC}"
    "$VOL" -f "$FILE" --profile="$PROFILE" connscan > "$OUTPUT_DIR/volatility/connscan.txt" 2>&1

    # Extract registry hive information from the memory dump
    echo -e "${CYAN}[*] Extracting registry information...${NC}"
    "$VOL" -f "$FILE" --profile="$PROFILE" hivelist > "$OUTPUT_DIR/volatility/hivelist.txt" 2>&1

    # Save Volatility result locations in the report
    echo "Imageinfo saved in: $OUTPUT_DIR/volatility/imageinfo.txt" >> "$REPORT"
    echo "Running processes saved in: $OUTPUT_DIR/volatility/pslist.txt" >> "$REPORT"
    echo "Network connections saved in: $OUTPUT_DIR/volatility/connscan.txt" >> "$REPORT"
    echo "Registry information saved in: $OUTPUT_DIR/volatility/hivelist.txt" >> "$REPORT"

    echo -e "${GREEN}[+] Volatility analysis finished.${NC}"
}

function FINAL_STATISTICS()
{
    # Create and display final statistics about the analysis
    echo -e "${MAGENTA}========== FINAL STATISTICS ==========${NC}"
    echo -e "${CYAN}[*] Creating final statistics...${NC}"

    # Save the end time and count all files created in the output directory
    END_TIME=$(date)
    FOUND_FILES=$(find "$OUTPUT_DIR" -type f | wc -l)

    # Display statistics to the user
    echo -e "${YELLOW}Start time: $START_TIME${NC}"
    echo -e "${YELLOW}End time: $END_TIME${NC}"
    echo -e "${YELLOW}Number of result files: $FOUND_FILES${NC}"

    # Save statistics in the report
    echo "" >> "$REPORT"
    echo "Final Statistics" >> "$REPORT"
    echo "----------------" >> "$REPORT"
    echo "Start time: $START_TIME" >> "$REPORT"
    echo "End time: $END_TIME" >> "$REPORT"
    echo "Number of result files: $FOUND_FILES" >> "$REPORT"
}

function ZIP_RESULTS()
{
    # Zip the results directory and the report
    echo -e "${MAGENTA}========== ZIP RESULTS ==========${NC}"
    echo -e "${CYAN}[*] Creating ZIP archive...${NC}"

    # Save the zip archive name in the report before creating the archive
    echo "" >> "$REPORT"
    echo "ZIP archive: $OUTPUT_DIR.zip" >> "$REPORT"

    # Create a zip archive from the whole output directory
    zip -r "$OUTPUT_DIR.zip" "$OUTPUT_DIR" > /dev/null 2>&1

    echo -e "${GREEN}[+] ZIP archive created: $OUTPUT_DIR.zip${NC}"
}

function MAIN()
{
    # Run all functions in the correct order
    BANNER
    START
    CREATE_OUTPUT_DIR
    FILE_HASH
    INSTALL_TOOLS
    RUN_CARVERS
    FIND_NETWORK_TRAFFIC
    RUN_STRINGS
    RUN_VOLATILITY
    FINAL_STATISTICS
    ZIP_RESULTS

    # Display final result locations
    echo -e "${MAGENTA}========== ANALYSIS COMPLETED ==========${NC}"
    echo -e "${GREEN}[+] Analysis finished successfully.${NC}"
    echo -e "${YELLOW}Results directory: $OUTPUT_DIR${NC}"
    echo -e "${YELLOW}Report file: $REPORT${NC}"
    echo -e "${YELLOW}ZIP archive: $OUTPUT_DIR.zip${NC}"
}

# Start the script
MAIN
