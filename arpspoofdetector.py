import os
import time
from datetime import datetime

# This function retrieves the ARP table and stores it in a dictionary for maniuplation
def get_arp_table():
    # Variable to store IP/MAC pairs
    arp_table = {}
    # Variable to retrieve ARP table from OS
    command_output = os.popen("arp -a").read()
    command_output_line = command_output.splitlines()
    # Iterating through the input to identify certain parts of the table
    for line in command_output_line:
        # Removing broadcast IP/MAC combos from the table, using the broadcast MAC
        if "ff-ff-ff-ff-ff-ff" in line:
            continue
        # Using indexing to number the lines and take the first two lines out of the table
        # First line identifies the interface; second line displays the table headers
        elif command_output_line.index(line) > 2:
            #Splitting the input into the three datatypes and assigning variables to them
            ip,mac,_type = line.split()
            arp_table[ip] = mac
        
    return arp_table

# This function takes the dictionary returned from the first function, identifies duplicate MAC
# address resulting from the ARP spoof, and stores that address in the duplicates dictionary  
def check_duplicates(arp_table):
    # Create a list for the identified duplicates from the ARP table
    duplicates = {}
    for ip,mac in arp_table.items():
        # Iterates through table to find duplicate MAC addresses
        if mac not in duplicates:
            duplicates[mac] = [ip]
        else:
            duplicates[mac].append(ip)
        print(duplicates.keys())
        break
        
    return duplicates

# This function logs the spoofed MAC address, as well as the date and time of the spoof, in a
# separate file
def log_spoof(duplicates):
    with open("spoof_log.txt", "a") as file:
        for mac in duplicates:
            # Logging the time the ARP spoof occurred and providing notification
            current_datetime = datetime.now()
            file.write(f"Arp Spoofed!\nThe address is: {mac}\nDate: {current_datetime}\n")
    return log_spoof

# Everything declared in the main function to run the program
def main():
    arp_table = get_arp_table()
    duplicates = check_duplicates(arp_table)
    log_spoof(duplicates)

# Adding execution control to make sure the program is executed only if the file is directly executed
if __name__ == "__main__":
    main()
