import pyshark
import socket
import psutil
import subprocess
import os
import datetime
from datetime import timedelta
import sys
import re

dizin = f"{os.getcwd()}/"    #Default value for folder.
fileConfig = f"{dizin}config.txt"
listenDuration = 5  #Default listening value of 5 seconds.
oldResultTimeout = 2592000   #Default time to disregard existing Virustotal result of 30 days.

def inputParser(input, inputName, inputType, delimeterIndex, durationCheck):    #Parses input from config.txt. If the input part is invalid, exits the program.
    timeList = ["s", "m", "h", "d"]
    timeMultiplier = 1
    print (f"Input: {input}")   #Debug
    print (f"Input Name: {inputName}")  #Debug
    print (f"Input Type: {inputType}")  #Debug
    print (f"Delimeter index: {delimeterIndex}")  #Debug
    print (f"Duration check: {durationCheck}")  #Debug
    #Calculate the duration unit and the equal sign position to correctly parse the input.
    if durationCheck == "duration":
        equalsSign = delimeterIndex+3
        if input[equalsSign-2] == "m":
            timeMultiplier = 60
        elif input[equalsSign-2] == "h":
            timeMultiplier = 3600
        elif input[equalsSign-2] == "d":
            timeMultiplier = 86400
        elif input[equalsSign-2] != "s":    #Wrong input for duration (correct ones are s,m,h,d)
            print (f"Wrong input for {inputName}: input {input} that has duration defined in it has has wrong duration denoter: the duration can only be s,m,h,d; exiting program. Please change the values from the config file.")
            logAction ("system", "inputError", fileConfig, inputName, "doesn't have the correct time denoter (s, m, h, d) inside paranteses")
            sys.exit(1)        
    else:
        equalsSign = delimeterIndex
    parsedInput = input[(equalsSign+1):].strip()

    print (f"Parsed input: {parsedInput}")  #Debug
    commaCount = parsedInput.count(",")
    parantesesCount = parsedInput.count("\"")

    #Input cheking to see if everything in config.txt is correctly written.
    if inputType == "number" and not parsedInput.isnumeric():
        print (f"Wrong input for {inputName}: parsed input {parsedInput} has been found to contain non-number characters; exiting program. Please change the values from the config file.")
        logAction ("system", "inputError", fileConfig, inputName, "has non-numbers when it shouldn't have")
        sys.exit(1)
    elif inputType == "list" and parantesesCount != ((commaCount+1)*2): #List elements are separated by , and defined by encircled by paranteses like "*company1","*company2" . Paranteses count should be double the number of elements, which is comma_count+1
        print (f"Wrong input for {inputName}: parsed input {parsedInput} has been found to contain the wrong number of paranteses ({parantesesCount}) and commas ({commaCount}), indicating wrong input. Please change the values from the config file.")
        logAction ("system", "inputError", fileConfig, inputName, "has wrong amount of paranteses and commas")
        sys.exit(1)
    elif durationCheck == "duration" and input[equalsSign-3] != "(" and input[equalsSign-1] != ")":
        print (f"Wrong input for {inputName}: input {input} that has duration defined in it has has wrong syntax: the duration should be enclosed by parantheses like (s); exiting program. Please change the values from the config file.")
        logAction ("system", "inputError", fileConfig, inputName, "doesn't have paranteses at correct locations (example: (s)) when it should have")
        sys.exit(1)        
    elif "=" != input[equalsSign]:
        print (f"Wrong input for {inputName}: input {input} doesn't have = sign or has it at the correct index (just before input); exiting program. Please change the values from the config file.)")
        logAction ("system", "inputError", fileConfig, inputName, "doesn't have a = sign when it should have")
        sys.exit(1)
    else:   #Successful input, return the requested input
        if inputType == "number":   #For numbers, multiply by time multiplier, which is 1 for no duration.
            output = int(parsedInput)*timeMultiplier
        elif inputType == "list":   #For list, create a list for output.
            parsedList = parsedInput.split("\"")   #List looks like [',', 'great', ',', 'antivir', ',', 'avira', '']
            for element in parsedList:
                if len(element)>=2: #Discard the 0 and 1 length elements like '' and ','
                    output.append(element)
            print (f"The list output is: {output}") #Debug
        elif inputType == "text":
            output = parsedInput
        return output

def folderChecker(folder):  #Creates required folders.
    if not os.path.exists(folder): 
        timestamp = timestampFunc("timestamp")
        try:
            os.makedirs(folder)
            logAction("system", "directoryCreate", folder, "NULL", "NULL")
            print (f"{folder} created.")  #Debug
        except OSError as e:
            print(f"Error creating directory '{logPath}': {e}")
            print (f"{timestamp} Error creating directory '{logPath}': {e}. Exiting program.")
            sys.exit(1)

def timestampFunc(mode):
    dateNow = datetime.datetime.now()
    if mode == "timestamp":        
        dateFile = f"[{dateNow}]"
    elif mode == "filename":
        dateFile = dateNow.strftime("%Y-%m-%d")
    elif mode == "report":
        dateFile = dateNow.strftime("%Y-%m-%d_%H-%M-%S")
    return dateFile

def timestampExtractor(line):   #To extract timestamp from already existing log lines.
    timestampEvent = re.findall(r'\[(.*?)\]', line).strip() #Regex to get everything between [ and ]
    return timestampEvent

def timestampExpiredCheck(timestampOld, timestampNew):   #Example timestamp: 2023-08-14 02:29:17.217915
    format = "[%Y-%m-%d %H:%M:%S.%f]"
    old = datetime.strptime(timestampOld, format)
    new = datetime.strptime(timestampNew, format)
    pastTime = new - old
    if pastTime.seconds > oldResultTimeout:
        return True
    else:
        return False

def deleteMatchingLine(fileName, match): #Used to delete past timestamp lines from lists.
    lineNo = 0
    with open(fileName, "r") as file:
        lines = file.readlines()   
    for line in lines:
        lineNo+=1
        if match in line:
            del lines[lineNo]   #Delete the requested line.
            logAction("system", "deletedLine", fileName, line, lineNo)
    with open(fileName, "w") as file:
        file.writelines(lines)  #Overwrite the file without the deleted line.

def appendToFiles(fileList, sentence):
    print ("File list outside loop:", fileList) #Debug
    print ("Sentence list outside loop: ", sentence) #Debug
    for file in fileList:
        print ("File appending:", file)    #Debug
        with open(file, "a") as currentFile:
            currentFile.write(f"{sentence}")

def logAction(logType, logSubtype, IPSource, IPDestination, param):
    timestamp = timestampFunc("timestamp")
    dayDate = timestampFunc("filename")
    fileLogDaily = f"{logPath}{dayDate}_log.txt"
    fileLogType = ""
    logSentence = ""

    if logType == "packetList":
        fileLogType = f"{listPath}list_packet.txt"
        fileList = [fileLogType, fileLogAll, fileLogDaily]
        print (f"File list is: {fileList}")
        if logSubtype == "IPFound":
            logSentence = f"{timestamp} (packetList) (IPFound) IP detected in packet #{param}. Source IP: {IPSource} and Destination IP: {IPDestination}\n"
        elif logSubtype == "streamStart":  #Special case to denote new packet stream with IP in it.
            logSentence = f"{timestamp} (packetList) (streamStart) New stream packet processing started. There are {param} packets in the stream.\n"
        elif logSubtype == "noIP":
            logSentence = f"{timestamp} (packetList) (noIP) No IP's detected in packet #{param}.\n"
        else:
            print (f"Error: reached undefined logging with keyword {logSubtype}. Action has been logged.")
            fileLogType = f"{logPath}system_log.txt"
            logSentence = f"{timestamp} (system) (undefinedLogCommand) Undefined log command, beware! {logType}, {logSubtype}, {IPSource}, {IPDestination}, {param}\n"

    elif logType == "IPList":
        fileLogType = f"{listPath}list_IP.txt"
        fileList = [fileLogType, fileLogAll, fileLogDaily]
        if logSubtype == "safe" or logSubtype == "suspicious" or logSubtype == "malicious":
            logSentence = f"{timestamp} (IPList) ({logSubtype}) Destination IP {IPDestination} was checked previously at [{param}] and was found to be {logSubtype}. Packet source IP: {IPSource}\n"
        elif logSubtype == "IPAdded":
            logSentence = f"{timestamp} (IPList) (IPAdded) New IP {IPDestination} is being added to the Virustotal check list {fileIPOutput}. Packet source IP: {IPSource}\n"
        elif logSubtype == "duplicateIP":
            logSentence = f"{timestamp} (IPList) (duplicateIP) Current IP {IPDestination} is already in the IP output list {fileIPOutput} Packet source IP: {IPSource}\n"
        elif logSubtype == "packetsOutsideNetwork": #Both packets are outside the network.
            logSentence = f"{timestamp} (IPList) (packetsOutsideNetwork) Both source IP {IPSource} and destination IP {IPDestination} are outside the network IP {param}. Adding both to Virustotal script.\n"
        else:
            print (f"Error: reached undefined logging with keyword {logSubtype}. Action has been logged.")
            fileLogType = f"{logPath}system_log.txt"
            logSentence = f"{timestamp} (system) (undefinedLogCommand) Undefined log command, beware! {logType}, {logSubtype}, {IPSource}, {IPDestination}, {param}\n"

    elif logType == "networkList":
        fileLogType = f"{listPath}list_network.txt"
        fileList = [fileLogType, fileLogAll, fileLogDaily]
        if logSubtype == "networkIP": #New network IP added to the list.
            logSentence = f"{timestamp} (IPList) (networkIP) New network IP {IPSource} is being added to the network list {fileIPNetwork}\n"
        elif logSubtype == "networkIPResult":
            logSentence = f"{timestamp} (system) (networkIPResult) IP's in the connected network that received or sent IP packets are: {IPSource}\n"
        elif logSubtype == "hostIP":
            logSentence = f"{timestamp} (system) (ownerIP) Host network IP {IPSource} is being added to the network list {fileIPNetwork}\n"
        else:
            print (f"Error: reached undefined logging with keyword {logSubtype}. Action has been logged.")
            fileLogType = f"{logPath}system_log.txt"
            logSentence = f"{timestamp} (system) (undefinedLogCommand) Undefined log command, beware! {logType}, {logSubtype}, {IPSource}, {IPDestination}, {param}\n"


    elif logType == "system":   #IP parameter is used to pass the type of system log information.
        fileLogType = f"{logPath}system_log.txt"
        if logSubtype == "start": 
            logSentence = f"{timestamp} (system) (start) Network script started with computer {IPSource} with main directory: {IPDestination}\n"
        elif logSubtype == "finish":  #End of program
            logSentence = f"{timestamp} (system) (finish) All {packetTotal} packets are processed; {safeCount} are known to be safe, {suspiciousCount} are known to be suspicious, {maliciousCount} are known to be malicious.\n{timestamp} (system) (finish) Quitting the Packetparser script and starting the Virustotal script.\n"
        elif logSubtype == "findNetworkIP": #IPOwner, IPNetwork, subnetTotal
            logSentence = f"{timestamp} (system) (networkInfo) Network information gathered. Host IP is: {IPSource} Network IP is: {IPDestination} and Network subnet is: {param}\n"
        elif logSubtype == "interfaceFound": 
            logSentence = f"{timestamp} (system) (interfaceFound) Network interface is found as {param}.\n"
        elif logSubtype == "deletedLine":   #IPSource is fileName, IPDestination is line content, param is line number.
            logSentence = f"{timestamp} (system) (deletedLine) Deleted line #{param} ({IPDestination}) from file: {IPSource}\n"
        elif logSubtype == "deleteExpiredResult":
            logSentence = f"{timestamp} (system) (deleteExpiredResult) Deleted expired result of {IPSource} from file: {param}\n"
        elif logSubtype == "interfaceMissing":  #Special case: program ends after logging due to no network interface being found.
            logSentence = f"{timestamp} (system) (interfaceMissing) No network interfaced found, closing program.\n"
        elif logSubtype == "noPackets": #Special case: program ends after logging due to no network packets being captured.
            logSentence = f"{timestamp} (system) (noPackets) There are no packets found in the capture, quitting program.\n"
        elif logSubtype == "inputError": #Special case: program ends after logging due to faulty input.
            logSentence = f"{timestamp} (system) (inputError) Input acquired from {IPSource} for {IPDestination} {param}; quitting program.\n"
        elif logSubtype == "reportPrepared":
            logSentence = f"{timestamp} (system) (reportPrepared) Report for the capture prepared and can be found at {param}\n" 
        else:
            logSentence = f"{timestamp} (system) (undefinedLogCommand) Undefined log command, beware! {logType}, {logSubtype}, {IPSource}, {IPDestination}, {param}\n"

                   
    fileList = [fileLogType, fileLogAll, fileLogDaily]
    appendToFiles(fileList, logSentence)

with open(fileConfig, 'r') as configFile:   #Reads valid lines in config file, if there are any. config.txt must be in the same folder as script! Durations are all returned in seconds. 
    for line in configFile:
        if "directory" == line[0:9]:
            dizin = inputParser(line.strip(), "directory", "text", 9, "noDuration")
        elif "listenDuration" == line[0:14]:
            listenDuration = int(inputParser(line.strip(), "listenDuration", "number", 14, "duration"))
        elif "oldResultTimeout" == line[0:16]:
            oldResultTimeout = int(inputParser(line.strip(), "oldResultTimeout", "number", 16, "duration"))

#Initialize variables and parameters.
packetNo = 0
safeCount = 0
suspiciousCount = 0
maliciousCount = 0
undetectedCount = 0
toBeCheckedCount = 0
duplicateCount = 0
#Define file paths
logPath = f"{dizin}log/"
listPath = f"{dizin}list/"
reportPath = f"{dizin}reports/"
fileAPI = f"{dizin}listAPI.txt"
fileIPOutput = f"{dizin}virustotalInputIP.txt"  #This program's output IP is virustotal's input IP.
fileIPInput = f"{dizin}virustotalOutputIP.txt"  #Check if IP is inside this file (already checked or not).
fileIPNetwork = f"{listPath}list_network"
fileLogAll = f"{logPath}all_log.txt"
fileLogsystem = f"{logPath}system_log.txt"
outputIP= f"{dizin}outputReport.txt"
#Network related data
hostnameOwner = socket.gethostname()
IPOwner = socket.gethostbyname(hostnameOwner)
IPNetworkList=[IPOwner]    #Computers in the network, including host.
logAction("networkList", "hostIP", IPOwner, "NULL", "NULL")
IPNetworkSide = ""

#Both files should exist (even as empty files) for no errors to occur during file readings.
if not os.path.exists(fileIPOutput):
    file = open(fileIPOutput, "w")
    file.close()
file = open(fileIPOutput, "w")  #Reset the IP Output for virustotal file.
file.close()


folderChecker(logPath)
folderChecker(listPath)
folderChecker(reportPath)

logAction("system", "start", hostnameOwner, dizin, "NULL")

def IPChecker(IPCurrent, IPNetwork):   #Sorts packet IP's into results.
    print (f"IPChecker function reached with {IPCurrent} and {IPNetwork}")  #Debug
    global safeCount, suspiciousCount, maliciousCount, toBeCheckedCount, duplicateCount
    timestamp = timestampFunc("timestamp")
    with open(fileIPInput, "r") as checkedIPList:
        checkedIPLines = checkedIPList.readlines()
    with open(fileIPOutput, "r") as outputIPList:    #Will be virustotal input file
        outputIPLines = outputIPList.readlines()

    if IPCurrent in checkedIPLines:  #If IP is already checked by virustotal.
        print (f"{IPCurrent} already found to be checked by Virustotal before.")    #Debug
        for line in checkedIPLines:  #Example line: [2023-08-13 23:05:13.980864] (IPResult) 104.21.13.119 is safe.
            if IPCurrent in line:   #We find the line of the match.
                timestampEvent = timestampExtractor(line)   #Extract the timestamp from the log.
                if timestampExpiredCheck(timestampEvent, timestamp) == True:    #If timestamp has expired.
                    deleteMatchingLine(fileIPInput, IPCurrent)  #Delete expired result.
                    logAction("system", "deleteExpiredResult", IPCurrent, "NULL", fileIPInput)
                    #Delete line from the lists.
                    if "safe" in line:
                        deleteMatchingLine(f"{listPath}list_safe.txt", IPCurrent)
                        logAction("system", "deleteExpiredResult", IPCurrent, "NULL", f"{listPath}list_safe.txt")
                    elif "suspicious" in line:
                        deleteMatchingLine(f"{listPath}list_suspicious.txt", IPCurrent)
                        logAction("system", "deleteExpiredResult", IPCurrent, "NULL", f"{listPath}list_suspicious.txt")
                    elif "malicious" in line:
                        deleteMatchingLine(f"{listPath}list_malicious.txt", IPCurrent)
                        logAction("system", "deleteExpiredResult", IPCurrent, "NULL", f"{listPath}list_malicious.txt")
                    else:
                        print ("Undefined delete action taken, cancelled.")
                        logAction("system", "undefinedLogCommand", "NULL", "NULL", "NULL")

                elif "safe" in line:
                    safeCount+=1
                    logAction("IPList", "safe", IPNetwork, IPCurrent, timestampEvent)   
                elif "suspicious" in line:
                    logAction("IPList", "suspicious", IPNetwork, IPCurrent, timestampEvent)   
                    suspiciousCount+=1
                elif "malicious" in line:
                    maliciousCount+=1
                    logAction("IPList", "malicious", IPNetwork, IPCurrent, timestampEvent)   
    
    elif f"{IPCurrent}\n" in outputIPLines:   #If IP is a duplicate of a previous IP that's already in the virustotal check IP list.
        print (f"{IPCurrent} already exists in {fileIPOutput} as a duplicate.")
        duplicateCount+=1
        logAction("IPList", "duplicateIP", IPNetwork, IPSource, "NULL")
    else:   #If IP not checked by virustotal yet and not in the output file (to prevent repeat cases).
        toBeCheckedCount+=1
        print (f"{IPCurrent} not found inside the output list {outputIPLines} and is being added to Virustotal check list.")
        listSentence = f"{IPCurrent}\n"
        appendToFiles([fileIPOutput], listSentence)
        logAction("IPList", "IPAdded", IPCurrent, IPNetwork, "NULL")  
        

def findInterface():    #Used to get the interface name of connection to be used in pyhsark.
    print(f"Hostname: {hostnameOwner}")  #Debug
    print(f"IP Address: {IPOwner}")  #Debug
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.address == IPOwner:
                print(f"Currently connected to the interface: {interface}")
                interfaceCheck = True
                logAction("system", "interfaceFound", "NULL", "NULL", interface.strip())
                return interface.strip()
    if interfaceCheck != True:
        print("No matching interface found.")
        logAction("system", "interfaceMissing", "NULL", "NULL", "NULL")
        sys.exit(1)

connectionInterface = findInterface()
print ("Connection interface:",connectionInterface)

def findNetworkIP():    #Used to determine network IP so that IP to send to virustotal can be sorted.
    ipconfigResult = subprocess.run(["ipconfig"], stdout=subprocess.PIPE, text=True).stdout
    lines = ipconfigResult.split("\n")
    subnetMask = None
    IpOwnerOctets = IPOwner.split(".")

    for line in lines:
        if "Subnet Mask" in line:
            subnetMask = line.split(":")[-1].strip()

    if subnetMask:
        subnetOctets = subnetMask.split(".")
        subnetTotal = sum(bin(int(octet))[2:].count("1") for octet in subnetOctets if octet)
        print("Subnet Octets are:", subnetOctets)
        print("Subnet Total is:", subnetTotal)

    if subnetTotal > 16:
        IPNetwork = f"{IpOwnerOctets[0]}.{IpOwnerOctets[1]}"    #Take the first 2 octets as network IP (125.12)
    elif subnetTotal > 24:
        IPNetwork = f"{IpOwnerOctets[0]}.{IpOwnerOctets[1]}.{IpOwnerOctets[2]}" #First 3 octets as network IP.
    else:  #Subnet octet is lower than 16. Very unusual.
        IPNetwork = IpOwnerOctets[0]
        print (f"Subnet mask was found to be lower than 16. Subnet mask is: {subnetMask} and subnet octet is: {subnetOctets} which resulted in network IP being {IPNetwork}")

    logAction("system", "findNetworkIP", IPOwner, IPNetwork, subnetMask)
    return IPNetwork

#Network and capture info
IPNetwork = findNetworkIP()
networkOctets = IPNetwork.split('.')    #Maybe unnecessary
networkOctetCount = len(networkOctets)  #Maybe unnecessary
print (f"Network octet count is: {networkOctetCount}")
print (f"Capturing the network packets for {listenDuration} seconds.")
capture = pyshark.LiveCapture(interface=connectionInterface)
capture.sniff(timeout=listenDuration)
packets = [pkt for pkt in capture._packets]
capture.close()
packetTotal = len(packets)
if len(packets) == 0:   #End program with log action if there are no packets.
    logAction("system", "noPackets", "NULL", "NULL", "NULL")
    sys.exit(1)


###MAIN FUNCTION###
for packet in packets:
    packetNo+=1
    if packetNo == 1:
            logAction("packetList", "streamStart", "NULL", "NULL", packetTotal)  
    print(f"Packet number is: {packetNo} out of {packetTotal}")  #Debug
    print ("Packet layers are: ",packet.layers) #Debug
    if 'IP' in packet:
        networkCheck = False    #To check if both IP's are in the network or not, to skip IPChecker function.
        IPLayer = packet['IP']
        IPSource = IPLayer.src
        IPDestination = IPLayer.dst
        logAction("packetList", "IPFound", IPSource, IPDestination, packetNo)  
        print (f"Network IP is: {IPNetwork}")   #Debug
        print (f"Source IP is: {IPSource}")   #Debug
        print (f"Destination IP is: {IPDestination}")   #Debug
        if IPSource in IPNetworkList:     #One of the IP's are already in the network IP list.
            print ("Source IP already known to be inside the network.")   #Debug
            IPAddToList = IPDestination
            IPNetworkSide = IPSource
        elif IPDestination in IPNetworkList:
            print ("Destination IP already known to be inside the network.")   #Debug
            IPAddToList = IPSource
            IPNetworkSide = IPDestination
        else:   #None of the IP's are in the network IP list, network IP needs to be found and added to the list.
            if IPSource.startswith(IPNetwork) and IPDestination.startswith(IPNetwork):  #Both IP's in the network.
                print (f"Both IP's {IPSource} {IPDestination} are inside the current network.")   #Debug
                IPNetworkList.append(IPSource)
                IPNetworkList.append(IPDestination)
                logAction("networkList", "networkIP", IPSource, "NULL", "NULL")
                logAction("networkList", "networkIP", IPDestination, "NULL", "NULL")                
                networkCheck = True
            elif IPSource.startswith(IPNetwork):
                print (f"Only source IP {IPSource} is inside the current network.")   #Debug
                IPNetworkList.append(IPSource)
                logAction("networkList", "networkIP", IPSource, "NULL", "NULL")
                IPAddToList = IPDestination
                IPNetworkSide = IPSource
            elif IPDestination.startswith(IPNetwork):
                print (f"Only destination IP {IPDestination} is inside the current network.")   #Debug
                IPNetworkList.append(IPDestination)
                logAction("networkList", "networkIP", IPSource, "NULL", "NULL")
                IPAddToList = IPSource
                IPNetworkSide = IPDestination
            else:   #Both IP's not in network, send an error report.
                print (f"Both Source IP ({IPSource}) and Destination IP ({IPDestination}) are not in the network.")   #Debug
                logAction("IPList", "packetsOutsideNetwork", IPSource, IPDestination, IPNetwork)
                IPAddToList = IPDestination
                IPNetworkSide = IPSource
                IPChecker(IPSource, IPNetworkSide)

        if networkCheck == False:
            print (f"Network side IP is: {IPNetworkSide}")    
            IPChecker(IPAddToList, IPNetworkSide)

    else:
        logAction("packetList", "noIP", "NULL", "NULL", packetNo)  
        print ("Packet doesn't have IP and is skipped.")    #Debug

uniqueCount = packetTotal - duplicateCount
logAction("networkList", "networkIPResult", IPNetworkList, "NULL", "NULL")
logAction("system", "finish", safeCount, suspiciousCount, maliciousCount)  #Script finished log
print ("Network IP list is:", IPNetworkList)
print ("Script finished successfully. Starting virustotal script.")

import virustotal_api   #Virustotal script must be in the same folder as packet parser (this) script!

#Writing the report
timestampReport = timestampFunc("report")
fileReport = f"{reportPath}{timestampReport}_report_full.txt"
reportSentence = f"When checking for the first time; {safeCount} IP's are known to be safe, {suspiciousCount} IP's are known to be suspicious and {maliciousCount} IP's are known to be malicious.\nThere were {uniqueCount} unique external IP's and {duplicateCount} duplicate IP's in the data stream.\n"
appendToFiles([fileReport], reportSentence)
packetNo = 0
safeCount = 0
suspiciousCount = 0
maliciousCount = 0
undetectedCount = 0
internalCount = 0
noIPCount = 0
reportSentence = f"Host IP is: {IPOwner}\nNetwork IP's are: {IPNetworkList}\n"
appendToFiles([fileReport], reportSentence)

for packet in packets:
    packetNo+=1
    passCheck = False
    IPCheck = ""
    IPNetworkSide = ""

    #Decide which IP is going to be checked and separate internal connection packets.
    if 'IP' in packet:
        networkCheck = False    #To check if both IP's are in the network or not, to skip IPChecker function.
        IPLayer = packet['IP']
        IPSource = IPLayer.src
        IPDestination = IPLayer.dst
        print (f"Network IP is: {IPNetwork}")   #Debug
        print (f"Source IP is: {IPSource}")   #Debug
        print (f"Destination IP is: {IPDestination}")   #Debug
        if IPSource in IPNetworkList:     #One of the IP's are already in the network IP list.
            IPCheck = IPDestination
            IPNetworkSide = IPSource
        elif IPDestination in IPNetworkList:
            print ("Destination IP found to be inside the network.")   #Debug
            IPCheck = IPSource
            IPNetworkSide = IPDestination
        else:
            print("Both IP's are in the network, skipped.")
            passCheck = True
            internalCount+=1
    else:
        print ("Packet doesn't have IP and is skipped.")    #Debug
        passCheck = True
        noIPCount+=1
    print (f"Pass check is: {passCheck}") #Debug
    if passCheck == False:  #Non-internal network packet
        with open(fileIPInput, "r") as checkedIPList:
            checkedIPLines = checkedIPList.readlines()
        print (f"IP being checked is: {IPCheck}") #Debug
        for line in checkedIPLines:  #Example line: [2023-08-13 23:05:13.980864] (IPResult) 104.21.13.119 is safe.
            if IPCheck in line:   #We find the line of the match.
                print(f"{IPCheck} already found to be checked by Virustotal before.")   #Debug           
                if "safe" in line:
                    safeCount+=1
                    break
                elif "suspicious" in line:
                    suspiciousCount+=1
                    break
                elif "malicious" in line:
                    maliciousCount+=1
                    reportSentence = f"Packet number #{packetNo} is between network IP {IPNetworkSide} and malicious IP {IPCheck}\n"
                    appendToFiles([fileReport], reportSentence)
                    break
                elif "undetected" in line:
                    undetectedCount+=1
                    break
    
reportSentence = f"Total packets: {packetTotal}\nNon-IP packets: {noIPCount}\nInternal network packets: {internalCount}\nSafe packets: {safeCount}\nSuspicious packets: {suspiciousCount}\nMalicious packets: {maliciousCount}\nUndetected packets: {undetectedCount}"
appendToFiles([fileReport], reportSentence)
logAction("system", "reportPrepared", "NULL", "NULL", fileReport)
