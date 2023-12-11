import requests
import linecache
import time
import datetime
import os
import sys

#Initialize folders, file names, IP and API. Change variables (especially directory) from config file as needed.
dizin = f"{os.getcwd()}/"    #Default value for folder.
fileConfig = f"{dizin}config.txt"
maliciousThreshold = 2  #Default value for number of malicious detection for malicious result. Values with lower detection than this value will be put on suspicious list.
ignoreList = [] #Ignore no specific results as default.
detectionThreshold = 5  #Needs at least 5 results as safe, suspicious or malicious to count towards any result; will separate into a new list (undetected).

def timestampFunc(mode):
    dateNow = datetime.datetime.now()
    if mode == "timestamp":        
        dateFile = f"[{dateNow}]"
    elif mode == "filename":
        dateFile = dateNow.strftime("%Y-%m-%d")
    elif mode == "report":
        dateFile = dateNow.strftime("%Y-%m-%d_%H-%M-%S")
    return dateFile

def appendToFiles(fileList, sentence):  #Add line to list of files.
    print ("File list outside loop:", fileList) #Debug
    print ("Sentence list outside loop: ", sentence) #Debug
    for file in fileList:
        print ("File appending: ", file)    #Debug
        with open(file, "a") as currentFile:
            currentFile.write(f"{sentence}")

def deleteSingleLine(fileName, lineNo): #Used to delete past timestamp lines from lists.
    with open(fileName, "r") as file:
        lines = file.readlines()
    if lineNo > len(lines) or lineNo < 0:
        logAction("system", "invalidDeleteLine", fileName, lineNo, len(lines))
    else:
        with open(fileName, "w") as file:
            del lines[lineNo]   #Delete the requested line.
            file.writelines(lines)  #Overwrite the file without the deleted line.

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

def sleepVariable (duration, API):   #Used if virustotal API's are all unavailable.
    if duration == "minute":
        time.sleep(60)
        logAction("system", "sleep60", "60 seconds", API)
    else:
        print ("eksik")

#Log files are as follows:
#Everything log (all_log.txt), daily everything log (2023-08-08_log.txt), malicious log (log_malicious.txt)
#Suspicious log (log_suspicious.txt), safe log (log_safe.txt), system log (log_system.txt)

def logAction(logType, logSubtype, IP, param1, param2): #All logging done from this function.
    timestamp = timestampFunc("timestamp")
    dayDate = timestampFunc("filename")
    fileLogDaily = f"{logPath}{dayDate}_log.txt"
    fileLogType = ""

    if logType == "result":
        fileLogType = f"{logPath}{logSubtype}_log.txt"  #.../log/malicious_log.txt
        fileTypeList = f"{listPath}list_{logSubtype}.txt"  #.../list/list_malicious.txt
        print ("Filename:", fileTypeList)   #Debug
        listSentence = f"{timestamp} {IP}\n"
        if logSubtype == "maliciousThreshold":
            logSentence = f"{timestamp} (result) ({logSubtype}) The IP address {IP} has been found malicious by {param1} out of {param2} vendors.\n{timestamp} ({logType}) ({logSubtype}) Due to failing to pass the malicious detection threshold ({maliciousThreshold}), the IP address {IP} is being added to the known {logSubtype} list at: {fileTypeList}\n"
        elif logSubtype == "ignoredResult": #param1=ignoredCount, param2=ignoredList
            logSentence = f"{timestamp} (result) ({logSubtype}) {param1} results were ignored and deleted from the {IP} Virustotal query. The ignored results were: {param2}\n"
        elif logSubtype == "undetected":
            logSentence = f"{timestamp} ({logType}) ({logSubtype}) Due to failing to pass the detection threshold (safe+suspicious+malicious={param1}) as there were only {param2} results, the IP address {IP} is being added to the {logSubtype} list at: {fileTypeList}\n"
        elif logSubtype == "malicious":
            logSentence = f"{timestamp} ({logType}) ({logSubtype}) The IP address {IP} has been found {logSubtype} by {param1} vendors. \n"f"{timestamp} ({logType}) ({logSubtype}) The IP address {IP} is being added to the known {logSubtype} list at: {fileTypeList}\n"
        else:   #Result is suspicious or safe
            logSentence = f"{timestamp} (result) ({logSubtype}) The IP address {IP} has been found {logSubtype} by {param1} out of {param2} vendors.\n"f"{timestamp} ({logType}) ({logSubtype}) The IP address {IP} is being added to the known {logSubtype} list at: {fileTypeList}\n"
        appendToFiles([fileTypeList], listSentence)   #Just for the list.     

    elif logType == "IPAdded":  #logSubtype is type found (safe, suspicious, malicious, undetected)
            fileLogType = f"{logPath}IP_log.txt"
            IPSentence = f"{timestamp} (IPResult) {IP} is {logSubtype}.\n"
            appendToFiles([fileIPOutput], IPSentence)
            logSentence = f"{timestamp} (IPAdded) ({logSubtype}) IP:{IP} has been processed as {logSubtype} and has been added to the {fileIPOutput} file.\n"        
    
    elif logType == "system":   #IP parameter is used to pass the type of system log information.
        fileLogType = f"{logPath}system_log.txt"
        if logSubtype == "changeAPIQuota": 
            logSentence = f"{timestamp} (system) (changeAPIQuota) ({IP}) Virustotal API changed from '{param1}' to '{param2}' due to exceeding {IP} quota.\n"
        elif logSubtype == "changeAPIStart":
            if IP == "day":
                word = "daily"
            elif IP == "minute":
                word = "minute"
            logSentence = f"{timestamp} (system) (changeAPIStart) ({IP}) Reached end of the file of Virustotal API list.\n{timestamp} Virustotal API changed from '{param1}' to '{param2}' due to exceeding {word} quota.\n"
        elif logSubtype == "deletedAPI":
            logSentence = f"{timestamp} (system) (deletedAPI) Virustotal API changed from '{param1}' to '{param2}' due to previous API being invalid and thus being deleted.\n"
        elif logSubtype == "outOfBoundsAPI":    #param1 is length of API file.
            logSentence = f"{timestamp} (system) (outOfBoundsAPI) Virustotal API reset to '{param2}' (start of file) due to API file length {param1} being exceeded.\n"
        elif logSubtype == "sleep60":   #param1 is duration passed as string.
            logSentence = f"{timestamp} (system) (sleep60) Sleeping for '{param1}' due to API '{param2}' exceeding minute quota and no other API's being available.\n"
        elif logSubtype == "start":
            logSentence = f"{timestamp} (system) (start) Virustotal script started with API '{param1}'.\n"        
        elif logSubtype == "maliciousRecord":
            logSentence = f"{timestamp} (system) (maliciousRecord) Malicious result found for {IP}, full Virustotal API response is appended into {param1} \n"
        elif logSubtype == "maliciousFileCreated":
            logSentence = f"{timestamp} (system) (maliciousFileCreated) As it didn't exist and a malicious result was found with the IP {IP}, the file {param1} was created to hold the full Virustotal malicious responses for this capture.\n"
        elif logSubtype == "endOfScript":
            logSentence = f"{timestamp} (system) (endOfScript) Virustotal script finished processing all requested IP's. {param1} queries were made to Virustotal and the results were: {param2}.\n"
        elif logSubtype == "APIQuotaExceeded": #Special case: program ends after logging due to API list exhausted.
            logSentence = f"{timestamp} (system) (APIQuotaExceeded) All API's have their daily quotas spent. Ending program.'\n"
        elif logSubtype == "emptyAPIList":  #Special case: program ends after logging due to API list is empty.
            logSentence = f"{timestamp} (system) (emptyAPIList) There are no valid API's in {fileAPI} , quitting program.\n"
        elif logSubtype == "inputError": #Special case: program ends after logging due to faulty input.
            logSentence = f"{timestamp} (system) (inputError) Input acquired from {IP} for {param1} {param2}; quitting program.\n"
        elif logSubtype == "directoryCreate": 
            logSentence = f"{timestamp} (system) (directoryCreate) {IP} directory didn't exist, was created.\n"
        elif logSubtype == "websiteDown": #Special case: program ends after logging due to unreachable main website.
            logSentence == f"{timestamp} (system) (websiteDown) {IP} website couldn't be reached via ping, stopping the program.\n"
        else:
            logSentence = f"{timestamp} (system) (undefinedLogCommand) Undefined log command, beware! logSubtype: {logSubtype}, param1: {param1}, param2: {param2}\n"
    
    else:
        print ("Default log action found! Investigate situation that caused it. Ending program for safety")
        logSentence = f"{timestamp} (system) Default log action found. Unknown situation, investigate. Ending program for safety."
        fileLogType = fileLogSystem
        sys.exit(1)
    
    #Append the log sentence into the log file list.
    fileList = [fileLogType, fileLogAll, fileLogDaily]
    appendToFiles(fileList, logSentence)

def deleteLine(fileName, lineNo):
    global APIno
    with open(fileName, 'r') as file:
        lines = file.readlines()
        if lineNo<1 or lineNo>len(lines):   #Out of bounds checking
            print(f"Invalid line number. The file has {len(lines)} lines and line #{lineNo} was requested.")
            APIno = 1 #Reset the API number and start from the first API again.
            API = lines[APIno-1].strip()
            logAction("system", "outOfBoundsAPI", "NULL", len(lines), API)
            changeAPI("start")
            
        elif len(lines) <=1:   #All API are invalid, API file will be empty.
            print ("OldLines: ", lines)
            oldAPI = lines[APIno-1].strip()
            del lines[APIno - 1]   #Delete requested line from file
            with open(fileName, 'w') as APIFile:       
                APIFile.writelines(lines)   #Overwrite file without deleted line.
                print ("NewLines: ", lines)  #Debug
            print(f"All API in the APIList are invalid. Deleting last API and quitting.\n")
            logAction("system", "deletedAPI", "NULL", oldAPI, "NULL")
            logAction("system", "emptyAPIList", "NULL", oldAPI, "NULL")
            sys.exit(1)
        else:
            print ("OldLines: ", lines)
            oldAPI = lines[APIno-1].strip()
            del lines[APIno - 1]   #Delete requested line from file
            with open(fileName, 'w') as APIFile:       
                APIFile.writelines(lines)   #Overwrite file without deleted line.
                print ("NewLines: ", lines)  #Debug
            newAPI = lines[APIno-1].strip()
            logAction("system", "deletedAPI", "NULL", oldAPI, newAPI)

def changeAPI(situation):
    global APIno
    if situation == "start":    #Get initial API, first line.
        API = linecache.getline(fileAPI, APIno).strip()
        logAction("system", "start", "NULL", API, "NULL")
        return API
    elif situation == "delete": #For deleting faulty API's.
        deleteLine(fileAPI, APIno)
        API = linecache.getline(fileAPI, APIno).strip()
        #No log action needed since deleteLine does it.
        return API
    elif "next" in situation :   #Change to next API.
        with open(fileAPI, 'r') as APIFile:
            lines = APIFile.readlines()
            if (APIno+1)>len(lines):    #Check if end of the API list, go to start of API file if so.
                oldAPI = lines[APIno-1]
                APIno = 1
                newAPI = lines[0]
                logAction("system", "changeAPIStart", situation, oldAPI, newAPI)
                return API
            else:
                oldAPI = lines[APIno-1]
                newAPI = lines[APIno]
                if situation == "next-minute":
                    logAction("system", "changeAPIQuota", "minute", oldAPI, newAPI)
                elif situation == "next-day":
                    logAction("system", "changeAPIQuota", "day", oldAPI, newAPI) 
                APIno+=1
                return lines[APIno-1]

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
            outputList = []
            parsedList = parsedInput.split("\"")   #List looks like [',', 'great', ',', 'antivir', ',', 'avira', '']
            for element in parsedList:
                if len(element)>=2: #Discard the 0 and 1 length elements like '' and ','
                    outputList.append(element)
                    output = outputList
            print (f"The list output is: {output}") #Debug
        elif inputType == "text":
            output = parsedInput
        return output

#Gets the input values from config.txt (if there are any). config.txt can be empty; if so, the script assigns the default values to the variables. config.txt must be in the same folder as script!
with open(fileConfig, 'r') as configFile:
    for line in configFile:
        if "directory" == line[0:9]:
            dizin = inputParser(line.strip(), "directory", "text", 9, "noDuration")
        elif "maliciousThreshold" == line[0:18]:
            maliciousThreshold = int(inputParser(line.strip(), "maliciousThreshold", "number", 18, "noDuration"))
        elif "ignoreResultFrom" == line[0:16]:
            ignoreList = inputParser(line.strip(), "ignoreList", "list", 16, "noDuration")
            print (f"Ignore list is: {ignoreList}")
        elif "detectionThreshold" == line[0:18]:
            detectionThreshold = int(inputParser(line.strip(), "detectionThreshold", "number", 18, "noDuration"))

#Initialize variables and parameters.
logPath = f"{dizin}log/"
listPath = f"{dizin}list/"
reportPath = f"{dizin}reports/"
fileAPI = f"{dizin}listAPI.txt"
fileIPInput = f"{dizin}virustotalInputIP.txt"
fileIPOutput = f"{dizin}virustotalOutputIP.txt"
fileLogAll = f"{logPath}all_log.txt"
fileLogSystem = f"{logPath}system_log.txt"
with open(fileIPInput, "r") as file:
    inputIP = file.readlines()
    totalIPCount = len(inputIP)
outputIP= f"{dizin}outputReport.txt"

APIno = 1
safeCount = 0
suspiciousCount = 0
maliciousCount = 0
undetectedCount = 0

folderChecker(logPath)
folderChecker(listPath)
folderChecker(reportPath)

def getAPI():
    global APIno
    with open(fileAPI, 'r') as file:
        lines = file.readlines()
        if len(lines) == 0: #API file is empty at start case.
            logAction("system", "emptyAPIList", "NULL", "NULL", "NULL")
        else:
            currentAPI = lines[APIno-1].strip()
            return currentAPI

#Check if virustotal main website is reachable or not. Stop program if so.
website="www.virustotal.com"
response = os.system("ping -n 1 -w 5000 " + website)
if response == 0:
  print(f"{website} is up, starting Virustotal script.")
else:
  print(f"{website} is down, ending Virustotal script.")
  logAction("system", "websiteDown", website, "NULL", "NULL")
  sys.exit(1)

currentAPI = changeAPI("start")
timestampReport = timestampFunc("report")
fileReport = f"{reportPath}{timestampReport}_report.txt"
fileMaliciousReport = f"{reportPath}{timestampReport}_report_malicious.txt"

### MAIN FUNCTION START ###
for line in inputIP:    #Iterate every IP
    minuteCheck = 0 #Used to check whether to sleep or progress to the next API.
    dayCheck = 0    #used to check whether to end program due to all API's using up their daily limits.
    errorCheck = True
    IP = line.strip()
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{IP}"
    print("URL:", url)  # Debug
    
    while errorCheck == True:   #If there is Virustotal error, don't skip the current IP, instead switch API and try again. errorCheck is set to false if there is no Virustotal error so the program progresses.
        with open(fileAPI, 'r') as file:
            maxCheck = len(file.readlines())    #Used to set a max limit for minuteCheck and dayCheck.
        
        currentAPI = getAPI()
        print("API:", currentAPI)  # Debug        
        headers = {
            "accept": "application/json",
            "x-apikey": currentAPI
        }        
        response = requests.get(url, headers=headers)
        #print ("Response text: ",response.text)
        data = response.json()
        
        # Parse the contents of the Virustotal API query.
        if "data" in data and "attributes" in data["data"]: #Correct Virustotal query return, there's a result.
            errorCheck = False
            attributes = data["data"]["attributes"]["last_analysis_stats"]
            safe = attributes.get("harmless")
            suspicious = attributes.get("suspicious")
            malicious = attributes.get("malicious")
            totalCount = safe + malicious + suspicious
            print("Safe count (no ignored results):", safe)  #Debug
            print("Suspicious count (no ignored results):", suspicious) #Debug
            print("Malicious count (no ignored results):", malicious)   #Debug
            
            #Check if there are ignored vendors and remove their non-undetected results.
            ignoredCount = 0
            ignoredList = []
            lastAnalysisResults = data['data']['attributes']['last_analysis_results']
            for vendor in ignoreList:                
                category = data['data']['attributes']['last_analysis_results'][vendor]["category"]
                if vendor in lastAnalysisResults and category != "undetected": #There are ignored results and they aren't undetected.
                    totalCount-=1
                    ignoredCount+=1
                    ignoredResult = f"{vendor}: {category}"
                    ignoredList.append(ignoredResult)
                    if category == "malicious":
                        malicious-=1
                    elif category == "suspicious":
                        suspicious-=1
                    elif category == "safe":
                        safe-=1                    
                    del data['data']['attributes']['last_analysis_results'][vendor]   #Delete ignored vendor results.
            
            if ignoredCount > 0: #There were ignored valid results.
                logAction("result", "ignoredResult", IP, ignoredCount, ignoredList)

            if totalCount <= detectionThreshold:
                undetectedCount += 1
                IPType = "undetected"
                logAction("result", "undetected", IP, detectionThreshold, totalCount)
            elif malicious > 0 and malicious <= maliciousThreshold:
                suspiciousCount += 1
                IPType = "suspicious"
                logAction("result", "maliciousThreshold", IP, malicious, totalCount)
            elif malicious > 0 and malicious > maliciousThreshold:   #Malicious amount greater than threshold set in config.txt, so it is actually a malicious result.
                if not os.path.exists(fileMaliciousReport): #If no malicious report file exists, create file for it.
                    logAction("system", "maliciousFileCreated", IP, fileMaliciousReport, "NULL")
                    with open(fileMaliciousReport, "w") as file:
                        pass
                
                maliciousList = []
                #Prepare list of groups that detected malware for clarity (and to possibly blacklist them)
                for vendor in data["data"]["attributes"]['last_analysis_results']:
                    if lastAnalysisResults[vendor]["category"] == "malicious":
                        print (f"Malicious found by: {vendor}")    #Debug
                        maliciousList.append(vendor)
                print (f"The IP address {IP} is found malicious by: {maliciousList}")  #Debug
                maliciousCount += 1
                IPType = "malicious"
                countInfo = f"{malicious} out of {totalCount}"
                logAction("result", "malicious", IP, countInfo, maliciousList)
                logAction("system", "maliciousRecord", IP, fileMaliciousReport, "NULL")
                print ("Malicious record file:", fileMaliciousReport)   #Debug                
                appendToFiles([fileMaliciousReport], f"{response.text}") #Adds full result for future investigation.
                
            elif suspicious > 0:
                suspiciousCount += 1
                IPType = "suspicious"
                logAction("result", "suspicious", IP, suspicious, totalCount)
            elif safe > 0:
                safeCount += 1
                IPType = "safe"
                logAction("result", "safe", IP, safe, totalCount)
        
            logAction("IPAdded", IPType, IP, "NULL", "NULL")  #When IP is processed without an error.
        
        #Virustotal error code handling.
        elif "error" in data and "message" in data["error"]:
            errorCheck = True
            error_data = data["error"]            
            if error_data["code"] == "UserNotActiveError":
                if error_data["message"] == "User is banned":
                    print("Error: User is banned. Removing Virustotal API from list.")  # Debug
                    currentAPI = changeAPI("delete")
                else:
                    print("Error: Account is inactive. Removing Virustotal API from list.")  # Debug
                    currentAPI = changeAPI("delete")
            elif error_data["code"] == "WrongCredentialsError":
                print("Error: API key is incorrectly structured. Removing Virustotal API from list.")
                currentAPI = changeAPI("delete")
            elif error_data["code"] == "AuthenticationRequiredError":
                print("Error: API key is incorrectly structured (likely empty). Removing Virustotal API from list.")
                currentAPI = changeAPI("delete")
            elif error_data["code"] == "QuotaExceededError":
                print("Error: API key quota is exceeded. Switching to next API from list.")
                dayCheck+=1
                if dayCheck > maxCheck: #If all API's have their daily quotas exceeded. Ends program.
                    logAction("system", "APIQuotaExceeded", "NULL", "NULL", "NULL")
                    sys.exit(1)
                else:
                    currentAPI = changeAPI("next-day")
            else:
                minuteCheck+=1
                if minuteCheck > maxCheck:  #If all API's have their minute quotas exceeded.
                    sleepVariable ("minute", currentAPI)
                else:
                    currentAPI = changeAPI("next-minute")

logSentence = f"Safe:{safeCount}, Suspicious:{suspiciousCount}, Malicious:{maliciousCount}, Undetected:{undetectedCount}"
logAction("system", "endOfScript", "NULL", totalIPCount, logSentence)    #Script finished log.

print ("###Script finished successfully###")

