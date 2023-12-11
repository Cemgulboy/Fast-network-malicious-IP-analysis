# Fast-network-malicious-IP-analysis
###README###

Quick malware analysis of foreign networks using pyshark
Written by: Cem Gülboy
Assistant teacher: Nurlan Abishov

This is a program to listen to the connected network for the stated duration and ask Virustotal about the resulting IP's and listing out the results (safe, suspicious, malicious, undetected). It's made up of 2 separate scripts: one for collecting the network packets by listening to them via pyshark library then parsing their IP and another for querying these parsed IP's into the Virustotal database via API.
WARNING! This script will trigger any cyber security tools that watch for network packet captures! Using them in work environment without notifying your IT crew may be an offense. Use it carefully!


For this script to run successfully, the following requirements must be followed:
1) The following files must be at the same location:
		packetparser.py (must be used if the analysis report is requested)
		virustotal_api.py
		config.txt (file can be deleted, script will create empty file it if not found)
2) The following file must have a valid Virustotal API (location dependent on config.txt, multiple API's allowed):
		listAPI.txt

#config.txt details#
1)	Everything before and including the = sign for every line must be exactly as specified; otherwise program will skip over them; utilizing the default values.
2)	The values that can be included in the config.txt and their explanations are as follows:
		directory: The main directory that the scripts will store their output and the location where the scripts should be located in. The outputs are 2 files named virustotalInputIP and virustotalOutputIP and all the files located inside the folders named list, log and reports.
		listenDuration(*time): For how long the packet capture of the network will happen. During this duration, the script will simply collect the packets and start parsing them at the end.
		oldResultTimeout(*time) : For how long the previous Virustotal result is valid. After this duration is exceeded, the result is deleted and the IP is queried by Virustotal again.
		maliciousThreshold : How many malicious results are needed for an IP to count as a valid malicious result. The reason for this parameter comes from the fact that some router IP's are considered malicious by a single vendor, resulting with a false positive. With this parameter, you can specify how broad or narrow a result is actually considered malicious. If the threshold is not passed, the result is registered as suspicious with the log stating the threshold as the reason.
		detectionThreshold : How many valid results are needed for any result to be considered as such. This parameter is prioritized over maliciousThreshold, so if a malicious result doesn't pass both thresholds, it'll be categorized as undetected. Some vendors haven't analyzed the IP address, and there are rare cases where very few vendors have analyzed the results and determined it to be malicious.
		ignoreResultFrom : Which vendor results will be excluded. A statement about which results were excluded will be written into the logs.
3)	The default values are as follows:
		directory= Whatever folder the script is currently located in
		listenDuration(s)= 5 seconds
		oldResultTimeout(d)= 30 days
		maliciousThreshold= 2 results
		detectionThreshold= 5 results
		ignoreResultFrom= empty, no results excluded for default
4)	Supported duration modifers are:
		s for seconds
		m for minutes
		h for hours
		d for days
5)	If wrong results are entered, the program is stopped with an error and the log will show the error in detail.
6)	None of the values are mandatory: if none are entered, the default value will be used for any that's missing.

#General details#
The malicious count threshold takes priority over the undetected threshold. If maliciousThreshold=3 and detectionThreshold=8 and results come in with 3 malicious and 4 safe detected, it'll count as malicious.
Remember to check the logs if you want more detail about how the program works or for more details about the results.
The daily logs are named after the day the script is run.
The Virustotal API script can be used by itself after manually modifying the virustotalInputIP.txt file.
There are a lot of debug lines. If you want them removed, I've added a #Debug at the end of these lines; you can remove them from the code easily if you search and remove those lines.
The virustotal API list file can have multiple Virustotal API's in it. Every API must be in a new line. The script does have several Virustotal API error checks in it, including minute or daily based quota being depleted. Details about Virustotal API can be found in their documentation: https://docs.virustotal.com/reference/overview

Thank you for using my scripts.
