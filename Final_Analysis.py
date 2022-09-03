about = '''
CYBV473 - Violent Python 
Date: 12/12/2020
Final Project - SOC Analysis Version 1

This final project is a multithreading tool to help security 
analysts to identify a hash, email, IP or URL with a bad 
reputation by automatically querying it into different databases. 

Current Supported Databases:

https://www.virustotal.com/
https://who.is/
https://www.abuseipdb.com/
https://emailrep.io/

This tool can be used as a GUI (-g), or in a CLI (-q <string> -e <engine>).
'''
test_strings= '''
======== Test strings: ======= 

~~~~~~~
Bad  Reputation IP: 45.154.168.201
Good Reputation IP: 69.63.176.13 (Facebook)
~~~~~~~
Bad  Reputation Hash: b8458d393443ca9b59f4d32a5d31e4f7 (hotpotato.exe privesc hash)
Good Reputation Hash: 2ee1c17ba0344e6e58c572f52660d1f3 (Internet Explorer)
~~~~~~~
Good Reputation url: www.facebook.com
~~~~~~~
'''

import tkinter as tk
import tkinter.scrolledtext as scrolledtext
from   tkinter import messagebox

import argparse
import requests
import json
from prettytable import PrettyTable
from threading import Thread

# API Keys that I use through the code. Usually I would put those in a separate .conf file.

virusTotal_API = ""
abuseipdb_API = ""
emailRepio_API = ""

project = '''
=====================================================
   _______     ________      ___  _ ______ ____  
  / ____\ \   / |  _ \ \    / | || |____  |___ \ 
 | |     \ \_/ /| |_) \ \  / /| || |_  / /  __) |
 | |      \   / |  _ < \ \/ / |__   _|/ /  |__ < 
 | |____   | |  | |_) | \  /     | | / /   ___) |
  \_____|  |_________/   \/      __|/_/   |____/ 
           |  ____(_)           | |              
           | |__   _ _ __   __ _| |              
           |  __| | | '_ \ / _` | |             
           | |    | | | | | (_| | |          
           |_|    |_|_| |_|\__,_|_|          
=====================================================
'''

print(project)

'''
Function to check email reputation
This will query the database https://emailrep.io/, send the 
string, parse the results, input the results into a table, 
and print the table to the user.
'''
def emailrep(query_string,results_box):
    scan_title = "\n\n==========>  Emailrep.io Results:  <==========\n\n"  
    value = string_type(query_string)
    report = ""
    if value == 'email':
        try:
            url = 'https://emailrep.io/' + query_string + '?summary=true'
            params = {'Key': emailRepio_API, 'User-Agent': "CYBV473-Final"}     
            response = requests.get(url, params=params)
            
            req = response.json()
            emailDomain = query_string.split('@')[1]
            
            email_tbl = PrettyTable()
            domain_tbl = PrettyTable()
            malicious_tbl = PrettyTable()
            
            email_tbl.field_names = ["Data", "Result"]
            domain_tbl.field_names = ["Data", "Result"]
            malicious_tbl.field_names = ["Data", "Result"]
            
            email_tbl._max_width = {"Data" : 40, "Result" : 40}
            domain_tbl._max_width = {"Data" : 40, "Result" : 40}
            malicious_tbl._max_width = {"Data" : 40, "Result" : 40}
            
            if response.status_code == 400:
                if theArgs.gui:
                    results_box.insert(tk.END, scan_title)
                    results_box.insert(tk.END, 'Invalid Email / Bad Request')
                else:
                    print(scan_title)
                    print('Invalid Email / Bad Request')
                return 0
            
            if response.status_code == 429:
                if theArgs.gui:
                    results_box.insert(tk.END, scan_title)
                    results_box.insert(tk.END, 'Too many requests (Free API - 10/day)')
                else:
                    print(scan_title)
                    print('Too many requests (Free API - 10/day)')       
                return 0
            
            if response.status_code == 200:   
                
                report += '~~~~~~~~~~~~~~~~~~~~~\n'
                if req['suspicious'] == True:
                    report += "The email appears to be suspicious."
                else:
                    report += "The email does not appear to be suspicious."
                report += '\n~~~~~~~~~~~~~~~~~~~~~\n'
                report += 'Full Report: '
                
                email_tbl.add_row(["Email", req['email']])
                email_tbl.add_row(["Reputation", req['reputation']])
                email_tbl.add_row(["Suspicious", req['suspicious']])
                email_tbl.add_row(["Spotted", str(req['references']) + ' Times'])
                email_tbl.add_row(["Blacklisted", req['details']['blacklisted']])
                email_tbl.add_row(["Last Seen", req['details']['last_seen']])
                email_tbl.add_row(["Known Spam", req['details']['spam'] ])
                
                malicious_tbl.add_row(["Malicious Activity::", req['details']['malicious_activity'] ])
                malicious_tbl.add_row(["Recent Activity::", req['details']['malicious_activity_recent'] ])
                malicious_tbl.add_row(["Credentials Leaked:", req['details']['credentials_leaked'] ])
                malicious_tbl.add_row(["Found in breach:", req['details']['data_breach'] ])
                
                domain_tbl.add_row(["Domain", emailDomain ])
                domain_tbl.add_row(["Domain Exists:", req['details']['domain_exists'] ])
                domain_tbl.add_row(["Domain Rep:", req['details']['domain_reputation'] ])
                domain_tbl.add_row(["Domain Age:", str(req['details']['days_since_domain_creation']) + ' Days' ])
                domain_tbl.add_row(["New Domain:", req['details']['new_domain'] ])
                domain_tbl.add_row(["Deliverable:", req['details']['deliverable'] ])
                domain_tbl.add_row(["Free Provider:", req['details']['free_provider'] ])
                domain_tbl.add_row(["Disposable:", req['details']['disposable'] ])
                domain_tbl.add_row(["Spoofable:", req['details']['spoofable'] ])

        except:
            if theArgs.gui:
                results_box.insert(tk.END, scan_title)
                results_box.insert(tk.END, 'Error accessing https://emailrep.io/')
            else:
                print(scan_title)
                print('Error accessing https://emailrep.io/')  
                
        email_tbl.align = "l" 
        domain_tbl.align = "l" 
        malicious_tbl.align = "l" 
        
        email_String = email_tbl.get_string()
        domain_String = domain_tbl.get_string()
        malicious_String = malicious_tbl.get_string()
          
        if theArgs.gui:
            results_box.insert(tk.END, scan_title)
            results_box.insert(tk.END,report + "\n")
            results_box.insert(tk.END,'\n Email Analysis Report\n')
            results_box.insert(tk.END, email_String)
            results_box.insert(tk.END,'\n Domain Report\n')
            results_box.insert(tk.END, domain_String)
            results_box.insert(tk.END,'\n Malicious Activity Report\n')
            results_box.insert(tk.END, malicious_String)
            
            results_box.insert(tk.END, "\n\n")
        else:
            print(scan_title)
            print(report)
            print('\n Email Analysis Report\n')
            print(email_String)
            print('\n Domain Report\n')
            print(domain_String)
            print('\n Malicious Activity Report\n')
            print(malicious_String)
    else:
        if theArgs.gui:
            results_box.insert(tk.END, scan_title + 'Value does not appear to be a valid email')
        else:
            print(scan_title)
            print('Value does not appear to be a valid email')        




'''
Function to check the whois database
This will query the database https://who.is/, send the
string, parse the HTML results and return the results to the user.
I attempted to parse the HTML code without the use of any other 
third_party libraries. Next Version I should use the Beautifulsoup library.  

'''
def whois_Lookup(query_string,results_box):
    scan_title = "\n\n==========>  Who.is Information:  <==========\n\n"  
    value = string_type(query_string)
    report = ""
    
    registrar_tbl = PrettyTable()
    name_servers_tbl = PrettyTable()
    similar_domains_tbl = PrettyTable()
    registrar_data_tbl = PrettyTable()
    
    registrar_tbl.field_names = ["Data", "Result"]
    name_servers_tbl.field_names = ["Data", "Result"]
    similar_domains_tbl.field_names = ["Data", "Result"]
    registrar_data_tbl.field_names = ["Data", "Result"]
    
    registrar_tbl._max_width = {"Data" : 40, "Result" : 40}
    name_servers_tbl._max_width = {"Data" : 40, "Result" : 40}
    similar_domains_tbl._max_width = {"Data" : 40, "Result" : 40}    
    registrar_data_tbl._max_width = {"Data" : 40, "Result" : 40}    
    
    nomatch = 0
    if value == 'url':
        if '//' in query_string:
            query_string = query_string.split('//')[1]
        url = 'https://who.is/whois/' + query_string
        response = requests.get(url)
        
        if "No match for" in response.text:
            nomatch = 1
        else:
            registrar = response.text.split('Name Servers')[0]
            name_servers = response.text.split('Name Servers')[1].split('Similar Domains')[0]
            similar_domains = response.text.split('Name Servers')[1].split('Similar Domains')[1].split('Registrar Data')[0]
            registrar_data = response.text.split('Name Servers')[1].split('Similar Domains')[1].split('Registrar Data')[1]
            
            
            # Registrar Info / Important Dates 
            for i in range (len(registrar.split('queryResponseBodyKey'))):
                key = CleanString(registrar.split('queryResponseBodyKey')[i].split('<')[0][2:]) # key
                key_value = CleanString(registrar.split('queryResponseBodyValue">')[i].split('<')[0]) # value
                registrar_tbl.add_row([key,key_value])
                    
            #name servers
            i=1
            while i < (len(name_servers.split('queryResponseBodyValue">'))):
                key = CleanString(name_servers.split('queryResponseBodyValue">')[i].split('>')[1].split('<')[0])  # key 
                key_value = CleanString(name_servers.split('queryResponseBodyValue">')[i+1].split('>')[1].split('<')[0])   # value
                name_servers_tbl.add_row([key,key_value])
                i = i + 2
            
            # Similar Domains    
            i=1
            while i < (len(similar_domains.split('href'))):
                #similar_domains.split('href')[i].split('>')[1].split('<')[0]
                similar_domains_tbl.add_row(['Similar domain:', CleanString(similar_domains.split('href')[i].split('>')[1].split('<')[0])])
                i = i + 1
            
            #Registrar Data        
            i=1
            while i < (len(registrar_data.split('strong'))):
                key = CleanString(registrar_data.split('strong')[i][1:-2]) # key
                key_value = CleanString(registrar_data.split('strong')[i+1].split('>')[3].split('<')[0]) # value
                registrar_data_tbl.add_row([key,key_value])
                i = i + 2
        
    if value == 'ip':
        url = 'https://who.is/whois-ip/ip-address/' + query_string
        response = requests.get(url)
        
        if "No match for" in response.text:
            nomatch = 1
        else:
            s = response.text
            
            start = s.find('<pre>') + len('<pre>')
            end = s.find('</pre>')
            report = s[start:end]
        
    
    registrar_tbl.align = "l" 
    name_servers_tbl.align = "l" 
    similar_domains_tbl.align = "l" 
    registrar_data_tbl.align = "l" 
    
    if theArgs.gui:
        if value == "ip":
            if nomatch == 0:
                results_box.insert(tk.END, scan_title)
                results_box.insert(tk.END,CleanString(report))
            else:
                results_box.insert(tk.END, scan_title)
                results_box.insert(tk.END, "IP not found in this database")
        elif value == 'url':
            if nomatch == 0:
                results_box.insert(tk.END, scan_title)
                results_box.insert(tk.END,"\nRegistrar Info\n")
                resultString = registrar_tbl.get_string()    
                results_box.insert(tk.END,resultString)
                results_box.insert(tk.END,"\nName Servers\n")
                resultString = name_servers_tbl.get_string()    
                results_box.insert(tk.END,resultString)
                results_box.insert(tk.END,"\nSimilar domains\n")
                resultString = similar_domains_tbl.get_string()    
                results_box.insert(tk.END,resultString)
                results_box.insert(tk.END,"\nRegistrar data\n")
                resultString = registrar_data_tbl.get_string()    
                results_box.insert(tk.END, resultString)
            else:
                results_box.insert(tk.END, scan_title)
                results_box.insert(tk.END, "URL not found in this database")
        else:
            results_box.insert(tk.END, scan_title + "The string does not appear to be a ip or url")         
    else:
        if value == "ip":
            if nomatch == 0:
                print(scan_title)
                print(report)
            else: 
                print(scan_title)
                print("IP not found in this database")
        elif value == 'url':
            if nomatch == 0:
                print(scan_title)
                print("Registrar Info")
                resultString = registrar_tbl.get_string()    
                print(resultString)
                print("Name servers")
                resultString = name_servers_tbl.get_string()    
                print(resultString)
                print("Similar domains")
                resultString = similar_domains_tbl.get_string()    
                print(resultString)
                print("Registrar data")
                resultString = registrar_data_tbl.get_string()    
                print(resultString)
            else:
                print(scan_title)
                print("URL not found in this database")
        else:
            print(scan_title)
            print("The string does not appear to be a ip or url")                  
            


'''
Function to check the VirusTotal database:
This will query the database https://www.virustotal.com/, send the
string, depending on the type of string (url,hash or ip), the code 
parses the result and return to the user accordingly.
'''
def virustotal(query_string,results_box):
    scan_title = "\n\n==========> Virustotal Results: <==========\n\n"   
    report = ""

    value = string_type(query_string)
        
    if (value == "ip"):
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'apikey': virusTotal_API, 'ip': query_string}
        response = requests.get(url, params=params)
        if response.status_code == 200:    
            if 'IP address in dataset' in response.json()['verbose_msg']:
                try:
                    report += "Owner: " + CleanString(response.json()['as_owner']) + "\n"
                except:
                    pass
                report += "\nPassive DNS Replication:\n"
                for i in range(0,len(response.json()['resolutions'])):
                    report += "  " + CleanString(response.json()['resolutions'][i]['hostname']) + "\n"
                
                # trying to to get url reputation
                url = 'https://www.virustotal.com/vtapi/v2/url/report'
                params = {'apikey': virusTotal_API, 'resource': query_string}
                response = requests.get(url, params=params)
                report += "\n"
                report += "Detected as Malicious by: " + str(response.json()['positives']) + " engines\n"
                report += "Total number of engines: " + str(response.json()['total'])
            
            else:
                report += "The IP does not appear to be part of VirusTotal database."
                report += '\n~~~~~~~~~~~~~~~~~~~~~\n'
                report += 'Full Report: '
                report += json.dumps(response, sort_keys=False, indent=4)
       
            if theArgs.gui:
                results_box.insert(tk.END, scan_title)
                results_box.insert(tk.END, report)
                results_box.insert(tk.END, "\n\n")
            else:
                print(scan_title)
                print(report)            
    
        else:
            if theArgs.gui:
                results_box.insert(tk.END, scan_title)
                results_box.insert(tk.END,"\nError: " + str(response.status_code))
            else:
                print("error: " + response.status_code)  
            
    
    elif (value == "url"):      
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': virusTotal_API, 'resource': query_string}
        response = requests.get(url, params=params) 
        if response.status_code == 200:    
            result = response.json()
            
            if 'The requested resource is not among the finished, queued or pending scans' in result['verbose_msg']:
                report += '~~~~~~~~~~~~~~~~~~~~~\n'
                report += "The URL does not appear to be part of VirusTotal database."
                report += '\n~~~~~~~~~~~~~~~~~~~~~\n'
                if theArgs.gui:
                    results_box.insert(tk.END, scan_title)
                    results_box.insert(tk.END, report)
                    results_box.insert(tk.END, "\n\n")
                else:
                    print(scan_title)
                    print(report)                  
            
            elif 'Resource does not exist in the dataset' in result['verbose_msg']:
                report += '~~~~~~~~~~~~~~~~~~~~~\n'
                report += "The URL does not appear to be part of VirusTotal database."
                report += '\n~~~~~~~~~~~~~~~~~~~~~\n'
                if theArgs.gui:
                    results_box.insert(tk.END, scan_title)
                    results_box.insert(tk.END, report)
                    results_box.insert(tk.END, "\n\n")
                else:
                    print(scan_title)
                    print(report)                    
            
            elif 'Invalid resource, check what you are submitting' in result['verbose_msg']:
                report += '~~~~~~~~~~~~~~~~~~~~~\n'
                report += "Invalid resource, check what you are submitting."
                report += '\n~~~~~~~~~~~~~~~~~~~~~\n'
                if theArgs.gui:
                    results_box.insert(tk.END, scan_title)
                    results_box.insert(tk.END, report)
                    results_box.insert(tk.END, "\n\n")
                else:
                    print(scan_title)
                    print(report)                    
            
            else:
                list_a = result['scans'].keys()
                detected = 0 
                tbl = PrettyTable()
                tbl.field_names = ["Engine", "Result", "Detected"]
                
                for i in list_a:
                    tbl.add_row([i, result['scans'][i]['result'], result['scans'][i]['detected']])
                    if result['scans'][i]['detected'] == True:
                        detected = detected + 1
                    
                report += '~~~~~~~~~~~~~~~~~~~~~~~~\n'
                report += "The URL was detected as malicious by " + str(detected) + " out of " + str(len(list_a)) + " engines"
                report += '\n~~~~~~~~~~~~~~~~~~~~~~~~\n\n'
                report += "Full Report:\n\n"
                
                tbl.align = "l" 
                tbl.sortby = "Detected"
                tbl.reversesort = True
                resultString = tbl.get_string()
    
                if theArgs.gui:
                    results_box.insert(tk.END, scan_title)
                    results_box.insert(tk.END, report)
                    results_box.insert(tk.END, resultString)
                    results_box.insert(tk.END, "\n\n")
                else:
                    print(scan_title)
                    print(report)  
                    print(resultString)  
        else:
            if theArgs.gui:
                results_box.insert(tk.END, scan_title)
                results_box.insert(tk.END,"\nError: " + str(response.status_code))
            else:
                print("error: " + response.status_code)   
                
    elif (value == "hash"):
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': virusTotal_API, 'resource': query_string}
        response = requests.get(url, params=params)

        if response.status_code == 200:    
            result = response.json()
        
            if 'The requested resource is not among the finished, queued or pending scans' in result['verbose_msg']:
                report += '~~~~~~~~~~~~~~~~~~~~~~~~\n'
                report += "The hash does not appear to be part of VirusTotal database."
                report += '\n~~~~~~~~~~~~~~~~~~~~~\n'
                report += 'Full Report: '
                report += json.dumps(response, sort_keys=False, indent=4)
            
            if 'Invalid resource, check what you are submitting' in result['verbose_msg']:
                report += '~~~~~~~~~~~~~~~~~~~~~~~~\n'
                report += "Invalid resource, check what you are submitting."
                report += '\n~~~~~~~~~~~~~~~~~~~~~\n'
                report += 'Full Report: '
                report += json.dumps(response, sort_keys=False, indent=4)    
                
            else:
                list_a = result['scans'].keys()
                detected = 0 
                tbl = PrettyTable()
                tbl.field_names = ["Engine", "Result", "Detected", "Updated"]
                tbl._max_width = {"Engine" : 20, "Result" : 20, "Detected" : 20 , "Updated" : 20}
                
                for i in list_a:
                    tmpdate = result['scans'][i]['update']
                    tbl.add_row([i, result['scans'][i]['result'], result['scans'][i]['detected'], tmpdate[4:6] + '-' + tmpdate[6:8] + '-' + tmpdate[0:4]])
                    if result['scans'][i]['detected'] == True:
                        detected = detected + 1
                    
                report += '~~~~~~~~~~~~~~~~~~~~~~~~\n'
                report += "The hash was detected as malicious by " + str(detected) + " out of " + str(len(list_a)) + " engines"
                report += '\n~~~~~~~~~~~~~~~~~~~~~~~~\n'
                report += "\nFull Report:\n\n"
            
                tbl.align = "l" 
                tbl.sortby = "Detected"
                tbl.reversesort = True
                resultString = tbl.get_string()

            if theArgs.gui:
                results_box.insert(tk.END, scan_title)
                results_box.insert(tk.END, report)
                results_box.insert(tk.END, resultString)
                results_box.insert(tk.END, "\n\n")
            else:
                print(scan_title)
                print(report)  
                print(resultString)
        else:
            if theArgs.gui:
                results_box.insert(tk.END, scan_title)
                results_box.insert(tk.END,"\nError: " + str(response.status_code))
            else:
                print("error: " + str(response.status_code))             
    else:
        if theArgs.gui:
            results_box.insert(tk.END, scan_title + "The string does not appear to be a URL, IP or Hash")
        else:
            print(scan_title)
            print("The string does not appear to be a URL, IP or Hash")        
         


'''
Function to check the abuseipdb database
This will query the database https://www.abuseipdb.com/, send the
string, the code parses the result and return to the user accordingly.
'''
def abuseipdb(query_string,results_box):
    scan_title = "\n\n==========>  AbuseIPDB Results:  <==========\n\n"
    report = ""  
    value = string_type(query_string)
        
    if (value == "ip"):    
        try:
        
            AB_URL = 'https://api.abuseipdb.com/api/v2/check'
            days = '180'
            querystring = {'ipAddress': query_string,'maxAgeInDays': days}
            headers = {'Accept': 'application/json','Key': abuseipdb_API}
            response = requests.request(method='GET', url=AB_URL, headers=headers, params=querystring)
            
            if response.status_code == 200:
                req = response.json()
                report += "\nIP:          " + CleanString(str(req['data']['ipAddress']))
                report += "\nReports:     " + CleanString(str(req['data']['totalReports']))
                report += "\nAbuse Score: " + CleanString(str(req['data']['abuseConfidenceScore']) + "%")
                report += "\nLast Report: " + CleanString(str(req['data']['lastReportedAt']))
            
            else:
                report +=  "Error Reaching ABUSE IPDB"

            if theArgs.gui:
                results_box.insert(tk.END, scan_title)
                results_box.insert(tk.END, report)
            else:
                print(scan_title)
                print(AIPDB_report)     
        except:
            report += '   IP Not Found'
    else:
        if theArgs.gui:
            results_box.insert(tk.END, scan_title + 'Value does not appear to be a valid IP')
        else:
            print(scan_title)
            print('Value does not appear to be a valid IP')                  



'''
This function will check if string being 
passed is a hash, url, ip, or email.
This function will be updated in future versions.
'''
def string_type(query_string):
    
    if len(query_string) >= 32: # check the lenght of the string (32 bits = md5) 
        value = "hash"
    elif query_string.count('.') == 3 and all(0<=int(num)<256 for num in query_string.rstrip().split('.')):
        value = "ip"
    elif '@' in query_string:
        value = "email"
    elif query_string == '':
        value = "empty"
    elif ('http' in query_string) or ('www.' in query_string) or ('.com' in query_string) or ('.edu' in query_string) or ('.org' in query_string):
        value = "url" 
    else:
        value = 'I dont know what is this.'
    #print("String identified as: " + value)
    return value



'''
Function to clean IP's and URLs. This is 
important in a report to avoid clicking on
malicious emails or IP's.
'''
def CleanString(string):
    string = string.replace('.','[.]')
    string = string.replace('https://','hxxps://')
    string = string.replace('http://','hxxp://')
    return string



'''
Function that will manage all the searches.
This function utilizes threads to execute the database searches. 
The order that the databases are printed might vary, since there
are different threads and they might finish at different times.

If using a graphical interface, this function opens a new window that will hold the results. 
this is helpful, since depending on the analyst investigation, it might be required to
search for different strings at the same time, for example: email, ip, domain and hash.
'''
def manager(root,query_string,Virustotal_check,AbuseIPDB_check,Emailrep_check,whois_check):  
    results_box = ""
    if theArgs.gui:
        window = tk.Toplevel(root)
        window.resizable(False, False)
        window.title('Results')
    
        results_box_label = tk.Label(window, text="Results for: " + CleanString(query_string), font=("Helvetica 16 bold"))
        results_box = tk.scrolledtext.ScrolledText(window, height=50, width=80)  # Create the TextBox
        closebtn = tk.Button(window, text='Close', command=lambda: window.destroy(), font=("Helvetica 16 bold"), width=20)
    
        results_box_label.grid(row=0, columnspan=2, padx=5, pady=5)
        results_box.grid(row=1, columnspan=2, padx=5, pady=5)
        closebtn.grid(row=2, columnspan=2, padx=5, pady=5)
        
        window.update()
    
    if query_string == "":
        if theArgs.gui:
            results_box.insert(tk.END, 'Search string cannot be empty')
        else:
            print("Search string cannot be empty")
    else:
        if whois_check:    
            t = Thread(target=whois_Lookup,args=(query_string, results_box,))
            t.start()
    
        if Virustotal_check:
            t = Thread(target=virustotal,args=(query_string, results_box,))
            t.start()
            
        if AbuseIPDB_check:
            t = Thread(target=abuseipdb,args=(query_string, results_box,))
            t.start()            
    
        if Emailrep_check:
            t = Thread(target=emailrep,args=(query_string, results_box,))
            t.start()
    
    if (whois_check == False) and (Virustotal_check == False) and (AbuseIPDB_check == False) and (Emailrep_check == False) :
        if theArgs.gui:
            results_box.insert(tk.END, '\nPlease select at least one Database')
        else:
            print('Please select at least one Database')        

    
'''
This is the about menu for the graphical interface.
'''  
def menuAbout():
    messagebox.showinfo("About", about)
    messagebox.Dialog



'''
This is the how_to menu for the graphical interface.
'''  
def menuHow_To():
    messagebox.showinfo("How To", how_to + test_strings)
    messagebox.Dialog



'''
Graphical Interface
This is a quick graphical interface. It contains a input string box, 
database check boxes and a button to perform the search. when the search
starts, it opens a new window that will hold all the results from the search.
'''
def graphicalInterface():
    root = tk.Tk()
    root.title("CYBV 473 Final")
    root.resizable(False, False)
    menuBar = tk.Menu(root)
    toolsMenu = tk.Menu(menuBar, tearoff=0)
    
    
    toolsMenu.add_command(label='About Search', command=menuAbout, underline=0)
    toolsMenu.add_command(label='How To', command=menuHow_To, underline=0)
    toolsMenu.add_separator()
    toolsMenu.add_command(label='Exit', command=root.destroy)
    menuBar.add_cascade(label='Help', menu=toolsMenu, underline=0)  
    root.config(menu=menuBar)  # menu ends
        
    search_Label = tk.Label(root, text="URL, IP, hash or email:", font=("Helvetica 16 bold"))
    search_String = tk.Entry(root,font=("Helvetica 16 bold"))
    search_Button = tk.Button(root, text='search', command=lambda: manager(root,search_String.get(),Virustotal_check.get(),AbuseIPDB_check.get(),Emailrep_check.get(),whois_check.get()),font=("Helvetica 16 bold"))
    
    # create the checkboxes
    Virustotal_check = tk.BooleanVar() 
    Virustotal = tk.Checkbutton(root, text="Virustotal", variable=Virustotal_check)
    
    AbuseIPDB_check = tk.BooleanVar() 
    AbuseIPDB = tk.Checkbutton(root, text="AbuseIPDB", variable=AbuseIPDB_check)
    
    Emailrep_check = tk.BooleanVar() 
    Emailrep = tk.Checkbutton(root, text="Emailrep", variable=Emailrep_check)
    
    whois_check= tk.BooleanVar() 
    whois = tk.Checkbutton(root, text="who.is", variable=whois_check)
    
    search_Label.grid(row=0, columnspan=2, padx=5, pady=5)
    search_String.grid(row=1, columnspan=2, padx=5, pady=5)

    Virustotal.grid(row=2, column=0, padx=5, pady=5,sticky=tk.W)
    AbuseIPDB.grid(row=2, column=1, padx=5, pady=5,sticky=tk.W)
    Emailrep.grid(row=3, column=1, padx=5, pady=5,sticky=tk.W)
    whois.grid(row=3, column=0, padx=5, pady=5,sticky=tk.W)
    search_Button.grid(row=5, columnspan=2, padx=5, pady=5)    
    
    if theArgs.query:
        search_String.insert(tk.END, theArgs.query)
    tk.mainloop()
  

'''
Main Function:
'''   

how_to='This tool checks for hash, ip, url or email reputation.\n Usage:\n GUI: \npython3 SOC_analysis.py -g |\n CLI: \npython3 SOC_analysis.py -e whois,virustotal -q www.facebook.com'

parser = argparse.ArgumentParser(description=how_to)
parser.add_argument('-g', '--gui', help='Use graphical interface', action='store_true')
parser.add_argument('-e', '--engine', help='Select a search engine (whois, virustotal, abuseipdb or emailrep)')
parser.add_argument('-q', '--query', help='This needs to be a valid Hash, email, url or IP.')

theArgs = parser.parse_args()
 
if theArgs.gui:
    graphicalInterface()
    
elif theArgs.query:
    if theArgs.engine: 
        # manager(root,query_string,Virustotal_check,AbuseIPDB_check,Emailrep_check,whois_check):  
        virustotal_temp = False
        abuseipdb_temp = False
        emailrep_temp = False
        whois_temp = False
        
        if 'virustotal' in theArgs.engine:
            virustotal_temp = True
        if 'whois' in theArgs.engine:
            whois_temp = True
        if 'abuseipdb' in theArgs.engine:
            abuseipdb_temp = True
        if 'emailrep' in theArgs.engine:
            emailrep_temp = True
            
        manager(False,theArgs.query,virustotal_temp,abuseipdb_temp,emailrep_temp,whois_temp)

    else:
        parser.print_help()

elif theArgs.engine:
    parser.print_help()

else: 
    parser.print_help()

