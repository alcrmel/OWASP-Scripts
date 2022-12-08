# Created by Armel Alcera - 
# Socials:
#    Twitter  - @alcrmel
#    Linkedin - https://www.linkedin.com/in/armelalcera/
# 

"""
Passive scan rules should not make any requests.

Note that new passive scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"
"""  

import re
from org.zaproxy.zap.extension.pscan import PluginPassiveScanner;


def appliesToHistoryType(historyType):
    """Tells whether or not the scanner applies to the given history type.

    Args:
        historyType (int): The type (ID) of the message to be scanned.

    Returns:
        True to scan the message, False otherwise.

    """
    return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);


def scan(ps, msg, src):
    """Passively scans the message sent/received through ZAP.

    Args:
        ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
        msg (HttpMessage): The HTTP message being scanned.
        src (Source): The HTML source of the message (if any). 

    """  
    
    # Regex for Locating a file upload form
    formRegex = """<input[^>]*type=['"]?file['"]?[^>]*(\/)?>"""
    
  
    # Test the request and/or response here
    if (True):
        # Change to a test which detects the vulnerability
        # raiseAlert(risk, int confidence, String name, String description, String uri, 
        # String param, String attack, String otherInfo, String solution, String evidence, 
        # int cweId, int wascId, HttpMessage msg)
        # risk: 0: info, 1: low, 2: medium, 3: high
        # confidence: 0: false positive, 1: low, 2: medium, 3: high
        
        alertName = 'Script: File Upload Found'
        alertDescription = 'Uploaded files represent a significant risk to applications. The first step in many attacks is to get some code to the system to be attacked. Then the attack only needs to find a way to get the code executed. Using a file upload helps the attacker accomplish the first step'
        alertSolution = 'Fully protecting against malicious file upload can be complex, and the exact steps required will vary depending on the types files that are uploaded, and how the files are processed or parsed on the server.\n\nIdentifying where all the upload functionalities are in the web application and inspecting whether they only accept files based on their functionality will help increase the security of the application.'
        alertReference = 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files'
        alertUri = msg.getRequestHeader().getURI().toString()
     
        # Get the responseBody to be parsed
        responseBody = msg.getResponseBody().toString()

        # Identify the file upload tags in the response body
        form_found = re.search(formRegex, responseBody)
    
        # If a tag was identified, this if statement will trigger
        # and will create an alert
        if form_found:
            
            alertObj = ps.newAlert()
            
            alertObj.setRisk(0)
            alertObj.setConfidence(3)
            alertObj.setName(alertName)
            alertObj.setDescription(alertDescription)
            alertObj.setReference(alertReference)
            alertObj.setSolution(alertSolution)
            alertObj.setUri(alertUri)
            alertObj.setEvidence(form_found.group(0))
            alertObj.setMessage(msg)
            alertObj.setWascId(13)
            alertObj.raise()
