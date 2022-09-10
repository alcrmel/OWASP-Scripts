# Created by Armel Alcera - Twitter @alcrmel
# 

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
    formRegex = """(type\s*=\s*['"]?file['"]?)"""
    
  
    # Test the request and/or response here
    if (True):
        # Change to a test which detects the vulnerability
        # raiseAlert(risk, int confidence, String name, String description, String uri, 
        # String param, String attack, String otherInfo, String solution, String evidence, 
        # int cweId, int wascId, HttpMessage msg)
        # risk: 0: info, 1: low, 2: medium, 3: high
        # confidence: 0: false positive, 1: low, 2: medium, 3: high
        
        alertTitle = 'Script: File upload field'
        alertDescription = 'Uploaded files represent a significant risk to applications. The first step in many attacks is to get some code to the system to be attacked. Then the attack only needs to find a way to get the code executed. Using a file upload helps the attacker accomplish the first step'
        alertSolution = 'Fully protecting against malicious file upload can be complex, and the exact steps required will vary depending on the types files that are uploaded, and how the files are processed or parsed on the server. '
        alertReference = 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files'
     
        # Get the responseBody to be parsed
        responseBody = msg.getResponseBody().toString()
        
        form_found = re.search(formRegex, responseBody)
    
    
        # Docs on alert raising function:
        #  raiseAlert(int risk, int confidence, str name, str description, str uri,
        #             str param, str attack, str otherInfo, str solution,
        #             str evidence, int cweId, int wascId, HttpMessage msg)
        #  risk: 0: info, 1: low, 2: medium, 3: high
        #  confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
        if form_found:
            print(form_found.group(0))
            ps.raiseAlert(1, 2, alertTitle, alertDescription, 
                msg.getRequestHeader().getURI().toString(), 
                '', '', alertReference, alertSolution, form_found.group(0), 434, 0, msg);
