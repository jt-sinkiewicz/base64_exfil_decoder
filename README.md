# base64_exfil_decoder

Exfil data parser - During a BianLian TA group ransomware IR investigation, firewall logs were found with a b64 encoded string in the 'arg', which when decoded 
turned out to be the path of the file sent to the exfil server by the Powershell backdoor web.ps1. This script was writted to parse the b64 string via regex and decode the b64 to the file path for all files transferred/RE matches. 
The 'arg' field size does appear to have a limiation, (106 char.?) that may be a Sonicwall specific limitation.'''
