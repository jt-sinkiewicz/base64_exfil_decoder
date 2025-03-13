'''JT Sinkiewicz - Exfil data parser
During a BianLian TA ransomware IR investigation firewall logs were found with a b64 encoded string in the 'arg', which when decoded 
turned out to be the path of the file sent to the exfil server by the Powershell backdoor web.ps1. This script was writted to parse the b64 string via regex and decode the b64 to the file path for all files transferred/RE matches. 
The 'arg' field size does appear to have a limiation, (106 char.?) that may be a Sonicwall specific limitation.'''

import base64
import argparse
import csv
import re


parser = argparse.ArgumentParser()
parser.add_argument('infile', type=str, help="Path to b64 file file")
parser.add_argument('outfile', type=str, help=".csv file to write output to")
args = parser.parse_args()


#writes headers for output .csv file
		
def write_headers(headers):
    with open(args.outfile, 'w', newline='') as f1:
        out_writer = csv.writer(f1)
        out_writer.writerow(headers)
		
		
#writes data to the columns of the output .csv file
		
def write_data(output):
    with open(args.outfile, 'a', newline='') as f2:
        out_writer = csv.writer(f2)
        out_writer.writerow(output)
		
#Accepts the regex parsed b64 string in the 'arg' field of the firewall logs and decodes the b64. 
		
def decode_base64(encoded):

	#Because some lines were truncated, need to add padding. Any additionl padding (more than two ==) are automatically removed
	decoded = base64.b64decode(encoded + '==')
	
	#Does not use verify
	decodedstr = decoded.decode('utf-8', 'ignore')
	
	#output = (decodedstr + "," + encoded)
	output = decodedstr
	
	#returns the decoded b64 string (file path) to the calling func.
	return output
	
#Parses the 'arg' field from the input firewall log and passes it to the b64 decode function, then writes to the output .csv		
def parse_encoded(infile, outfile):
	
	#defines headers for column names and writes them by calling wirte_headers
	headers = ['Decoded_path','Encoded_path','ARG_Length', 'src_addr', 'src_hostname', 'dst_addr', 'bytes_sent']
	write_headers(headers)
	
	#opens input file as command-line arg.
	with open(infile, 'r') as f1:
		a = f1.readlines()
		
		#Checks each line in input file for matching regex patterns, uses capture group to exclude all non-b64 characters, parsed source and destination addresses as well as bytes sent
		for line in a:
			enc = r'arg\=\/form\?p=([a-zA-Z0-9=]+)'
			src = r'src\=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
			dst = r'dst\=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
			sent = r'sent\=([0-9]+)'
			host = r'([a-zA-Z0-9\-]+)/'
			encoded = re.search(enc, line).group(1)
			src2 = re.search(src, line).group(1)
			dst2 = re.search(dst, line).group(1)
			sent2 = re.search(sent, line).group(1)
			
			
			#If there's an RE match, call the b64 decode function and write encoded string, decoded strings, and encoded b64 str. length
			if encoded:
				b = encoded
				output = decode_base64(encoded)
				hostname = re.search(host, output).group(1)
				d = output,b,len(b),src2,hostname,dst2,sent2
				print(d)
				write_data(d)
				
					
parse_encoded(args.infile, args.outfile)
