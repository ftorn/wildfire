import requests
import xmltodict
import argparse
import os, sys

host = "https://wildfire.paloaltonetworks.com/publicapi"

headers = {  		
		'Accept': '*/*',
  		'User-agent': 'curl/7.47.1'
	  }

verdicts = { '0' : 'benign',
             '1' : 'malware',
             '2' : 'greyware',
             '100' : 'pending',
             '101' : 'error',
             '102' : 'not found'
           }

def read_apikey():
	try:
        	readf = lambda x: os.path.exists(x) and open(x, 'r')
        	return readf('apikey.txt').read().rstrip('\r\n')
	except:
		print "[*] Error!!The file 'apikey.txt' doesn't exist!! [*]"
		sys.exit(0)

def send_sample(f, types):
	if types is not None:
		link = f
		form_data = {
                	'apikey': read_apikey(),
                	'link': f
        		}

        	multipart_form_data = {
                	'link': f
        		}
		response = requests.post(host + '/submit/link', data=form_data, files=multipart_form_data, headers=headers)
               	print "[*] At this moment wildfire doesn't generate any report for the link.. [*]"	
        	checkc = lambda s: s == 200 and response.text or "[*] Error code: " + str(status_code) + " [*]"
		print str(checkc(response.status_code))
	else:
		sample = f
		form_data = {
    			'apikey': read_apikey()
			}

		multipart_form_data = {
    			'file': open(f, 'rb')
			}

		response = requests.post(host + '/submit/file', data=form_data, files=multipart_form_data, headers=headers)
        	print "[*] Try to send sample to wildfire...[*]"
		if response.status_code == 200:
        		print "[*] Ok, I send sample to wildfire...[*]"
			xml = xmltodict.parse(response.text)
                	hash_file = xml['wildfire']['upload-file-info']['md5']
			cf = lambda x: os.path.exists(x) and sys.exit(0)
			cf('sample/' + f + '_' + str(hash_file))
			print "[*] Write file upload-file-info.xml in sample dir [*]"
			os.makedirs('sample/' + f + '_' + str(hash_file))
			with open('sample/' + f + '_' + str(hash_file) + '/upload-file-info.xml', "wb") as code:
				code.write(response.text)
		else:
			print "[*] Error code: " + str(response.status_code) + " [*]"


def download_report(file,format):
	
	hash = file.split("_")[1]

        form_data = {
                'apikey': read_apikey(),
		'hash': hash,
		'format': format
        }

        response = requests.post(host + '/get/report', data=form_data, headers=headers)
        verdict = requests.post(host + '/get/verdict', data=form_data, headers=headers)
	if os.path.exists('sample/' + file):
        	if response.status_code == 200:
			print "Download report: " + file + '.' + format
			with open('sample/' + file + '/report_' + file + '.' + format, "wb") as code:
        			code.write(response.content)
			xml = xmltodict.parse(verdict.text)
			v = str(xml['wildfire']['get-verdict-info']['verdict'])
			for key in verdicts:
				if v == '1' and key == v:
					print "Verdict report " + file + " : " + verdicts[key]
					if not os.path.exists('sample/' + file + '/' + file + '.pcap'):
						print "Download .pcap file..."
                        			response_pcap = requests.post(host + '/get/pcap', data=form_data, headers=headers)
                        			with open('sample/' + file + '/' + file + '.pcap', "wb") as code:
                        				code.write(response_pcap.content)
				elif key == v:
					print "Verdict report " + file + " : " + verdicts[key]
		else:
			print "Error code: " + str(response.status_code)
			print "[!] Report doesn't exist yet! You have to first upload the sample" 
			print "[!] or wait about 5 minutes after the submission"
	else:
		print "[!] Report doesn't exist yet! You have to first upload the sample" 
		print "[!] or wait about 5 minutes after the submission"
		sys.exit(0)

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
    	parser.add_argument("-sf", "--file", help="-sf sample.exe")
    	parser.add_argument("-sl", "--link", help="-sl http://www.google.com")
    	parser.add_argument("-dpdf", "--download_pdf", help="-d sample.exe_c699c279309d24ce779e1ffc44c199bd [!] please, look inside sample dir]")
    	parser.add_argument("-dxml", "--download_xml", help="-d sample.exe_c699c279309d24ce779e1ffc44c199bd [!] please, look inside sample dir]")
    	args = parser.parse_args()
    	if not args.file and not (args.download_pdf or args.download_xml or args.link):
        	print "[!] No operation specified! Try --help."
        	sys.exit(-1)

	if args.file:
		send_sample(sys.argv[2], None)
	if args.link:
		send_sample(sys.argv[2], types='link')
	if args.download_pdf:
		download_report(sys.argv[2], 'pdf')
	if args.download_xml:
		download_report(sys.argv[2], 'xml')
