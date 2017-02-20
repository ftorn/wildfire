PaloAlto Wildfire send and download report/pcap
===============================================

## Docker way
- cd /wildfire
- Insert your wildfire key in the 'apikey.txt' file
- Execute:
  - docker build -t wildfire .
  - docker run --rm wildfire 

## Or 
- cd /wildfire
- Insert your wildfire key in the 'apikey.txt' file
- Execute:
  - pip install -r requirements.txt
  - python ./wildfire_send.py -h
