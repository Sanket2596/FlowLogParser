## FlowLogParser
Flow Log Parser - Illumio Technical assessment

This program processes AWS VPC flow logs and maps each flow to a tag based on a lookup table of `dstport` and `protocol`. It outputs the count of logs per tag and per port/protocol combination. 

## Requirements

- The program is written in Python completely.
- No external dependencies or libraries are required or need to be installed


## Steps to run the program

1. Clone the repository to your local machine:
   
   git clone https://github.com/Sanket2596/FlowLogParser.git
   cd FlowLogParser

2. Run the command: python flow_log_parser.py.

-> The program will generate two output files:
1. tag_counts.csv: Count of matches for each tag.
2. port_protocol_counts.csv: Count of matches for each port/protocol combination.



