## FlowLogParser
Flow Log Parser - Illumio Technical assessment

This program processes AWS VPC flow logs and maps each flow to a tag based on a lookup table of 'dstport' and 'protocol'. It outputs the count of logs per tag and per port/protocol combination. 

## Requirements

- The program is written in Python completely.
- No external dependencies or libraries are required or need to be installed


## Steps to run the program

1. Clone the repository to your local machine:
   
   git clone https://github.com/Sanket2596/FlowLogParser.git
   cd FlowLogParser
   cd src

2. Inside src -> Run the command: python flow_log_parser.py.

-> The program will generate two output files: in the output directory
1. tag_counts.csv: Count of matches for each tag.
2. port_protocol_counts.csv: Count of matches for each port/protocol combination.

# Assumptions that were made while running the program:

1) The program only supports the default flow log format, version 2, based on the given example and it was assumed that this is the only valid version logs that will be supported. Hence, the progam does not handle custom formats or other versions.

2) The protocol field is case-insensitive, meaning "TCP" and "tcp" are treated as equivalent.
Explanations for assumption -> The program converts all protocol values to lowercase before matching, so entries in the flow log can have "TCP", "tcp", or any other case variation, and they will still be matched correctly.

3) Any log entry that does not match any dstport/protocol combination in the lookup table is counted as "Untagged" and grouped accordingly.
Explanation for assumption -> log entry doesn’t have a corresponding tag in the lookup table, it’s classified as "Untagged" in the final output. This makes sure that no entry in the logs is left unaccounted for and can be categorized into some of the category.

4) The 7th row in the log entry file is the protocol number which defines either it is tcp or udp checking the number.
-> Based on the sample output provided it was assumed that 6 -> tcp and 17 -> udp protocol and thus the conditions were handled accordingly and if any other number that 6 or 17 then protocol was categorized into unkown category.

5) The program assumes the fields in each flow log entry follow the exact ordering as in the example logs (e.g., dstport at index 5 and protocol at index 7).
-> Based on the provided sample output the program written mainly relies on the fixed positioning of these fields for parsing. If the log format changes or fields appear in a different order, the code will fail or produce incorrect results. SO the ordering of the log fields is assumed to be in the given order and will always remain in that order.

# General functioining or analysis of the code:

1) Basic functionality: The script effectively reads network logs and correlates them with a predefined lookup table, helping to identify how often certain network interactions occur based on defined tags.

2) Data Handling: The use of dictionaries allows for efficient lookups and counting, making the processing of logs straightforward.

3) Output: Writing results to CSV files makes it easy to view and analyze the counts of tags and port/protocol combinations.

4) Modularity: The code is well-structured and modularized with separate functions for different tasks, making it easier to read, maintain, and test the code.

## Test Cases: 

1) Test Case 1 - Basic Functionality: Tests that the parser works correctly when there are matches between flow log entries and the lookup table.
2) Test Case 2 - No Matches: Tests that the parser correctly categorizes entries as "Untagged" when there are no matches in the lookup table.
3) Test Case 3 - Multiple Entries for the Same Tag: Tests that the parser counts multiple occurrences of the same port/protocol combination correctly.
4) Test Case 4 - Mixed Protocols: Tests that the parser can handle entries with different protocols (TCP and UDP) and count them correctly.
5) Test Case 5 - Case insensitive: Test case to verify that the flow log parser correctly handles case insensitivity in protocol names when looking up tags from the lookup table.


## Steps to exceute the Test cases:
-> Run the following command for running the test case file:
        python -m unittest test_flow_log_parser.py