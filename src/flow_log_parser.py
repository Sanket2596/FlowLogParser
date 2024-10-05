import csv
import os

def parse_lookup_table(lookup_file):
    lookup = {}
    # parse the lookup table file and add port, protocol to it.
    with open(lookup_file, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            port = int(row['dstport'])
            protocol = row['protocol'].lower()
            tag = row['tag']
            lookup[(port, protocol)] = tag
    return lookup

def parse_and_process_logs(flow_log_file, lookup):
    # Initialize dictionaries to store tag and port/protocol combination counts
    tag_counts = {}
    port_protocol_counts = {}

    with open(flow_log_file, mode='r') as file:
        for row in file:
            if row.startswith("2"):
                # Parse the flow log line
                fields = row.split()
                # Extracting the specific port and protocol while parsing through the fields of logs 
                dstport = int(fields[5]) 
                protocol_num = fields[7]  
                
                # Convert protocol number to string representation
                if protocol_num == '6':
                    protocol = 'tcp'
                elif protocol_num == '17':
                    protocol = 'udp'
                else:
                    protocol = 'unknown'
                
                # Lookup the tag for the port/protocol
                tag = lookup.get((dstport, protocol), "Untagged")
                
                # Count the tag
                if tag in tag_counts:
                    tag_counts[tag] += 1
                else:
                    tag_counts[tag] = 1
                
                # Count the port/protocol combination
                port_protocol_key = (dstport, protocol)

                # Checking if key is already in the port_protocol_counts dictionary if not then adding and then counting
                if port_protocol_key in port_protocol_counts:
                    port_protocol_counts[port_protocol_key] += 1
                else:
                    port_protocol_counts[port_protocol_key] = 1

    return tag_counts, port_protocol_counts

def write_output(tag_counts, port_protocol_counts, output_directory):
    tag_output_file = os.path.join(output_directory, 'tag_counts.csv')

    # Write Tag Counts -> this will print the output in the required format
    with open(tag_output_file, mode='w') as file:
        file.write("Tag,Count\n")
        for tag, count in tag_counts.items():
            file.write(f"{tag},{count}\n")
    
    port_protocol_output_file = os.path.join(output_directory, 'port_protocol_counts.csv')
    # Write Port/Protocol Combination Counts -> this will print the output in the required format
    with open(port_protocol_output_file, mode='w') as file:
        file.write("Port,Protocol,Count\n")
        for (port, protocol), count in port_protocol_counts.items():
            file.write(f"{port},{protocol},{count}\n")

def main():
    # Input files
    flow_log_file = 'flow_logs.txt'
    lookup_file = 'lookup_table.csv'
    output_directory = 'outputs'

   # Create outputs directory if it doesn't exist
    os.makedirs(output_directory, exist_ok=True)


     # Load the lookup table
    lookup = parse_lookup_table(lookup_file)
    tag_counts, port_protocol_counts = parse_and_process_logs(flow_log_file, lookup)

    # Call the updated write_output function
    write_output(tag_counts, port_protocol_counts, output_directory)


if __name__ == '__main__':
    main()
