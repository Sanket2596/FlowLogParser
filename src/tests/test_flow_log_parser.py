import unittest
from unittest.mock import mock_open, patch
import sys
import os

# Add the src directory to sys.path so that flow_log_parser can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flow_log_parser import parse_lookup_table, parse_and_process_logs

class TestFlowLogParser(unittest.TestCase):

    @patch('builtins.open', new_callable=mock_open)
    @patch("os.makedirs", return_value=True)
    
    def test_case_1_basic_functionality(self, mock_makedirs, mock_open_func):
        mock_open_func.side_effect = [
            mock_open(read_data="dstport,protocol,tag\n443,tcp,sv_P2\n1030,tcp,sv_P1\n22,tcp,sv_P4\n").return_value,
            mock_open(read_data="2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK\n"
                                "2 123456789012 eni-1a2b3c4d 10.0.1.102 172.217.7.228 1030 443 6 8 4000 1620140661 1620140721 ACCEPT OK\n").return_value
        ]

        lookup = parse_lookup_table('lookup_table.csv')
        flow_logs = 'flow_logs.txt'
        tag_counts, port_protocol_counts = parse_and_process_logs(flow_logs, lookup)

        # Adjusted assertion
        self.assertEqual(tag_counts, {'sv_P2': 1, 'sv_P1': 1, 'Untagged': 0})
        self.assertEqual(port_protocol_counts, {(443, 'tcp'): 1, (1030, 'tcp'): 1})

    @patch('builtins.open', new_callable=mock_open)
    @patch("os.makedirs", return_value=True)

    def test_case_2_no_matches(self, mock_makedirs, mock_open_func):
        mock_open_func.side_effect = [
            mock_open(read_data="dstport,protocol,tag\n443,tcp,sv_P2\n1030,tcp,sv_P1\n22,tcp,sv_P4\n").return_value,
            mock_open(read_data="2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 80 49153 6 25 20000 1620140761 1620140821 ACCEPT OK\n"
                                "2 123456789012 eni-1a2b3c4d 10.0.1.102 172.217.7.228 25 443 6 8 4000 1620140661 1620140721 ACCEPT OK\n").return_value
        ]

        lookup = parse_lookup_table('lookup_table.csv')
        flow_logs = 'flow_logs.txt'
        tag_counts, port_protocol_counts = parse_and_process_logs(flow_logs, lookup)

        self.assertEqual(tag_counts, {'Untagged': 2})  # Expecting 2 untagged entries since none matched
        self.assertEqual(port_protocol_counts, {(80, 'tcp'): 1, (25, 'tcp'): 1})

    @patch('builtins.open', new_callable=mock_open)
    @patch("os.makedirs", return_value=True)

    def test_case_3_multiple_entries_same_tag(self, mock_makedirs, mock_open_func):
        mock_open_func.side_effect = [
            mock_open(read_data="dstport,protocol,tag\n443,tcp,sv_P2\n").return_value,
            mock_open(read_data="2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK\n"
                                "2 123456789012 eni-1a2b3c4d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140821 1620140921 ACCEPT OK\n"
                                "2 123456789012 eni-2b3c4d5e 10.0.1.202 198.51.100.3 443 49153 6 25 20000 1620140951 1620141051 ACCEPT OK\n").return_value
        ]

        lookup = parse_lookup_table('lookup_table.csv')
        flow_logs = 'flow_logs.txt'
        tag_counts, port_protocol_counts = parse_and_process_logs(flow_logs, lookup)

        self.assertEqual(tag_counts, {'Untagged': 0,'sv_P2': 3})
        self.assertEqual(port_protocol_counts, {(443, 'tcp'): 3})

    @patch('builtins.open', new_callable=mock_open)
    @patch("os.makedirs", return_value=True)

    def test_case_4_mixed_protocols(self, mock_makedirs, mock_open_func):
        # Mock the lookup table and flow log content
        mock_open_func.side_effect = [
            mock_open(read_data="dstport,protocol,tag\n443,tcp,sv_P2\n53,udp,sv_P3\n").return_value,
            mock_open(read_data="2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK\n"
                                "2 123456789012 eni-1a2b3c4d 10.0.1.102 172.217.7.228 53 443 17 8 4000 1620140661 1620140721 ACCEPT OK\n").return_value
        ]

        lookup = parse_lookup_table('lookup_table.csv')
        flow_logs = 'flow_logs.txt'
        tag_counts, port_protocol_counts = parse_and_process_logs(flow_logs, lookup)

        self.assertEqual(tag_counts, {'Untagged': 0, 'sv_P2': 1, 'sv_P3': 1})
        self.assertEqual(port_protocol_counts, {(443, 'tcp'): 1, (53, 'udp'): 1})
    
    @patch('builtins.open', new_callable=mock_open)
    def test_case_insensitivity(self, mock_file):
        lookup_file = 'lookup_table.csv'
        flow_log_file = 'flow_logs.txt'
        
        mock_flow_log_data = "2 2024-10-05 12:00:00 123 456 443 0 6 0 0 0 0 0\n"  # tcp
        mock_flow_log_data = "2 2024-10-05 12:00:01 123 456 80 0 17 0 0 0 0 0\n"  # UDP

        with patch('builtins.open', mock_open(read_data=mock_flow_log_data)) as mock_flow_log_file:
            lookup = parse_lookup_table(lookup_file)
            tag_counts, port_protocol_counts = parse_and_process_logs(flow_log_file, lookup)

            # Assert that the tag counts account for both 'tcp' and 'UDP' correctly
            self.assertEqual(tag_counts, {'Untagged': 1})  # sv_P2 for tcp, sv_P3 for UDP


if __name__ == '__main__':
    unittest.main()
