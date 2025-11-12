"""
Test cases for Azure Vulnerability Scanner
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from vulnerability_scanner import AzureVulnerabilityScanner

class TestVulnerabilityScanner(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.mock_credential = Mock()
        self.mock_subscription_id = "test-subscription-id"
        
        # Create scanner instance with mocked clients
        self.scanner = AzureVulnerabilityScanner(
            self.mock_credential, 
            self.mock_subscription_id
        )
    
    @patch('vulnerability_scanner.ComputeManagementClient')
    def test_scan_virtual_machines(self, mock_compute_client):
        """Test VM vulnerability scanning"""
        # Mock VM data
        mock_vm = Mock()
        mock_vm.name = "test-vm"
        mock_vm.id = "/subscriptions/test/resourceGroups/test-rg/providers/Microsoft.Compute/virtualMachines/test-vm"
        mock_vm.storage_profile.os_disk.encryption_settings = None
        mock_vm.storage_profile.os_disk.os_type = "Windows"
        mock_vm.storage_profile.image_reference.offer = "WindowsServer2012"
        
        mock_compute_client.return_value.virtual_machines.list_all.return_value = [mock_vm]
        
        # Run scan
        vulnerabilities = self.scanner.scan_virtual_machines()
        
        # Assertions
        self.assertIsInstance(vulnerabilities, list)
        self.assertGreater(len(vulnerabilities), 0)
        
        # Check for specific vulnerabilities
        vuln_types = [v['vulnerability'] for v in vulnerabilities]
        self.assertIn('Disk not encrypted', vuln_types)
        self.assertIn('Outdated Windows version', vuln_types)
    
    @patch('vulnerability_scanner.StorageManagementClient')
    def test_scan_storage_accounts(self, mock_storage_client):
        """Test storage account vulnerability scanning"""
        # Mock storage account data
        mock_account = Mock()
        mock_account.name = "teststorage"
        mock_account.id = "/subscriptions/test/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage"
        mock_account.allow_blob_public_access = True
        mock_account.encryption = None
        
        mock_network_rule_set = Mock()
        mock_network_rule_set.default_action = "Allow"
        mock_account.network_rule_set = mock_network_rule_set
        
        mock_storage_client.return_value.storage_accounts.list.return_value = [mock_account]
        
        # Run scan
        vulnerabilities = self.scanner.scan_storage_accounts()
        
        # Assertions
        self.assertIsInstance(vulnerabilities, list)
        self.assertGreater(len(vulnerabilities), 0)
        
        vuln_types = [v['vulnerability'] for v in vulnerabilities]
        self.assertIn('Public blob access enabled', vuln_types)
        self.assertIn('Encryption not enabled', vuln_types)
        self.assertIn('Network access too permissive', vuln_types)
    
    @patch('vulnerability_scanner.NetworkManagementClient')
    def test_scan_network_security_groups(self, mock_network_client):
        """Test NSG vulnerability scanning"""
        # Mock NSG data with insecure rule
        mock_nsg = Mock()
        mock_nsg.name = "test-nsg"
        mock_nsg.id = "/subscriptions/test/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-nsg"
        
        mock_rule = Mock()
        mock_rule.name = "insecure-rule"
        mock_rule.direction = "Inbound"
        mock_rule.source_address_prefix = "0.0.0.0/0"
        mock_rule.destination_port_range = "22"
        
        mock_nsg.security_rules = [mock_rule]
        
        mock_network_client.return_value.network_security_groups.list_all.return_value = [mock_nsg]
        
        # Run scan
        vulnerabilities = self.scanner.scan_network_security_groups()
        
        # Assertions
        self.assertIsInstance(vulnerabilities, list)
        self.assertGreater(len(vulnerabilities), 0)
        
        # Should detect insecure SSH rule
        self.assertIn('Insecure rule: insecure-rule', vulnerabilities[0]['vulnerability'])
        self.assertEqual('High', vulnerabilities[0]['severity'])
    
    def test_is_insecure_nsg_rule(self):
        """Test NSG rule security assessment"""
        # Test insecure SSH rule
        mock_rule = Mock()
        mock_rule.direction = "Inbound"
        mock_rule.source_address_prefix = "0.0.0.0/0"
        mock_rule.destination_port_range = "22"
        
        self.assertTrue(self.scanner._is_insecure_nsg_rule(mock_rule))
        
        # Test secure rule
        mock_rule.source_address_prefix = "10.0.0.0/24"
        self.assertFalse(self.scanner._is_insecure_nsg_rule(mock_rule))
    
    def test_calculate_security_score(self):
        """Test security score calculation"""
        # Test with no vulnerabilities
        self.scanner.scan_results = []
        score = self.scanner._calculate_security_score()
        self.assertEqual(100, score)
        
        # Test with vulnerabilities
        self.scanner.scan_results = [
            {'severity': 'High'},
            {'severity': 'High'},
            {'severity': 'Medium'}
        ]
        score = self.scanner._calculate_security_score()
        self.assertLess(score, 100)

if __name__ == '__main__':
    unittest.main()
