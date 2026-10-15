import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import storage
from app.models import ParseResult, PolicyRule, NatRule, Vendor
from app.remediation import (CommandRequest, RemediationRequest, generate_commands,
                            init_remediation, list_remediations, save_remediation)


class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.patches = [patch.object(storage, 'DATA_DIR', Path(self.temp.name)),
                        patch.object(storage, 'DB_PATH', Path(self.temp.name) / 'test.db')]
        for item in self.patches:
            item.start()
        storage.init_db()
        init_remediation()
        self.rule = PolicyRule(id='p1', vendor=Vendor.palo_alto, device_name='lab', rule_name='business access',
                               source_addresses=['any'], destination_addresses=['server'], services=['https'],
                               raw='set rulebase security rules "business access" source any')
        self.import_rule(self.rule)

    def tearDown(self):
        for item in self.patches:
            item.stop()
        self.temp.cleanup()

    def import_rule(self, rule):
        storage.save_parse_result(ParseResult(vendor=rule.vendor, device_name=rule.device_name, policies=[rule], objects=[]))

    def test_pa_replaces_instead_of_appending_and_rolls_back(self):
        result = generate_commands(CommandRequest(kind='policy', rule_id='p1', operation='source', values=['approved-client'], context='local-rulebase'))
        self.assertIn('delete rulebase security rules "business access" source', result['commands'])
        self.assertIn('[ "approved-client" ]', result['commands'])
        self.assertIn('[ "any" ]', result['rollback'])
        self.assertNotIn('\ncommit', result['commands'])

    def test_disable_rollback_preserves_disabled_state(self):
        self.rule.enabled = False
        self.import_rule(self.rule)
        result = generate_commands(CommandRequest(kind='policy', rule_id='p1', operation='disable', context='local-rulebase'))
        self.assertIn('disabled yes', result['rollback'])

    def test_forti_numeric_id_and_context(self):
        self.import_rule(PolicyRule(id='f1', vendor=Vendor.fortinet, device_name='forti', rule_name='named', raw='edit 42\nset srcaddr "all"', source_addresses=['all']))
        result = generate_commands(CommandRequest(kind='policy', rule_id='f1', operation='source', values=['clients'], context='firewall-policy'))
        self.assertIn('edit 42', result['commands'])
        self.assertIn('set srcaddr "all"', result['rollback'])

    def test_rejects_unknown_scope_and_injection(self):
        for context, values in [('panorama', ['client']), ('local-rulebase', ['client\ncommit']), ('local-rulebase', ['x";delete'])]:
            with self.assertRaises(ValueError):
                generate_commands(CommandRequest(kind='policy', rule_id='p1', operation='source', values=values, context=context))

    def test_tickets_survive_reimport_and_keep_snapshots(self):
        ticket = RemediationRequest(title='Fix broad rule', owner='Network team', category='broad-scope', kind='policy', rule_ids=['p1'], plan='Narrow source')
        saved = save_remediation(ticket)
        ticket.status = 'in_progress'
        ticket.plan = 'Approved scope recorded'
        save_remediation(ticket, saved['id'])
        storage.save_parse_result(ParseResult(vendor=Vendor.palo_alto, device_name='lab', policies=[], objects=[]))
        ticket.status = 'implemented'
        save_remediation(ticket, saved['id'])
        row = list_remediations()[0]
        self.assertEqual(row['status'], 'implemented')
        self.assertEqual(row['rule_snapshots'][0]['source_addresses'], ['any'])
        self.assertEqual(sum(row['event'] == 'update_remediation' for row in storage.list_audit_log()), 2)

    def test_missing_rules_and_immutable_association(self):
        ticket = RemediationRequest(title='Fix', owner='Team', category='broad-scope', kind='policy', rule_ids=['missing'], plan='Review')
        with self.assertRaises(ValueError):
            save_remediation(ticket)
        ticket.rule_ids = ['p1']
        saved = save_remediation(ticket)
        ticket.category = 'unused'
        with self.assertRaises(ValueError):
            save_remediation(ticket, saved['id'])

    def test_unsupported_vendor_and_missing_rule_emit_no_commands(self):
        self.import_rule(PolicyRule(id='a1', vendor=Vendor.cisco_asa, device_name='asa', rule_name='ACL', raw='access-list ACL extended permit ip any any'))
        with self.assertRaises(ValueError):
            generate_commands(CommandRequest(kind='policy', rule_id='a1', operation='disable', context='asa'))
        with self.assertRaises(KeyError):
            generate_commands(CommandRequest(kind='policy', rule_id='missing', operation='disable', context='local-rulebase'))

    def test_nat_single_service(self):
        nat = NatRule(id='n1', vendor=Vendor.palo_alto, device_name='nat', rule_name='publish', original_services=['any'])
        storage.save_parse_result(ParseResult(vendor=Vendor.palo_alto, device_name='nat', policies=[], objects=[], nat_rules=[nat]))
        with self.assertRaises(ValueError):
            generate_commands(CommandRequest(kind='nat', rule_id='n1', operation='service', values=['https', 'ssh'], context='local-rulebase'))
        result = generate_commands(CommandRequest(kind='nat', rule_id='n1', operation='service', values=['https'], context='local-rulebase'))
        self.assertIn('service "https"', result['commands'])


if __name__ == '__main__':
    unittest.main()
