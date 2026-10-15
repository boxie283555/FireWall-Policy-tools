import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import xml.etree.ElementTree as ET

from fastapi import HTTPException
from app import panos_online as pan, storage

CONFIG = '''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase><security><rules>
<entry name="web"><from><member>trust</member></from><to><member>untrust</member></to><source><member>any</member></source><destination><member>server</member></destination><service><member>application-default</member></service><application><member>web-browsing</member></application><action>allow</action><profile-setting><group><member>strict</member></group></profile-setting><log-end>yes</log-end></entry>
<entry name="deny"><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source><destination><member>any</member></destination><service><member>any</member></service><application><member>any</member></application><action>deny</action></entry>
</rules></security></rulebase></entry></vsys></entry></devices></config>'''


class OnlineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.patches = [patch.object(storage, 'DATA_DIR', Path(self.temp.name)), patch.object(storage, 'DB_PATH', Path(self.temp.name)/'test.db')]
        for item in self.patches: item.start()
        storage.init_db()
        self.current = ET.fromstring(CONFIG)
        self.running = copy.deepcopy(self.current)
        self.calls = []
        self.session = pan.Session('192.0.2.1', 443, 'test', 'test-secret', read_only=False)
        pan._sessions['test-token'] = self.session
        self.patches.append(patch.object(pan, 'api_call', self.api))
        self.patches[-1].start()

    def tearDown(self):
        pan._sessions.clear()
        for item in reversed(self.patches): item.stop()
        self.temp.cleanup()

    def api(self, session, params):
        self.calls.append(dict(params))
        if params.get('cmd') == '<check><pending-changes/></check>':
            pending = 'yes' if pan.revision(self.current) != pan.revision(self.running) else 'no'
            return ET.fromstring(f'<response status="success"><result>{pending}</result></response>')
        if params.get('action') == 'show' or params.get('cmd') == '<show><config><candidate/></config></show>':
            result = ET.Element('response', status='success')
            ET.SubElement(result, 'result').append(copy.deepcopy(self.running if params.get('action')=='show' else self.current))
            return result
        if params.get('type') == 'commit':
            return ET.fromstring('<response status="success"><result><job>9</job></result></response>')
        return ET.fromstring('<response status="success"><msg>ok</msg></response>')

    def body(self, **kwargs):
        data = dict(name='web', operation='edit', revision=pan.revision(self.current), xml=self.changed_xml())
        data.update(kwargs)
        return pan.Preview(**data)

    def changed_xml(self):
        rule = copy.deepcopy(self.current.find('.//rules/entry'))
        rule.find('./source/member').text = 'approved-client'
        return ET.tostring(rule, encoding='unicode')

    def preview(self, **kwargs):
        return pan.preview(self.body(**kwargs), 'test-token')

    def writes(self):
        return [c for c in self.calls if c.get('type') == 'commit' or (c.get('type') == 'config' and c.get('action') not in {'get','show'})]

    def test_read_only_allows_preview_but_blocks_execution(self):
        self.session.read_only = True
        result = self.preview()
        self.assertIn('risk_changes', result)
        for execute in (pan.apply, pan.commit):
            with self.assertRaises(HTTPException) as raised:
                execute(pan.Execute(preview_id=result['preview_id'], confirm=True), 'test-token')
            self.assertEqual(raised.exception.status_code, 403)
        self.assertFalse(self.writes())

    def test_optimization_reports_resolved_findings(self):
        result = self.preview()
        changes = result['risk_changes']
        self.assertLess(changes['after_count'], changes['before_count'])
        self.assertTrue(any(f['category'] == 'broad-scope' for f in changes['resolved']))
        self.assertFalse(self.writes())

    def test_read_and_preview_do_not_write(self):
        result = pan.read_rules(pan.Scope(), 'test-token')
        self.assertEqual(len(result['rules']), 2)
        self.assertFalse(result['has_pending_changes'])
        self.assertTrue(result['findings'])
        result = self.preview()
        self.assertIn('approved-client', result['diff'])
        self.assertFalse(self.writes())

    def test_edit_retains_profiles_and_requires_confirmation(self):
        result = self.preview()
        with self.assertRaises(HTTPException):
            pan.apply(pan.Execute(preview_id=result['preview_id']), 'test-token')
        self.assertFalse(self.writes())
        pan.apply(pan.Execute(preview_id=result['preview_id'], confirm=True), 'test-token')
        write = self.writes()[0]
        self.assertEqual(write['action'], 'edit')
        self.assertIn('profile-setting', write['element'])
        self.assertIn('<log-end>yes</log-end>', write['element'])
        self.assertNotIn('commit', str(self.writes()))

    def test_stale_candidate_prevents_write(self):
        result = self.preview()
        ET.SubElement(self.current, 'other-admin-setting').text='changed'
        with self.assertRaises(HTTPException) as raised:
            pan.apply(pan.Execute(preview_id=result['preview_id'], confirm=True), 'test-token')
        self.assertEqual(raised.exception.status_code, 409)
        self.assertFalse(self.writes())

    def test_write_preview_is_single_use(self):
        result=self.preview()
        request=pan.Execute(preview_id=result['preview_id'],confirm=True)
        pan.apply(request,'test-token')
        with self.assertRaises(HTTPException): pan.apply(request,'test-token')
        self.assertEqual(len(self.writes()),1)

    def test_timeout_consumes_plan(self):
        result=self.preview()
        request=pan.Execute(preview_id=result['preview_id'],confirm=True)
        original=self.api
        def fail(session,params):
            if params.get('action')=='edit': raise HTTPException(502,'timeout')
            return original(session,params)
        with patch.object(pan,'api_call',fail):
            with self.assertRaises(HTTPException): pan.apply(request,'test-token')
        self.assertNotIn(result['preview_id'],self.session.plans)

    def test_move_order_and_missing_target(self):
        result=self.preview(operation='move',where='after',destination='deny')
        self.assertIn('web',result['diff'])
        plan=self.session.plans[result['preview_id']]
        self.assertEqual(plan['params']['dst'],'deny')
        with self.assertRaises(HTTPException): self.preview(operation='move',destination='missing')

    def test_create_duplicate_delete_and_scope_validation(self):
        with self.assertRaises(HTTPException): self.preview(operation='create')
        result=self.preview(operation='delete')
        self.assertEqual(self.session.plans[result['preview_id']]['params']['action'],'delete')
        with self.assertRaises(HTTPException): self.preview(vsys='vsys404')
        self.assertFalse(self.writes())

    def test_create_and_delete_security_and_nat_rules(self):
        for kind in ('security', 'nat'):
            with self.subTest(kind=kind):
                scope = pan.Scope(kind=kind)
                rules, _ = pan.rules_node(self.current, scope, create=True)
                entry = ET.fromstring(self.changed_xml())
                entry.set('name', 'new-rule')
                ET.SubElement(entry, 'disabled').text = 'yes'
                if kind == 'nat':
                    service = entry.find('service')
                    service.clear()
                    service.text = 'any'
                    entry.remove(entry.find('action'))
                    entry.remove(entry.find('application'))
                xml = ET.tostring(entry, encoding='unicode')
                result = self.preview(kind=kind, operation='create', name='new-rule', xml=xml)
                self.assertEqual(self.session.plans[result['preview_id']]['params']['action'], 'set')
                pan.apply(pan.Execute(preview_id=result['preview_id'], confirm=True), 'test-token')
                self.assertIn('<disabled>yes</disabled>', self.writes()[-1]['element'])
                rules.append(entry)
                result = self.preview(kind=kind, operation='delete', name='new-rule')
                pan.apply(pan.Execute(preview_id=result['preview_id'], confirm=True), 'test-token')
                self.assertEqual(self.writes()[-1]['action'], 'delete')
                self.assertIn('/' + kind + '/rules/', self.writes()[-1]['xpath'])
        self.assertFalse(any(call.get('type') == 'commit' for call in self.writes()))

    def test_invalid_xml_and_name_cannot_target_another_rule(self):
        for xml in ['<entry/>', '<!DOCTYPE entry [<!ENTITY x "y">]><entry name="web"/>', '<entry name="different"/>', '<entry name="web"><source/></entry>']:
            with self.assertRaises(HTTPException): self.preview(xml=xml)
        self.assertFalse(self.writes())

    def test_commit_preview_redacts_and_checks_entire_device(self):
        ET.SubElement(self.current, 'password').text='private-value'
        result=pan.commit_preview('test-token')
        self.assertNotIn('private-value',result['diff'])
        self.assertIn('[redacted]',result['diff'])
        response=pan.commit(pan.Execute(preview_id=result['preview_id'],confirm=True),'test-token')
        self.assertEqual(response['job_id'],'9')
        self.assertFalse(response['completed'])
        self.assertEqual(self.writes()[0]['type'],'commit')

    def test_changed_running_config_prevents_commit(self):
        ET.SubElement(self.current,'setting').text='new'
        result=pan.commit_preview('test-token')
        ET.SubElement(self.running,'someone-committed').text='yes'
        with self.assertRaises(HTTPException): pan.commit(pan.Execute(preview_id=result['preview_id'],confirm=True),'test-token')
        self.assertFalse(self.writes())

    def test_no_changes_and_expired_sessions(self):
        with self.assertRaises(HTTPException): pan.commit_preview('test-token')
        self.session.expires=0
        with self.assertRaises(HTTPException) as raised: pan.read_rules(pan.Scope(),'test-token')
        self.assertEqual(raised.exception.status_code,401)

    def test_job_success_requires_fin_and_ok(self):
        for status,result,expected in [('ACT','PEND',False),('FIN','FAIL',False),('FIN','OK',True)]:
            with patch.object(pan,'api_call',return_value=ET.fromstring(f'<response><result><job><status>{status}</status><result>{result}</result></job></result></response>')):
                self.assertEqual(pan.job_status(9,'test-token')['succeeded'],expected)

    def test_drift_hash_ignores_api_metadata_but_preserves_rule_order(self):
        other=copy.deepcopy(self.current)
        other.find('.//rules/entry').set('admin','someone')
        self.assertEqual(pan.revision(self.current),pan.revision(other))
        rules=other.find('.//rules'); first=rules[0];rules.remove(first);rules.append(first)
        self.assertNotEqual(pan.revision(self.current),pan.revision(other))

    def test_attribute_order_is_not_configuration_drift(self):
        a=ET.fromstring('<entry name="web" uuid="abc"/>')
        b=ET.fromstring('<entry uuid="abc" name="web"/>')
        self.assertEqual(pan.revision(a),pan.revision(b))

    def test_device_pending_status_is_distinct_from_snapshot_difference(self):
        ET.SubElement(self.current,'phash').text='changed-value'
        original=self.api
        def api(session,params):
            if params.get('cmd')=='<check><pending-changes/></check>':
                return ET.fromstring('<response status="success"><result>no</result></response>')
            return original(session,params)
        with patch.object(pan,'api_call',api):
            result=pan.read_rules(pan.Scope(),'test-token')
            self.assertFalse(result['has_pending_changes'])
            self.assertTrue(result['has_config_differences'])
            with self.assertRaises(HTTPException): pan.commit_preview('test-token')
        self.assertFalse(self.writes())


class TransportReadOnlyTests(unittest.TestCase):
    def test_default_session_blocks_writes_before_network(self):
        session = pan.Session('192.0.2.1', 443, 'test', 'secret')
        with patch.object(pan.request, 'build_opener') as network:
            for params in ({'type': 'commit'}, {'type': 'config', 'action': 'edit'},
                           {'type': 'config', 'action': 'move'}, {'type': 'config', 'action': 'delete'},
                           {'type': 'config', 'action': 'set'}):
                with self.assertRaises(HTTPException) as raised:
                    pan.api_call(session, params)
                self.assertEqual(raised.exception.status_code, 403)
            network.assert_not_called()


if __name__=='__main__': unittest.main()
