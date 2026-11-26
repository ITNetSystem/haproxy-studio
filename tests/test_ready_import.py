from test_services import ServicesFixture
from haproxy_studio.importer import Importer

class ReadyImportTests(ServicesFixture):
    def source(self):
        checked,draft=self.preview(self.data());self.assertTrue(checked['ok']);return draft['raw']
    def request(self,raw):
        value=dict(source='file',content=raw.decode(),revision=self.engine.snapshot()[1]);report=Importer(self.manager).scan(value);return dict(value,fingerprint=report['fingerprint'],selected=[],replace_confirm=True),report
    def test_ready_file_without_new_publications_is_loaded_exactly(self):
        raw=self.source();before=self.config.read_bytes();value,report=self.request(raw);self.assertTrue(report['ready_config']);self.assertEqual(1,report['managed']);checked,draft=Importer(self.manager).preview(value);self.assertTrue(checked['ok'],checked['output']);self.assertEqual(raw,draft['raw']);self.assertEqual(before,self.config.read_bytes())
    def test_ready_file_still_requires_confirmation_and_revision(self):
        from haproxy_studio.core import Conflict
        value,report=self.request(self.source())
        with self.assertRaises(ValueError):Importer(self.manager).preview(dict(value,replace_confirm=False))
        with self.assertRaises(Conflict):Importer(self.manager).preview(dict(value,revision='stale'))
        with self.assertRaises(Conflict):Importer(self.manager).preview(dict(value,fingerprint='stale'))
    def test_current_config_still_requires_selection_and_invalid_file_is_rejected(self):
        raw=self.source();self.config.write_bytes(raw);value=dict(source='current',revision=self.engine.snapshot()[1]);report=Importer(self.manager).scan(value);self.assertFalse(report['ready_config'])
        with self.assertRaises(ValueError):Importer(self.manager).preview(dict(value,fingerprint=report['fingerprint'],selected=[]))
        value,report=self.request(raw+b'unknown-section bad\n');checked,draft=Importer(self.manager).preview(value);self.assertFalse(checked['ok']);self.assertEqual(raw,self.config.read_bytes())
