from test_services import ServicesFixture,BASE
from haproxy_studio.selfpublish import protect_publication
from unittest.mock import patch

class SelfProtectionTests(ServicesFixture):
    def published(self):
        return BASE.split(b'frontend legacy')[0]+b'frontend studio\n bind 127.0.0.1:19000\n mode http\n default_backend studio\nbackend studio\n mode http\n server local 127.0.0.1:9130\n'
    def test_replacement_missing_panel_is_blocked_before_write(self):
        previous=self.published();self.config.write_bytes(previous);result,draft=self.engine.preview(BASE.decode(),self.engine.snapshot()[1]);self.assertFalse(result['ok']);self.assertIn('публикацию самой',result['output'])
        with patch.object(self.engine,'command') as command:
            with self.assertRaisesRegex(ValueError,'публикацию самой'):self.engine.apply(draft)
            command.assert_not_called()
        self.assertEqual(previous,self.config.read_bytes())
    def test_removing_route_with_unused_panel_pool_is_also_blocked(self):
        previous=self.published();self.config.write_bytes(previous)
        with self.assertRaises(ValueError):protect_publication(self.engine,previous,previous.replace(b' default_backend studio\n',b''))
    def test_rename_and_additional_files_preserve_panel(self):
        previous=self.published();self.config.write_bytes(previous);candidate=previous.replace(b'backend studio',b'backend panel')
        protect_publication(self.engine,previous,candidate)
        extra=self.extra/'studio.cfg';extra.write_bytes(previous);self.config.write_bytes(BASE);protect_publication(self.engine,BASE,BASE)
        with self.assertRaises(ValueError):protect_publication(self.engine,BASE,BASE,{str(extra):b''})
    def test_installation_without_prior_publication_is_unchanged(self):
        protect_publication(self.engine,BASE,BASE+b'# change\n')

    def test_direct_listen_publication_is_protected(self):
        previous=self.published().split(b'frontend studio')[0]+b'listen panel\n bind 127.0.0.1:19000\n mode http\n server local 127.0.0.1:9130\n'
        with self.assertRaises(ValueError):protect_publication(self.engine,previous,BASE)
