import os
import pytest

from glob import glob

from vault_mods.transit import Transit, TransitKey
from vault_mods.system import System
from . import settings

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.path.join(BASE_DIR, os.path.pardir, 'test_data'))
DECRYPTED_DATA_DIR = os.path.join(DATA_DIR, 'decrypted')


@pytest.fixture(scope='module')
def transit_instance():
    vault = System(
        server_url=settings.TRANSIT['SERVER_URL'],
        token=settings.TRANSIT['TOKEN'],
        cafile=settings.TRANSIT['CAFILE']
    )
    vault.unmount('example.com/test-transit')
    return vault.mount(
        System.SecretBackend.Transit, mount_point='example.com/test-transit', description='test',
    )


# noinspection PyShadowingNames
@pytest.fixture(scope='module')
def encryption_key(transit_instance: Transit):
    k = transit_instance.get_key('new_key')
    k.create_key(exportable=True)
    return k


# noinspection PyShadowingNames
@pytest.fixture(scope='module')
def sign_key(transit_instance: Transit):
    sign_key = transit_instance.get_key('sign_key')
    sign_key.create_key(key_type=sign_key.EncryptionKeyType.ECDSA_P256, exportable=True)
    return sign_key


# noinspection PyShadowingNames,PyMethodMayBeStatic
class TransitAPITest:
    def test_create_key(self, transit_instance: Transit):
        k = transit_instance.get_key('new_key')
        k.create_key(exportable=True)

    def test_list_keys(self, transit_instance: Transit):
        assert 'new_key' in transit_instance.list_keys()

    def test_delete_key(self, transit_instance: Transit):
        transit_instance.get_key('new_key').delete_key()

    def test_encrypt_data(self, encryption_key: TransitKey):
        encryption_key.encrypt_data('some text')
        encryption_key.encrypt_data(b'some text')
        encryption_key.encrypt_data(b'some text', context='qwerty', nonce='qwerty')

    def test_encrypt_batch(self, encryption_key: TransitKey):
        encryption_key.encrypt_batch(
            [
                '123', 'qweqwe', {'plaintext': 'NONOENONE', 'nonce': '1'},
                b'vasya where are you',
                {
                    'plaintext': b'op opa',
                    'nonce': 'qwe'
                },
            ]
        )

    def test_config_key(self, encryption_key: TransitKey):
        encryption_key.config_key(deletion_allowed=True)

    def test_read_key(self, encryption_key: TransitKey):
        assert isinstance(encryption_key.read_key(), TransitKey.KeyInfo)

    def test_go(self, encryption_key: TransitKey):
        encryption_key.append_task('data1', encryption_key.encrypt_data_task('data1'))
        encryption_key.append_task('data2', encryption_key.encrypt_data_task('data2'))
        res = encryption_key.go()
        assert len(res.keys()) == 2

    def test_go_tasks(self, encryption_key: TransitKey):
        res = encryption_key.go_tasks(
            encryption_key.encrypt_data_task('data1'),
            encryption_key.encrypt_data_task('data2'),
        )
        assert len(res.keys()) == 2

    def test_rotate_key(self, encryption_key: TransitKey):
        encryption_key.rotate_key()

    def test_decrypt_data(self, encryption_key: TransitKey):
        raw, context, nonce = 'sample text', 'context', 'nonce'
        raw_encrypted = encryption_key.encrypt_data(raw, context=context, nonce=nonce)
        assert encryption_key.decrypt_data(raw_encrypted, encoding='utf8') == raw

    def test_decrypt_batch(self, encryption_key: TransitKey):
        ciphers = encryption_key.encrypt_batch(
            [
                '123', 'qweqwe', {'plaintext': 'NONOENONE', 'nonce': '1'},
                b'vasya where are you',
                {
                    'plaintext': b'op opa',
                    'nonce': 'qwe'
                },
            ]
        )
        # ciphers[2]['nonce'] = '123'
        res = encryption_key.decrypt_batch(ciphertext_data_bundle=ciphers)

    def test_encrypt_files(self, encryption_key: TransitKey):
        dirname = os.path.dirname(os.path.abspath(__file__))
        files = [
            {
                'file': __file__,
                'data_context': 'ct1',
                'data_nonce': 'n1',
                'name_context': 'ct2',
                'name_nonce': 'n2',
            },
            {
                'file': __file__,
                'data_context': 'ct1',
                'data_nonce': 'n1',
                'name_context': 'ct2',
                'name_nonce': 'n2',
                'encrypt_file_name': True
            },
        ]
        res = encryption_key.encrypt_files(files, makedirs=True, output_dir=DATA_DIR)
        decrypt_files = [
            {
                'file': res[0],
                'data_context': 'ct1',
                'data_nonce': 'n1',
                'name_context': 'ct2',
                'name_nonce': 'n2',
            },
            {
                'file': res[1],
                'data_context': 'ct1',
                'data_nonce': 'n1',
                'name_context': 'ct2',
                'name_nonce': 'n2',
                'decrypt_file_name': True
            },
        ]

        encryption_key.decrypt_files(
            decrypt_files,
            output_dir=DECRYPTED_DATA_DIR,
            makedirs=True
        )
        encrypted = encryption_key.encrypt_files([{'file': __file__}])
