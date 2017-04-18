import os
import pytest

from vault_mods.transit import Transit, TransitKey
from vault_mods.system import System
from . import settings

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.path.join(BASE_DIR, os.path.pardir, 'test_data'))
DECRYPTED_DATA_DIR = os.path.join(DATA_DIR, 'decrypted')
REWRAP_DATA_DIR = os.path.join(DATA_DIR, 'rewrap')


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
def signing_key(transit_instance: Transit):
    k = transit_instance.get_key('test_sign_key')
    k.create_key(key_type=k.EncryptionKeyType.ECDSA_P256, exportable=True)
    return k


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
                'encrypted_file_name': True
            },
        ]
        _encrypted = encryption_key.encrypt_files(files, makedirs=True, output_dir=DATA_DIR)
        decrypt_files = [
            {
                'file': _encrypted[0],
                'data_context': 'ct1',
                'data_nonce': 'n1',
                'name_context': 'ct2',
                'name_nonce': 'n2',
            },
            {
                'file': _encrypted[1],
                'data_context': 'ct1',
                'data_nonce': 'n1',
                'name_context': 'ct2',
                'name_nonce': 'n2',
                'encrypted_file_name': True
            },
        ]

        _decrypted = encryption_key.decrypt_files(
            decrypt_files,
            output_dir=DECRYPTED_DATA_DIR,
            makedirs=True
        )
        [os.remove(file) for file in set(_decrypted)]
        [os.remove(file) for file in set(_encrypted)]

        _encrypted = encryption_key.encrypt_files(
            [{'file': __file__}, {'file': __file__}, {'file': __file__}],
            DECRYPTED_DATA_DIR
        )
        [os.remove(file) for file in set(_encrypted)]

    def test_rewrap_data_batch(self, encryption_key: TransitKey):
        data = ['test', 'lol', 'qwe']
        encrypted_batch = encryption_key.encrypt_batch(data)
        encryption_key.rotate_key()
        rewrapped = encryption_key.rewrap_data_batch(encrypted_batch)
        decrypted = encryption_key.decrypt_batch(rewrapped, encoding='utf8')

        assert decrypted == data

    def test_rewrap_data(self, encryption_key: TransitKey):
        data = 'text'
        encrypted_data = encryption_key.encrypt_data(data, context='ct1', nonce='n1')
        encryption_key.rotate_key()
        rewrapped_data = encryption_key.rewrap_data(encrypted_data, context='ct1', nonce='n1')
        decrypted_data = encryption_key.decrypt_data(rewrapped_data, encoding='utf8')
        assert data == decrypted_data

    def test_sign(self, signing_key: TransitKey):
        data = 'qwerty123'
        signing_key.sign(data)

    def test_export_key(self, signing_key: TransitKey, encryption_key: TransitKey):
        signing_key.export_key(TransitKey.ExportKeyType.HMAC_KEY)
        signing_key.export_key(TransitKey.ExportKeyType.SIGNING_KEY)

        encryption_key.export_key(TransitKey.ExportKeyType.HMAC_KEY)
        encryption_key.export_key(TransitKey.ExportKeyType.ENCRYPTION_KEY)

        with pytest.raises(Exception):
            signing_key.export_key(TransitKey.ExportKeyType.ENCRYPTION_KEY)

        with pytest.raises(Exception):
            encryption_key.export_key(TransitKey.ExportKeyType.SIGNING_KEY)

    def test_rewrap_encrypted_files(self, encryption_key: TransitKey):
        _encrypted = encryption_key.encrypt_files(
            [{'file': __file__}],
            DATA_DIR, do_encrypt_file_names=True
        )
        encryption_key.rotate_key()
        _rewrapped = encryption_key.rewrap_encrypted_files(
            [{'file': f} for f in _encrypted],
            do_rewrap_file_names=True,
            output_dir=REWRAP_DATA_DIR,
            makedirs=True
        )

        _decrypted = encryption_key.decrypt_files(
            [{'file': f} for f in _rewrapped],
            makedirs=True,
            output_dir=DECRYPTED_DATA_DIR,
            do_decrypt_file_names=True
        )

        [os.remove(file) for file in set(_encrypted)]
        [os.remove(file) for file in set(_decrypted)]
        [os.remove(file) for file in set(_rewrapped)]

        _encrypted = encryption_key.encrypt_files(
            [{'file': __file__}],
            DATA_DIR, do_encrypt_file_names=False
        )
        encryption_key.rotate_key()
        _rewrapped = encryption_key.rewrap_encrypted_files(
            [{'file': f} for f in _encrypted],
            output_dir=REWRAP_DATA_DIR,
            makedirs=True
        )
        _decrypted = encryption_key.decrypt_files(
            [{'file': f} for f in _rewrapped],
            makedirs=True,
            output_dir=DECRYPTED_DATA_DIR,
        )

        [os.remove(file) for file in set(_encrypted)]
        [os.remove(file) for file in set(_decrypted)]
        [os.remove(file) for file in set(_rewrapped)]
