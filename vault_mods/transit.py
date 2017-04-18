import os
import typing as t

from collections import OrderedDict, namedtuple
from vault_mods.api_base import VaultAPIBase
from vault_mods.utils import (
    is_success, b64_encode, b64_decode, b64_dict_encode, b32_encode, b32_decode, restore_padding
)
from vault_mods import enums

str_or_bytes = t.Union[str, bytes]
str_dict = t.Dict[str, str_or_bytes]
str_dict__or__bytes_or_str = t.Union[str_dict, str_or_bytes]
str_dict_or_str = t.Union[str_dict, str]


class Transit(VaultAPIBase):
    def __init__(
            self,
            server_url: str = 'http://127.0.0.1/',
            api_version: str = 'v1',
            mount_point: str = 'transit',
            loop=None,
            cafile: str = '',
            token: str = '',
            tcp_connector=None,
            parent=None
    ):
        self.server_url = server_url
        self.full_url = os.path.join(self.server_url, api_version, mount_point)
        self.URLS = {
            'keys': {
                'list': os.path.join(self.full_url, 'keys'),
            },
        }
        super().__init__(token=token, cafile=cafile, loop=loop, tcp_connector=tcp_connector, parent=parent)

    def list_keys(self) -> t.Dict[str, 'TransitKey']:
        response = self.af.go_single(self.list_keys_task())
        if not is_success(response.status):
            # do not raise if no keys present
            if response.status == 404 and not response.result['errors']:
                return {}
            raise Exception(response)

        key_instance_map = OrderedDict()
        for key_name in response.result['data']['keys']:
            key_instance_map[key_name] = TransitKey(self, key_name)
        return key_instance_map

    def list_keys_task(self) -> dict:
        return self.mk_task_bundle(self.url('keys', 'list'), method='get', query_params={'list': True})

    def get_key(self, name: str) -> 'TransitKey':
        return TransitKey(self, name)


class TransitKey(VaultAPIBase):
    KeyInfo = namedtuple('KeyInfo', [
        'supports_encryption', 'latest_version', 'supports_decryption', 'supports_derivation', 'min_decryption_version',
        'type', 'exportable', 'keys', 'name', 'derived', 'deletion_allowed', 'supports_signing'
    ])

    EncryptionKeyType = enums.EncryptionKeyType
    ExportKeyType = enums.ExportKeyType
    DigestAlgorithm = enums.DigestAlgorithm
    DigestOutputFormat = enums.DigestOutputFormat

    info = None
    name = None

    def __init__(self, parent: Transit, name: str) -> None:
        self.transit_url = parent.full_url
        self.name = name

        self.URLS = {
            'key': {
                'read': os.path.join(self.transit_url, 'keys', name),
                'delete': os.path.join(self.transit_url, 'keys', name),
                'create': os.path.join(self.transit_url, 'keys', name),
                'config': os.path.join(self.transit_url, 'keys', name, 'config'),
                'export_all_versions': os.path.join(self.transit_url, 'export/%(key_type)s', name),
                'export_version': os.path.join(self.transit_url, 'export/%(key_type)s', name, '%(version)s'),
                'encrypt': os.path.join(self.transit_url, 'encrypt', name),
                'decrypt': os.path.join(self.transit_url, 'decrypt', name),
                'rotate': os.path.join(self.transit_url, 'keys', name, 'rotate'),
                'rewrap': os.path.join(self.transit_url, 'rewrap', name),
                'sign': os.path.join(self.transit_url, 'sign', name),
            },
        }
        super(TransitKey, self).__init__(
            token=parent.token, cafile=parent.cafile, loop=parent.loop,
            # use parent' connector
            tcp_connector=parent.get_tcp_connector(),
            parent=parent
        )

    # ---------------- read_key ----------------
    def read_key(self) -> KeyInfo:
        response = self.af.go_single(self.read_key_task())
        if not is_success(response.status):
            raise Exception(response)
        self.info = self.KeyInfo(**response.result['data'])
        return self.info

    def read_key_task(self) -> dict:
        return self.mk_task_bundle(self.url('key', 'read'))

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- create_key ----------------
    def create_key(self,
                   key_type: enums.EncryptionKeyType = None,
                   convergent_encryption: bool = False,
                   derived: bool = False,
                   exportable: bool = False):
        task_bundle = self.create_key_task(key_type, convergent_encryption, derived, exportable)
        response = self.af.go_single(task_bundle)
        if not is_success(response.status):
            raise Exception(response)
        return response.result

    def create_key_task(self,
                        key_type: enums.EncryptionKeyType = None,
                        convergent_encryption: bool = False,
                        derived: bool = False,
                        exportable: bool = False) -> dict:
        if key_type and key_type not in self.EncryptionKeyType:
            raise ValueError(key_type)
        data_bundle = {
            'convergent_encryption': convergent_encryption,
            'derived': derived,
            'exportable': exportable,
        }
        if key_type:
            data_bundle['type'] = key_type.value
        return self.mk_task_bundle(self.url('key', 'create'), method='post', data=data_bundle)

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- config_key ----------------
    def config_key(self, min_decryption_version: int = None, deletion_allowed: bool = None):
        response = self.af.go_single(self.config_key_task(min_decryption_version, deletion_allowed))
        if not is_success(response.status):
            raise Exception(response)
        return response.result

    def config_key_task(self, min_decryption_version: int = None, deletion_allowed: bool = None) -> dict:
        data_bundle = {}
        if min_decryption_version is not None:
            data_bundle['min_decryption_version'] = min_decryption_version
        if deletion_allowed is not None:
            data_bundle['deletion_allowed'] = deletion_allowed

        return self.mk_task_bundle(self.url('key', 'config'), method='post', data=data_bundle)

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- delete_key ----------------
    def delete_key(self) -> None:
        return self.af.go_single(self.delete_key_task()).result

    def delete_key_task(self) -> dict:
        return self.mk_task_bundle(self.url('key', 'delete'), method='delete')

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- rotate_key ----------------
    def rotate_key(self) -> None:
        response = self.af.go_single(self.rotate_key_task())
        if not is_success(response.status):
            raise Exception(response)
        return response.result

    def rotate_key_task(self) -> dict:
        return self.mk_task_bundle(self.url('key', 'rotate'), method='post')

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- export_key ----------------
    def export_key(self, key_type: enums.ExportKeyType, version: int = 0) -> dict:
        response = self.af.go_single(self.export_key_task(key_type, version))
        if not is_success(response.status):
            raise Exception(response)
        return response.result['data']

    def export_key_task(self, key_type: enums.ExportKeyType, version: int = 0):
        if key_type not in self.ExportKeyType:
            raise Exception
        if version:
            url = self.url('key', 'export_version', key_type=key_type.value, version=version)
        else:
            url = self.url('key', 'export_all_versions', key_type=key_type.value)
        return self.mk_task_bundle(url, method='get')

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- encrypt_b64 ----------------
    def encrypt_b64(self,
                    b64_plain_text: str = '',
                    b64_context: str = '',
                    b64_nonce: str = '',
                    batch_input: t.List[t.Dict[str, str]] = None) -> dict:
        response = self.af.go_single(self.encrypt_b64_task(
            b64_plain_text, b64_context, b64_nonce, batch_input
        ))
        if not is_success(response.status):
            raise Exception(response)
        return response.result

    def encrypt_b64_task(self,
                         b64_plain_text: str = '',
                         b64_context: str = '',
                         b64_nonce: str = '',
                         batch_input: t.List[t.Dict[str, str]] = None) -> dict:
        url = self.url('key', 'encrypt')
        data_bundle = {}
        if batch_input:
            data_bundle['batch_input'] = batch_input
            return self.mk_task_bundle(url, data=data_bundle, method='post')
        data_bundle['plaintext'] = b64_plain_text
        if b64_context:
            data_bundle['context'] = b64_context
        if b64_nonce:
            data_bundle['nonce'] = b64_nonce
        return self.mk_task_bundle(url, data=data_bundle, method='post')

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- encrypt_data ----------------
    def encrypt_data(self,
                     plain_text: str_or_bytes,
                     context: str = '',
                     nonce: str = ''):
        response = self.af.go_single(self.encrypt_data_task(plain_text, context, nonce))
        if not is_success(response.status):
            raise Exception(response)
        return response.result['data']['ciphertext']

    def encrypt_data_task(self, plain_text: str_or_bytes, context: str = '', nonce: str = '') -> dict:
        return self.encrypt_b64_task(**b64_dict_encode({
            'b64_plain_text': plain_text,
            'b64_context': context,
            'b64_nonce': nonce,
        }))

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- encrypt_batch ----------------
    def encrypt_batch(self, plain_data_bundle: t.List[str_dict__or__bytes_or_str]) -> t.List[str_dict]:
        response = self.af.go_single(self.encrypt_batch_task(plain_data_bundle))
        if not is_success(response.status):
            raise Exception(response)
        return response.result['data']['batch_results']

    def encrypt_batch_task(self, plain_data_bundle: t.List[str_dict__or__bytes_or_str]) -> dict:
        batch = []
        for raw_data in plain_data_bundle:
            b64_bundle = {}
            if isinstance(raw_data, (str, bytes)):
                b64_bundle['plaintext'] = b64_encode(raw_data)
            elif isinstance(raw_data, dict):
                b64_bundle.update(b64_dict_encode(raw_data))
            else:
                raise TypeError('Wrong data bundle: %s' % raw_data)
            batch.append(b64_bundle)
        return self.encrypt_b64_task(batch_input=batch)

    # ------------------------------------------------------------------------------------------------------------------

    # ---------------- decrypt_b64 ----------------
    def decrypt_b64(self,
                    ciphertext: str = '',
                    b64_context: str = '',
                    b64_nonce: str = '',
                    batch_input: t.List[t.Dict[str, str]] = None) -> dict:
        response = self.af.go_single(self.decrypt_b64_task(ciphertext, b64_context, b64_nonce, batch_input))
        if not is_success(response.status):
            raise Exception(response)
        return response.result

    def decrypt_b64_task(self,
                         ciphertext: str = '',
                         b64_context: str = '',
                         b64_nonce: str = '',
                         batch_input: t.List[t.Dict[str, str]] = None) -> dict:
        url = self.url('key', 'decrypt')
        data_bundle = {}
        if batch_input:
            data_bundle['batch_input'] = batch_input
            return self.mk_task_bundle(url, data=data_bundle, method='post')

        data_bundle['ciphertext'] = ciphertext
        if b64_context:
            data_bundle['context'] = b64_context
        if b64_nonce:
            data_bundle['nonce'] = b64_nonce
        return self.mk_task_bundle(url, data=data_bundle, method='post')

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- decrypt_data ----------------
    def decrypt_data(self,
                     ciphertext: str,
                     context: str = '',
                     nonce: str = '',
                     encoding: str = None):
        b64_plaintext = self.decrypt_b64(ciphertext=ciphertext, **b64_dict_encode({
            'b64_context': context,
            'b64_nonce': nonce,
        }))['data']['plaintext']
        return b64_decode(b64_plaintext, encoding=encoding)

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- decrypt_batch ----------------
    def decrypt_batch(self,
                      ciphertext_data_bundle: t.List[str_dict__or__bytes_or_str],
                      encoding: str = None) -> t.List[str]:
        response = self.af.go_single(self.decrypt_batch_task(ciphertext_data_bundle))
        if not is_success(response.status):
            raise Exception(response)

        results = []
        for br in response.result['data']['batch_results']:
            results.append(b64_decode(br['plaintext'], encoding=encoding))
        return results

    def decrypt_batch_task(self, ciphertext_data_bundle: t.List[str_dict__or__bytes_or_str]) -> dict:
        batch = []
        for cipher_bundle in ciphertext_data_bundle:
            b64_bundle = {}
            if isinstance(cipher_bundle, (str, bytes)):
                b64_bundle['ciphertext'] = cipher_bundle
            elif isinstance(cipher_bundle, dict):
                b64_bundle['ciphertext'] = cipher_bundle.pop('ciphertext', '')
                b64_bundle.update(b64_dict_encode(cipher_bundle))
            else:
                raise TypeError('Wrong data bundle: %s' % cipher_bundle)
            batch.append(b64_bundle)
        return self.decrypt_b64_task(batch_input=batch)

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- encrypt_files ----------------
    @staticmethod
    def handle_encrypt_files(file_bundles_list: t.List[str_dict_or_str],
                             encrypted_files_data: t.List[str_dict],
                             encrypted_file_names: t.List[str_dict],
                             output_dir: str = '',
                             makedirs: bool = False,
                             do_encrypt_file_names: bool = False,
                             output_filename_template: str = '%(version)s_%(filename)s.vault',
                             rewrap=False) -> t.List[str]:
        encrypted_files = []
        efn = iter(encrypted_file_names)  # encrypted file name iterator
        # {file_bundle}, {ciphertext: 123}
        for bundle, d_data in zip(file_bundles_list, encrypted_files_data):
            orig_file = os.path.abspath(bundle['file'])
            orig_dirname, orig_filename = os.path.dirname(orig_file), os.path.basename(orig_file)

            _, version, b64_data = d_data['ciphertext'].split(':')
            b_data = b64_decode(b64_data)

            if bundle.get('encrypted_file_name', do_encrypt_file_names):
                _, _, b64_name = next(efn)['ciphertext'].split(':')
                b_name = b64_decode(b64_name)
                filename = output_filename_template % {
                    'filename': b32_encode(b_name).rstrip('='),
                    'version': version
                }
            else:
                # remove extra version info if rewrap
                # otherwise we'll get v2_v1_test_transit.py.vault.vault
                if rewrap:
                    filename = output_filename_template % {
                        'filename': orig_filename.split('_', 1)[1].split('.vault')[0],
                        'version': version
                    }
                else:
                    filename = output_filename_template % {'filename': orig_filename, 'version': version}

            _output_dir = bundle.get('output_dir', output_dir)
            if makedirs:
                os.makedirs(_output_dir, exist_ok=True)

            _file = os.path.join(_output_dir, filename)
            with open(_file, 'wb') as f:
                f.write(b_data)
            encrypted_files.append(_file)
        return encrypted_files

    def encrypt_files(self,
                      file_bundles_list: t.List[str_dict_or_str],
                      output_dir: str = '',
                      makedirs: bool = False,
                      do_encrypt_file_names: bool = False,
                      output_filename_template: str = '%(version)s_%(filename)s.vault') -> t.List[str]:
        """
        :param do_encrypt_file_names: default for encrypt file names and encode encrypted data with base32
        :param file_bundles_list: 
        [
            {
                'file': __file__,
                'data_context': 'ct1',
                'data_nonce': 'n1',
                'name_context': 'ct2', # context should be set either in all the request blocks or in none
                'name_nonce': 'n2',
                'encrypted_file_name': True
            },
        ]
        :param output_dir: default output dir for encrypted files
        :param makedirs: create output directory
        :param output_filename_template: %(version)s_%(filename)s.vault
        :return: absolute file paths of files encrypted, ['/path/1.vault',]
        """
        response = self.af.go_single(
            self.encrypt_files_task(file_bundles_list, do_encrypt_file_names=do_encrypt_file_names),
        )
        if not is_success(response.status):
            raise Exception(response)

        encrypted_files_data = response.result['data']['batch_results'][:len(file_bundles_list)]
        encrypted_file_names = response.result['data']['batch_results'][len(file_bundles_list):]
        if makedirs:
            os.makedirs(output_dir, exist_ok=True)

        return self.handle_encrypt_files(
            file_bundles_list=file_bundles_list,
            encrypted_files_data=encrypted_files_data,
            encrypted_file_names=encrypted_file_names,
            output_dir=output_dir,
            makedirs=makedirs,
            do_encrypt_file_names=do_encrypt_file_names,
            output_filename_template=output_filename_template
        )

    def encrypt_files_task(self,
                           file_bundles_list: t.List[str_dict_or_str],
                           do_encrypt_file_names: bool = False) -> dict:
        """
        :param do_encrypt_file_names: default for encrypt file names and encode encrypted data with base32
        :param file_bundles_list: [
            {
                'file': '/var/file',
                'data_context': 'ct1', 
                'data_nonce: 'n1',
                'name_context': 'ct2', 
                'name_nonce': 'n2',
            },
            '/var/www/file.txt',
        ] 
        :return: [] batch list
        """
        batch_data, batch_file_names = [], []
        for bundle in file_bundles_list:
            abspath = os.path.abspath(bundle['file'])
            filename = os.path.basename(abspath)
            batch_data.append({
                'plaintext': open(bundle['file'], 'rb').read(),
                'context': bundle.get('data_context'),
                'nonce': bundle.get('data_nonce')
            })
            if bundle.get('encrypted_file_name', do_encrypt_file_names):
                batch_file_names.append({
                    'plaintext': filename,
                    'context': bundle.get('name_context'),
                    'nonce': bundle.get('name_nonce')
                })

        # file names placed after file data
        return self.encrypt_batch_task(batch_data + batch_file_names)

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- decrypt_files ----------------
    def decrypt_files(self,
                      file_bundles_list: t.List[str_dict_or_str],
                      do_decrypt_file_names: bool = False,
                      output_dir: str = '',
                      makedirs: bool = False) -> t.List[str]:
        response = self.af.go_single(self.decrypt_files_task(file_bundles_list, do_decrypt_file_names))
        if not is_success(response.status):
            raise Exception(response)
        decrypted_files_data = response.result['data']['batch_results'][:len(file_bundles_list)]
        decrypted_file_names = response.result['data']['batch_results'][len(file_bundles_list):]

        if makedirs:
            os.makedirs(output_dir, exist_ok=True)

        decrypted_files = []
        dfn = iter(decrypted_file_names)  # decrypted file name iterator
        for bundle, d_data in zip(file_bundles_list, decrypted_files_data):
            abspath = os.path.abspath(bundle['file'])
            version, filename = os.path.basename(abspath).split('_', 1)
            filename = filename.split('.vault')[0]
            dirname = os.path.dirname(abspath)
            b_data = b64_decode(d_data['plaintext'])

            if bundle.get('encrypted_file_name', do_decrypt_file_names):
                filename = b64_decode(next(dfn)['plaintext'], 'utf8')

            _output_dir = bundle.get('output_dir', output_dir) or dirname
            if makedirs:
                os.makedirs(_output_dir, exist_ok=True)

            _file = os.path.join(_output_dir, filename)
            with open(_file, 'wb') as f:
                f.write(b_data)
            decrypted_files.append(_file)
        return decrypted_files

    @staticmethod
    def prepare_decrypt_batch_data(file_bundles_list: t.List[str_dict],
                                   do_decrypt_file_names: bool = False) -> t.List[str_dict]:
        batch_data, batch_file_names = [], []
        for bundle in file_bundles_list:
            abspath = os.path.abspath(bundle['file'])
            version, filename = os.path.basename(abspath).split('_', 1)
            filename = filename.split('.vault')[0]
            data_ciphertext = 'vault:%s:%s' % (version, b64_encode(open(bundle['file'], 'rb').read()))
            batch_data.append({
                'ciphertext': data_ciphertext,
                'context': bundle.get('data_context'),
                'nonce': bundle.get('data_nonce')
            })
            if bundle.get('encrypted_file_name', do_decrypt_file_names):
                filename_ciphertext = ':'.join([
                    'vault',
                    version,
                    b64_encode(b32_decode(restore_padding(filename)))
                ])
                batch_file_names.append({
                    'ciphertext': filename_ciphertext,
                    'context': bundle.get('name_context'),
                    'nonce': bundle.get('name_nonce')
                })
        return batch_data + batch_file_names

    def decrypt_files_task(self,
                           file_bundles_list: t.List[str_dict],
                           do_decrypt_file_names: bool = False) -> dict:
        return self.decrypt_batch_task(
            self.prepare_decrypt_batch_data(file_bundles_list, do_decrypt_file_names)
        )

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- rewrap_b64 ----------------
    def rewrap_b64(self,
                   ciphertext: str = '',
                   b64_context: str = '',
                   b64_nonce: str = '',
                   batch_input: t.List[t.Dict[str, str]] = None):
        response = self.af.go_single(self.rewrap_b64_task(
            ciphertext, b64_context, b64_nonce, batch_input
        ))
        if not is_success(response.status):
            raise Exception(response)
        return response.result

    def rewrap_b64_task(self,
                        ciphertext: str = '',
                        b64_context: str = '',
                        b64_nonce: str = '',
                        batch_input: t.List[t.Dict[str, str]] = None) -> dict:
        url = self.url('key', 'rewrap')
        data_bundle = {}
        if batch_input:
            data_bundle['batch_input'] = batch_input
            return self.mk_task_bundle(url, data=data_bundle, method='post')
        data_bundle['ciphertext'] = ciphertext
        if b64_context:
            data_bundle['context'] = b64_context
        if b64_nonce:
            data_bundle['nonce'] = b64_nonce
        return self.mk_task_bundle(url, data=data_bundle, method='post')

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- rewrap_data_batch ----------------
    def rewrap_data_batch(self, batch: t.List[str_dict__or__bytes_or_str]) -> t.List[str_dict]:
        response = self.af.go_single(self.rewrap_b64_task(batch_input=batch))
        if not is_success(response.status):
            raise Exception(response)
        return response.result['data']['batch_results']

    def rewrap_data_batch_task(self, batch: t.List[str_dict__or__bytes_or_str]) -> dict:
        _batch = []
        for bundle in batch:
            _batch.append(dict(ciphertext=bundle['ciphertext'], **b64_dict_encode({
                'b64_context': bundle.get('context'),
                'b64_nonce': bundle.get('nonce'),
            })))

        return self.rewrap_b64_task(batch_input=_batch)

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- rewrap_data ----------------
    def rewrap_data(self,
                    ciphertext: str = '',
                    context: str = '',
                    nonce: str = '') -> str:
        response = self.af.go_single(self.rewrap_data_task(
            ciphertext=ciphertext,
            context=context,
            nonce=nonce
        ))
        if not is_success(response.status):
            raise Exception(response)
        return response.result['data']['batch_results'][0]['ciphertext']

    def rewrap_data_task(self,
                         ciphertext: str = '',
                         context: str = '',
                         nonce: str = '') -> dict:
        return self.rewrap_data_batch_task([{
            'ciphertext': ciphertext,
            'context': context,
            'nonce': nonce
        }])

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- sign ----------------
    def sign(self,
             input_data: str_or_bytes,
             output_format: enums.DigestOutputFormat = enums.DigestOutputFormat.HEX,
             algorithm: enums.DigestAlgorithm = enums.DigestAlgorithm.SHA2_256):
        response = self.af.go_single(self.sign_task(input_data, output_format, algorithm))
        if not is_success(response.status):
            raise Exception(response)
        return response.result['data']['signature']

    def sign_task(self,
                  input_data: str_or_bytes,
                  output_format: enums.DigestOutputFormat = enums.DigestOutputFormat.HEX,
                  algorithm: enums.DigestAlgorithm = enums.DigestAlgorithm.SHA2_256):
        if algorithm not in self.DigestAlgorithm:
            raise ValueError(algorithm)
        if output_format not in self.DigestOutputFormat:
            raise ValueError(output_format)

        return self.mk_task_bundle(self.url('key', 'sign'), {
            'algorithm': algorithm.value,
            'format': output_format.value,
            'input': b64_encode(input_data)
        }, method='post')

    # ------------------------------------------------------------------------------------------------------------------
    # ---------------- rewrap_encrypted_files ----------------
    def rewrap_encrypted_files(self,
                               file_bundles_list: t.List[str_dict],
                               output_dir: str = '',
                               makedirs: bool = False,
                               do_rewrap_file_names: bool = False,
                               output_filename_template: str = '%(version)s_%(filename)s.vault'):
        response = self.af.go_single(
            self.rewrap_encrypted_files_task(file_bundles_list, do_rewrap_file_names)
        )
        if not is_success(response.status):
            raise Exception(response)
        batch_results = response.result['data']['batch_results']
        encrypted_files_data = batch_results[:len(file_bundles_list)]
        encrypted_file_names = batch_results[len(file_bundles_list):]
        if makedirs:
            os.makedirs(output_dir, exist_ok=True)

        # same as encrypt
        return self.handle_encrypt_files(
            file_bundles_list=file_bundles_list,
            encrypted_files_data=encrypted_files_data,
            encrypted_file_names=encrypted_file_names,
            output_dir=output_dir,
            makedirs=makedirs,
            do_encrypt_file_names=do_rewrap_file_names,
            output_filename_template=output_filename_template,
            rewrap=True
        )

    def rewrap_encrypted_files_task(self,
                                    file_bundles_list: t.List[str_dict],
                                    do_rewrap_file_names: bool = False):
        decrypt_batch_list = self.prepare_decrypt_batch_data(file_bundles_list, do_rewrap_file_names)
        return self.rewrap_data_batch_task(decrypt_batch_list)
