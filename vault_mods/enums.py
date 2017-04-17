from enum import Enum


class DigestAlgorithm(Enum):
    SHA2_224 = 'sha2-224'
    SHA2_256 = 'sha2-256'
    SHA2_384 = 'sha2-384'
    SHA2_512 = 'sha2-512'


class DigestOutputFormat(Enum):
    HEX = 'hex'
    BASE64 = 'base64'


class SecretBackend(Enum):
    AWS = 'aws'
    Cassandra = 'cassandra'
    Consul = 'consul'
    Cubbyhole = 'cubbyhole'
    Generic = 'generic'
    MongoDB = 'mongodb'
    MSSQL = 'mssql'
    MySQL = 'mysql'
    PKI = 'pki'
    PostgreSQL = 'postgresql'
    RabbitMQ = 'rabbitmq'
    SSH = 'ssh'
    Transit = 'transit'


class EncryptionKeyType(Enum):
    AES256_GCM96 = 'aes256-gcm96'
    ECDSA_P256 = 'ecdsa-p256'


class ExportKeyType(Enum):
    ENCRYPTION_KEY = 'encryption-key'
    SIGNING_KEY = 'signing-key'
    HMAC_KEY = 'hmac-key'


AllowedSecretBackendConfigKeys = Enum(
    'AllowedSecretBackendConfigKeys', 'default_lease_ttl max_lease_ttl force_no_cache'
)
