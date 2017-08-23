import unittest
from pypraware_crypto.choose_crypto import Crypto
from pypraware_normalize.normalize import normalize, ipNorm, urlNorm
from collections import OrderedDict
from multiprocessing import SimpleQueue
from base64 import b64decode

class CryptoTestBcrypt(unittest.TestCase):

    # Attention tester avec ou sans méta !!! 
    def setUp(self):
        # conf creation
        self.conf = {}
        self.conf['misp'] = {}
        self.conf['misp']['token'] = "test"
        self.conf['bcrypt'] = {}
        self.conf['bcrypt']['round'] = 1
        self.conf['bcrypt']['ipround'] = 1
        self.conf['rules'] = {}
        self.conf['rules']['location'] = "rules/"

        self.metadata = {'crypto': {'round': 2, 'ipround': 2}}

    def test_meta_none(self):
        # Test feature one.
        cry = Crypto('bcrypt', self.conf, None)
        ioc = OrderedDict()
        ioc['ip-dst'] = "192.168.0.0"
        ioc['url'] = "test.com"
        rule = cry.create_rule(ioc, "Hello, this is the message!")
        rule['salt'] = b64decode(rule['salt'])
        rule['nonce'] = b64decode(rule['nonce'])
        rule['attributes'] = rule['attributes'].split('||')
        rule['ciphertext-check'] = b64decode(rule['ciphertext-check'])
        rule['ciphertext'] = b64decode(rule['ciphertext'])
        queue = SimpleQueue()
        cry.match(ioc, rule, queue)
        self.assertTrue(not queue.empty())

    def test_meta(self):
        # Test feature two.
        cry = Crypto('bcrypt', self.conf, self.metadata)
        ioc = OrderedDict()
        ioc['ip-dst'] = "192.168.0.0"
        ioc['url'] = "test.com"
        rule = cry.create_rule(ioc, "Hello, this is the message!")
        rule['salt'] = b64decode(rule['salt'])
        rule['nonce'] = b64decode(rule['nonce'])
        rule['attributes'] = rule['attributes'].split('||')
        rule['ciphertext-check'] = b64decode(rule['ciphertext-check'])
        rule['ciphertext'] = b64decode(rule['ciphertext'])
        queue = SimpleQueue()
        cry.match(ioc, rule, queue)
        self.assertTrue(not queue.empty())

class CryptoTestPbkdf2(unittest.TestCase):

    # Attention tester avec ou sans méta !!! 
    def setUp(self):
        # conf creation
        self.conf = {}
        self.conf['misp'] = {'token':'test'}
        self.conf['pbkdf2'] = {'iterations':1, 'ipiterations':1, 'hash_name': 'sha256', 'dklen':32}
        self.conf['rules'] = {'location': "rules/"}

        self.metadata = {'crypto': {'hash_name':'sha256', 'dklen':32, 'iterations': 2, 'ipiterations': 2}}

    def test_meta_none(self):
        # Test feature one.
        cry = Crypto('pbkdf2', self.conf, None)
        ioc = OrderedDict()
        ioc['ip-dst'] = "192.168.0.0"
        ioc['url'] = "test.com"
        rule = cry.create_rule(ioc, "Hello, this is the message!")
        rule['salt'] = b64decode(rule['salt'])
        rule['nonce'] = b64decode(rule['nonce'])
        rule['attributes'] = rule['attributes'].split('||')
        rule['ciphertext-check'] = b64decode(rule['ciphertext-check'])
        rule['ciphertext'] = b64decode(rule['ciphertext'])
        queue = SimpleQueue()
        cry.match(ioc, rule, queue)
        self.assertTrue(not queue.empty())

    def test_meta(self):
        # Test feature two.
        cry = Crypto('pbkdf2', self.conf, self.metadata)
        ioc = OrderedDict()
        ioc['ip-dst'] = "192.168.0.0"
        ioc['url'] = "test.com"
        rule = cry.create_rule(ioc, "Hello, this is the message!")
        rule['salt'] = b64decode(rule['salt'])
        rule['nonce'] = b64decode(rule['nonce'])
        rule['attributes'] = rule['attributes'].split('||')
        rule['ciphertext-check'] = b64decode(rule['ciphertext-check'])
        rule['ciphertext'] = b64decode(rule['ciphertext'])
        queue = SimpleQueue()
        cry.match(ioc, rule, queue)
        self.assertTrue(not queue.empty())

class CryptoTestHKDF(unittest.TestCase):

    # Attention tester avec ou sans méta !!! 
    def setUp(self):
        # conf creation
        self.conf = {}
        self.conf['misp'] = {'token':'test'}
        self.conf['rules'] = {'location': "rules/"}

        self.metadata = {'crypto': {}}

    def test_meta_none(self):
        # Test feature one.
        cry = Crypto('hkdf', self.conf, None)
        ioc = OrderedDict()
        ioc['ip-dst'] = "192.168.0.0"
        ioc['url'] = "test.com"
        rule = cry.create_rule(ioc, "Hello, this is the message!")
        rule['salt'] = b64decode(rule['salt'])
        rule['nonce'] = b64decode(rule['nonce'])
        rule['attributes'] = rule['attributes'].split('||')
        rule['ciphertext-check'] = b64decode(rule['ciphertext-check'])
        rule['ciphertext'] = b64decode(rule['ciphertext'])
        queue = SimpleQueue()
        cry.match(ioc, rule, queue)
        self.assertTrue(not queue.empty())

    def test_meta(self):
        # Test feature two.
        cry = Crypto('hkdf', self.conf, self.metadata)
        ioc = OrderedDict()
        ioc['ip-dst'] = "192.168.0.0"
        ioc['url'] = "test.com"
        rule = cry.create_rule(ioc, "Hello, this is the message!")
        rule['salt'] = b64decode(rule['salt'])
        rule['nonce'] = b64decode(rule['nonce'])
        rule['attributes'] = rule['attributes'].split('||')
        rule['ciphertext-check'] = b64decode(rule['ciphertext-check'])
        rule['ciphertext'] = b64decode(rule['ciphertext'])
        queue = SimpleQueue()
        cry.match(ioc, rule, queue)
        self.assertTrue(not queue.empty())

def test_main():
    unittest.main()

if __name__ == '__main__':
    test_main()