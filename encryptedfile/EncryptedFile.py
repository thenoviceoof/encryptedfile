# * "THE BEER-WARE LICENSE" (Revision 42):
# * <thenoviceoof@gmail> wrote this file. As long as you retain this notice you
# * can do whatever you want with this stuff. If we meet some day, and you think
# * this stuff is worth it, you can buy me a beer in return
################################################################################

__version__ = (1, 1, 1)

import hashlib
from Crypto.Cipher import Blowfish, AES
from os import urandom
import math
import re

class EncryptedFile(object):
    '''
    A transparent, write-only file-like object

    Creates OpenPGP compatible encrypted files
    '''
    # OpenPGP values
    ALGO_BLOWFISH = 4
    ALGO_AES128 = 7
    ALGO_AES196 = 8
    ALGO_AES256 = 9

    S2K_SIMPLE = 0
    S2K_SALTED = 1
    S2K_ITERATED = 3

    HASH_MD5 = 1
    HASH_SHA1 = 2
    HASH_SHA256 = 8
    HASH_SHA384 = 9
    HASH_SHA512 = 10

    # things mapping OpenPGP values to Python values
    ENCRYPTION_ALGOS = {
        ALGO_BLOWFISH : Blowfish,
        ALGO_AES128: AES,
        ALGO_AES196: AES,
        ALGO_AES256: AES,
        }
    KEY_SIZES = {
        ALGO_BLOWFISH : 16,
        ALGO_AES128: 16,
        ALGO_AES196: 24,
        ALGO_AES256: 32,
        }
    HASHES = {
        HASH_MD5: hashlib.md5,
        HASH_SHA1: hashlib.sha1,
        HASH_SHA256: hashlib.sha256,
        HASH_SHA384: hashlib.sha384,
        HASH_SHA512: hashlib.sha512,
        }

    def __init__(self, file_obj, passphrase, mode='w', iv=None, salt=None,
                 block_size=16, buffer_size=1024, timestamp=None,
                 encryption_algo=ALGO_AES256, hash_algo=HASH_SHA256,
                 key_method=S2K_ITERATED, iterated_count=(16, 6)):
        '''
        Open a pipe to an encrypted file

        file_obj: a string or file-like object
            a string should be a path
            file object: write through to the file

        passphrase: passphrase
        mode: usual file modes

        iv: initialization vector, randomly generated if not
            given. same size as block_size
        key_method: which S2K_* method to use
        hash_algo: which HASH_* to convert the passphrase with
        encryption_algo: which ALGO_* to encrypt the plaintext with

        block_size: used by the cipher
        buffer_size: how much data should be slurped up before encrypting
        timestamp <int>: timestamp, if any, to be attached to the literal data
            if not given, just writes zeroes
        iterated_count: a tuple (base, exp), where base is between [16, 32),
            and the exp is between 6 and 22
        '''
        if not int(buffer_size/block_size)*block_size == buffer_size:
            raise ValueError('buffer_size is not a multiple of the block_size')
        self.block_size = block_size
        # check buffer_size: can set later
        if not buffer_size > 512:
            raise ValueError('First block_size must be larger than 512b')
        self.buffer_size = buffer_size

        self.mode = mode
        self.bin_mode = False
        if len(self.mode)>1:
            self.bin_mode = (self.mode[1] == 'b')
        self._raw_buffer = ''
        self._lit_buffer = ''
        self._enc_buffer = ''
        self.closed = False

        if isinstance(file_obj, basestring):
            if len(file_obj) > 0xff:
                raise ValueError('File name is too long')
            self.file = open(file_obj, mode)
            self.name = file_obj
        elif isinstance(file_obj, file):
            self.file = file_obj
            self.name = file_obj.name[:0xff]
        else:
            raise TypeError

        # we are write-only at the moment
        if mode[0] == 'w':
            if not iv:
                self.iv = urandom(self.block_size)
            elif len(iv) != self.block_size:
                raise ValueError('IV has to be one block size')
            else:
                self.iv = iv
            # write the symmetric encryption session packet
            header = ''
            header += chr((1 << 7) | (1 << 6) | 3)
            header += chr(0) # header length
            header += chr(4) # version
            header += chr(encryption_algo) # sym algo

            header += chr(key_method) # S2K
            header += chr(hash_algo) # S2K hash algo
            # generate 8b salt
            if key_method in [self.S2K_SALTED, self.S2K_ITERATED]:
                if not salt:
                    salt = urandom(8)
                header += salt
            if key_method == self.S2K_ITERATED:
                if iterated_count[0] < 16 or iterated_count[0] >= 32:
                    raise ValueError('iterated_count base illegal')
                if iterated_count[1] < 6 or iterated_count[1] >= 22:
                    raise ValueError('iterated_count exp illegal')
                count = iterated_count[0] << iterated_count[1]
                packed_base = iterated_count[0] - 16
                packed_exp  = iterated_count[1] - 6 << 4
                packed_count = chr(packed_exp & packed_base)
                header += packed_count

            header = header[0] + chr(len(header)-2) + header[2:]
            self.file.write(header)

            # write the encrypted data packet header
            self.file.write(chr((1 << 7) | (1 << 6) | 9))
        else:
            raise ValueError('Only \'wb\' mode supported')

        def gen_key(key_method, hash_algo, pass_phrase, salt, it=0):
            '''
            utility function to generate S2K keys
            '''
            hsh = self.HASHES[hash_algo]()
            hsh.update(chr(0) * it)
            if key_method == self.S2K_SIMPLE:
                hsh.update(pass_phrase)
            elif key_method == self.S2K_SALTED:
                hsh.update(salt)
                hsh.update(pass_phrase)
            elif key_method == self.S2K_ITERATED:
                # hash <count> number of bytes
                i = 0
                key = salt + pass_phrase
                while i + len(key) < count:
                    hsh.update(key)
                    i += len(key)
                hsh.update(key[:count - i])
            return hsh.digest()

        self.key = ''
        i = 0
        while len(self.key) < self.KEY_SIZES[encryption_algo]:
            self.key += gen_key(key_method, hash_algo, passphrase, salt, i)
            i += 1
        self.key = self.key[:self.KEY_SIZES[encryption_algo]]

        cipher = self.ENCRYPTION_ALGOS[encryption_algo]
        self.cipher = cipher.new(self.key, cipher.MODE_OPENPGP,
                                 self.iv, block_size = block_size)

        # add the literal block id byte to the unencrypted buffer
        self._lit_buffer += chr((1 << 7) | (1 << 6) | 11)
        # set mode
        self._raw_buffer += 'b' if self.bin_mode else 't'
        # write out file name
        self._raw_buffer += chr(len(self.name))
        self._raw_buffer += self.name
        # write out 4-octet date
        if timestamp:
            self._raw_buffer += chr(timestamp >> 24 & 0xff)
            self._raw_buffer += chr(timestamp >> 16 & 0xff)
            self._raw_buffer += chr(timestamp >> 8  & 0xff)
            self._raw_buffer += chr(timestamp & 0xff)
        else:
            self._raw_buffer += '\0' * 4
        self.count = 0

    # handle {with EncryptedFile(...) as f:} notation
    def __enter__(self):
        return self
    def __exit__(self, type, value, traceback):
        self.close()

    def _semi_length(self):
        '''
        Produce the byte encoding an intermediate block of data
        '''
        # make sure the buffer size fits the semi-packet length constraints
        # keep this here, self.buffer_size is user-available
        power = int(math.log(1024, 2))
        assert self.buffer_size == 2**power
        return chr(224 + power)
    def _final_length(self, length):
        '''
        Produce the bytes encoding the length of the final data segment
        '''
        if length <= 191:
            return chr(length)
        elif length <= 8383:
            return (chr(((length - 192) >> 8) + 192) +
                    chr((length - 192) & 0xFF))
        else:
            return (chr(0xff) +
                    chr((length >> 24) & 0xff) +
                    chr((length >> 16) & 0xff) +
                    chr((length >> 8)  & 0xff) +
                    chr(length & 0xff))

    def _write_enc_buffer(self, final=False):
        '''
        Given things in the encrypted buffer, write them
        '''
        while len(self._enc_buffer) >= self.buffer_size:
            self.file.write(self._semi_length())
            # write the encrypted data in blocks
            self.file.write(self._enc_buffer[:self.buffer_size])
            self._enc_buffer = self._enc_buffer[self.buffer_size:]

        if final:
            self.file.write(self._final_length(len(self._enc_buffer)))
            self.file.write(self._enc_buffer)
    def _encrypt_buffer(self, final=False):
        '''
        Given literal packet data, encrypt it
        '''
        cnt = int(math.floor(len(self._lit_buffer)/self.block_size))
        bs = cnt * self.block_size
        # encrypt all data that fits cleanly in the block size
        self._enc_buffer += self.cipher.encrypt(self._lit_buffer[:bs])
        self._lit_buffer = self._lit_buffer[bs:]

        if final:
            self._enc_buffer += self.cipher.encrypt(self._lit_buffer)

        self._write_enc_buffer(final=final)
    def _write_buffer(self, final=False):
        '''
        Given things in the raw buffer, attach metadata and put them
        in the literal buffer
        '''
        # add the literal data packet metadata
        while len(self._raw_buffer) >= self.buffer_size:
            self._lit_buffer += self._semi_length()
            # write/encrypt the literal data in blocks
            self._lit_buffer += self._raw_buffer[:self.buffer_size]
            self._raw_buffer = self._raw_buffer[self.buffer_size :]
            
        if final:
            final_len = self._final_length(len(self._raw_buffer))
            self._lit_buffer += final_len
            self._lit_buffer += self._raw_buffer

        self._encrypt_buffer(final=final)

    def write(self, data):
        # make sure the data is there
        self.count += len(data)
        self._raw_buffer += data
        if not self.bin_mode:
            self._raw_buffer = re.sub('([^\r])\n', '\\1\r\n', self._raw_buffer)
            self._raw_buffer = re.sub('\r([^\n])', '\r\n\\1', self._raw_buffer)
            if self._raw_buffer[-1] == '\r':
                # don't write yet: we might have more coming (\r\n pairs)
                return
        self._write_buffer()
    def writelines(self, lines):
        if self.bin_mode:
            raise ValueError('Textual method used with binary data')
        for line in lines:
            line = re.sub('([^\r])\n', '\\1\r\n', line)
            line = re.sub('\r([^\n])', '\r\n\\1', line)
            self._raw_buffer += line
            self._raw_buffer += '\r\n' # use CR/LF, network newlines
        self._write_buffer()

    # reading is hard
    def read(self, *args, **kwargs):
        raise NotImplementedError()
    def readlines(self, *args, **kwargs):
        raise NotImplementedError()

    # so is seeking
    def seek(self, offset, whence=None):
        raise NotImplementedError()

    def tell(self):
        return self.count

    def close(self):
        if self.file.closed:
            return
        # make sure we catch a final \r, which was waiting for the next write
        if not self.bin_mode and self._raw_buffer[-1] == '\r':
            self._raw_buffer += '\n'
        self._write_buffer(final=True)
        self.file.close()

    def flush(self):
        '''
        Merely flushes the encapsulated file object. If there's
        stuff in the buffer, there's a good reason for it.
        '''
        self.file.flush()
    def isatty(self):
        return False

if __name__=='__main__':
    '''
    Documentation and self-testing

    To decrypt with gpg:
    gpg <file name>
    '''
    msg = '''Hello world'''
    print("Encrypted message:")
    print(msg)
    b = EncryptedFile('example.gpg', passphrase='w')
    b.write(msg)
    b.close()
