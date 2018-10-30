"""cookiemonstruo_apple.py :: Retrieve and decrypt cookies from Chrome.

Adapted from https://github.com/n8henrie/pycookiecheat
"""

import pathlib
import sqlite3
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES
import argparse


def clean(decrypted: bytes) -> str:
    r"""Strip padding from decrypted value.

    Remove number indicated by padding
    e.g. if last is '\x0e' then ord('\x0e') == 14, so take off 14.

    Args:
        decrypted: decrypted value
    Returns:
        Decrypted stripped of junk padding

    """
    last = decrypted[-1]
    if isinstance(last, int):
        return decrypted[:-last].decode('utf8')
    return decrypted[:-ord(last)].decode('utf8')


def chrome_decrypt(encrypted_value: bytes, key: bytes, init_vector: bytes) \
        -> str:
    """Decrypt Chrome encrypted cookies.

    Args:
        encrypted_value: Encrypted cookie from Chrome/Chromium's cookie file
        key: Key to decrypt encrypted_value
        init_vector: Initialization vector for decrypting encrypted_value
    Returns:
        Decrypted value of encrypted_value

    """
    # Encrypted cookies should be prefixed with 'v10' or 'v11' according to the
    # Chromium code. Strip it off.
    encrypted_value = encrypted_value[3:]

    cipher = AES.new(key, AES.MODE_CBC, IV=init_vector)
    decrypted = cipher.decrypt(encrypted_value)

    return clean(decrypted)


def chrome_cookies(
        my_pass: str = None,
        cookie_file: str = None,
        output: str = "cookies.txt",
        ) -> dict:
    """Retrieve cookies from Chrome/Chromium on OSX or Linux.

    Args:
        cookie_file: Path to alternate file to search for cookies
        browser: Name of the browser's cookies to read ('Chrome' or 'Chromium')
        curl_cookie_file: Path to save the cookie file to be used with cURL
    Returns:
        Dictionary of cookie values for URL
        :param my_pass:
        :param cookie_file:
        :param output:

    """

    config = {
        'my_pass': my_pass,
        'iterations': 1003,
        'cookie_file': cookie_file,
        }

    config.update({
        'init_vector': b' ' * 16,
        'length': 16,
        'salt': b'saltysalt',
    })

    if cookie_file:
        cookie_file = str(pathlib.Path(cookie_file).expanduser())
    else:
        cookie_file = str(pathlib.Path(config['cookie_file']).expanduser())

    enc_key = pbkdf2_hmac(hash_name='sha1',
                          password=config['my_pass'].encode('utf8'),
                          salt=config['salt'],
                          iterations=config['iterations'],
                          dklen=config['length'])

    try:
        conn = sqlite3.connect(cookie_file)
    except sqlite3.OperationalError:
        print("Unable to connect to cookie_file at: {}\n".format(cookie_file))
        raise

    # Check whether the column name is `secure` or `is_secure`
    secure_column_name = 'is_secure'
    for sl_no, column_name, data_type, is_null, default_val, pk \
            in conn.execute('PRAGMA table_info(cookies)'):
        if column_name == 'secure':
            secure_column_name = 'secure'
            break

    sql = ('select host_key, path, ' + secure_column_name +
           ', expires_utc, name, value, encrypted_value '
           'from cookies')

    cookies = dict()

    for hk, path, is_secure, expires_utc, cookie_key, val, enc_val in conn.execute(sql):
        if val or (enc_val[:3] not in (b'v10', b'v11')):
            pass
        else:
            val = chrome_decrypt(enc_val, key=enc_key, init_vector=config['init_vector'])
            cookies[cookie_key] = val
            f = open(output, "a")
            f.write(hk + '\tFALSE\t/\tFALSE\t000000000\t' + cookie_key + '\t' + val + '\n')
            f.close()

    conn.rollback()

    return cookies


parser = argparse.ArgumentParser(description="CookieMonstruo apple!")
parser.add_argument('-p', dest='pwd', metavar='Chrome safe-storage password', type=str, required=True)
parser.add_argument('-f', dest='file', metavar='Cookie database file-path', type=str, required=True)
args = parser.parse_args()


cookies = chrome_cookies(args.pwd, args.file)