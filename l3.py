#region imports
from os import path
import os
import sys

import json
from base64 import b64encode
from base64 import b64decode

from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

import getpass

import traceback
import jsonpickle

from datetime import datetime
#endregion


#region config
_force_password_complexity = True  # Default =True; WARNING: setting this to =False is not recommended!
_minimim_pwd_len = 8               # Default =8, min =1, max =_max_input_len-1
_max_input_len = 256               # Default =256, min =2
_max_pwdAge_days = 31              # Default =31, min =1, max =inf
#endregion


#region classes
class UserData(object):
    def __init__(self, nonce: bytes, pwdHash: bytes, changeBool: bool = False):
        self._nonce = b64encode(nonce).decode('ascii')
        self._pwdHash = b64encode(pwdHash).decode('ascii')
        self._changeBool = changeBool
        self._setDate = (datetime.utcnow() - datetime(1970, 1, 1)).days

    @property
    def nonce(self):
        return b64decode(self._nonce)

    @nonce.setter
    def _set_nonce(self, newNonce: bytes):
        self._nonce = b64encode(newNonce).decode('ascii')

    def _get_pwdHash(self):
        return b64decode(self._pwdHash)

    def _set_pwdHash(self, newPwdHash: bytes):
        self._pwdHash = b64encode(newPwdHash).decode('ascii')

    pwdHash = property(_get_pwdHash, _set_pwdHash)

    def changeBool(self):
        return self._changeBool

    def setChangeBool(self):
        self._changeBool = True

    def clearChangeBool(self):
        self._changeBool = False

    def isPwdTooOld(self):
        if _max_pwdAge_days < 1 or _max_pwdAge_days == "inf":
            return False
        return (datetime.utcnow() - datetime(1970, 1, 1)).days - self._setDate > _max_pwdAge_days
#endregion


#region utility (unchanged from l2)
def printAvailableCommands():
    commands = [
        "usermgmt add <user>",
        "usermgmt passwd <user>",
        "usermgmt forcepass <user>",
        "usermgmt del <user>",
        "login <user>",
        "vault get <user> <address>",
        "vault put <user> <address>",
        "vault list <user>",
        "vault del <user> <address>",
    ]
    print("Available commands:")
    for cmd in commands:
        print(cmd)

def getPwd(login=False, forced=False):
    acceptable = False
    while not acceptable:
        if not forced:
            input1 = getpass.getpass(prompt='Password: ')
        else:
            input1 = getpass.getpass(prompt='New password: ')
        if not login and (len(input1) > _max_input_len):
            print("New password must have less than {} characters".format(_max_input_len))
            continue
        if _force_password_complexity and (not login) and (len(input1) < _minimim_pwd_len):
            print("New password must be at least {} characters long".format(_minimim_pwd_len))
            continue
        if _force_password_complexity and (not login) and (
                input1.islower() or input1.isupper() or input1.isalpha() or input1.isnumeric()):
            print("New password must contain at least one: lowercase letter, uppercase letter and a number")
            continue
        acceptable = True
    if (not login) or forced:
        input2 = getpass.getpass(prompt='Repeat Password: ')
        if input1 != input2:
            raise IOError
    return input1

def storageFactory():
    storage = dict()
    newNonce = get_random_bytes(16)
    pwd = "Pwd" + (_minimim_pwd_len - 3) * "1"

    """ref: https://pycryptodome.readthedocs.io/en/latest/src/hash/hash.html
    hashObj = SHA256.new(data=b'newPwd')
    hashObj.update(b'nonce')
    pwdHash = hashObj.digest()

    scrpyt used instead of SHA256:
    https://qvault.io/cryptography/very-basic-intro-to-key-derivation-functions-argon2-scrypt-etc/
    https://tools.ietf.org/id/draft-ietf-kitten-password-storage-01.html
    https://blog.tjll.net/please-stop-hashing-passwords/
    """

    derivedHash = scrypt(pwd, newNonce, int(128 / 8), N=2 ** 15, r=8, p=1, num_keys=1)
    storage["test"] = UserData(newNonce, derivedHash)
    return storage

def checkFile(create=False):
    if not path.exists("storage.txt") and create:
        with open("storage.txt", mode='w', encoding='utf-8') as fStorage:
            storage = storageFactory()
            newStorageSerialised = jsonpickle.encode(storage)
            fStorage.write(newStorageSerialised)
            return False
    elif not path.exists("storage.txt") and not create:
        return False
    else:
        return True
#endregion


#region vault helpers
def _vault_paths(user: str):
    """Return (vault_data_path, vault_params_path) for a given user."""
    return f"vault_{user}.bin", f"vault_{user}_params.json"

def _vault_derive_key(pwd: str, salt: bytes) -> bytes:
    """Derive a 128-bit AES key from the user's login password."""
    return scrypt(pwd, salt, int(128 / 8), N=2 ** 14, r=8, p=1, num_keys=1)

def _vault_init(user: str, pwd: str):
    """
    Create an empty vault for `user` encrypted with `pwd`.
    Called automatically on first vault write; safe to call if vault already exists.
    Returns True if created, False if already existed.
    """
    vdata, vparams = _vault_paths(user)
    if path.exists(vdata) and path.exists(vparams):
        return False

    salt = get_random_bytes(16)
    key = _vault_derive_key(pwd, salt)
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    empty = json.dumps({}).encode('utf-8')
    encrypted, tag = cipher.encrypt_and_digest(empty)

    with open(vdata, 'wb') as f:
        f.write(encrypted)
    with open(vparams, 'w', encoding='utf-8') as f:
        json.dump({
            'salt':  b64encode(salt).decode('ascii'),
            'nonce': b64encode(nonce).decode('ascii'),
            'tag':   b64encode(tag).decode('ascii'),
        }, f)
    return True

def _vault_read(user: str, pwd: str):
    """
    Decrypt and return the vault dict for `user`.
    Raises ValueError if the password is wrong or the file is corrupted.
    Raises FileNotFoundError if the vault doesn't exist yet.
    """
    vdata, vparams = _vault_paths(user)
    if not path.exists(vdata) or not path.exists(vparams):
        raise FileNotFoundError

    with open(vparams, 'r', encoding='utf-8') as f:
        params = json.load(f)

    salt  = b64decode(params['salt'])
    nonce = b64decode(params['nonce'])
    tag   = b64decode(params['tag'])
    key   = _vault_derive_key(pwd, salt)

    with open(vdata, 'rb') as f:
        encrypted = f.read()

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(encrypted, tag)   # raises ValueError on bad key/tamper
    return json.loads(decrypted)

def _vault_write(user: str, pwd: str, vault: dict):
    """
    Encrypt and persist `vault` for `user` using `pwd`.
    Rotates nonce on every write; updates params file atomically.
    """
    vdata, vparams = _vault_paths(user)

    with open(vparams, 'r', encoding='utf-8') as f:
        params = json.load(f)
    salt = b64decode(params['salt'])

    key      = _vault_derive_key(pwd, salt)
    newNonce = get_random_bytes(16)
    cipher   = AES.new(key, AES.MODE_GCM, nonce=newNonce)
    serialised = json.dumps(vault).encode('utf-8')
    encrypted, newTag = cipher.encrypt_and_digest(serialised)

    with open(vdata, 'wb') as f:
        f.write(encrypted)

    params['nonce'] = b64encode(newNonce).decode('ascii')
    params['tag']   = b64encode(newTag).decode('ascii')
    with open(vparams, 'w', encoding='utf-8') as f:
        json.dump(params, f)

def _vault_delete_files(user: str):
    """Remove vault files for a deleted user. Silent if they don't exist."""
    for p in _vault_paths(user):
        if path.exists(p):
            os.remove(p)
#endregion


#region user-management functions (identical to l2, except login returns the pwd)
def addUser(user: str):
    _ = checkFile(create=True)
    with open("storage.txt", mode='r+', encoding='utf-8') as fStorage:
        try:
            storage = jsonpickle.decode(fStorage.read())
        except json.decoder.JSONDecodeError:
            print("Error: storage.txt failed to decode because its integrity has been lost")
            return

        if user in storage:
            print("Error: User {} already exists".format(user))
            return

        newPwd = getPwd()
        newNonce = get_random_bytes(16)
        derivedHash = scrypt(newPwd, newNonce, int(128 / 8), N=2 ** 15, r=8, p=1, num_keys=1)
        storage[user] = UserData(newNonce, derivedHash)

        fStorage.seek(0)
        fStorage.truncate()
        fStorage.write(jsonpickle.encode(storage))

    print("User {} successfully added".format(user))

def updatePwd(user: str, forced=False, _old_pwd: str = None, _new_pwd: str = None):
    """
    Change a user's password.
    If called from the UI, _old_pwd and _new_pwd can be supplied directly so
    the vault can be re-encrypted without prompting again.
    When called from the CLI (or internally by login), they are None and
    getPwd() is used as before.
    """
    existed = checkFile()
    if not existed:
        print("Error: storage.txt doesn't exist, can't change password. Add a user to create the file")
        return
    with open("storage.txt", mode='r+', encoding='utf-8') as fStorage:
        try:
            storage = jsonpickle.decode(fStorage.read())
        except json.decoder.JSONDecodeError:
            print("Error: storage.txt failed to decode because its integrity has been lost")
            return

        if user not in storage:
            print("Error: User {} doesn't exist".format(user))
            return

        userData  = storage[user]
        storedHash  = userData.pwdHash
        storedNonce = userData.nonce

        same = True
        while same:
            if _new_pwd is None:
                newPwd = getPwd(forced=forced)
            else:
                newPwd = _new_pwd
                _new_pwd = None   # only use the supplied value once; loop shouldn't repeat
            derivedCheck = scrypt(newPwd, storedNonce, int(128 / 8), N=2 ** 15, r=8, p=1, num_keys=1)
            if derivedCheck == storedHash:
                print("New password must be different from the old password")
                if _new_pwd is None:
                    continue   # prompt again
                else:
                    return     # called programmatically — bail out
            same = False

        newNonce = get_random_bytes(16)
        derivedNewHash = scrypt(newPwd, newNonce, int(128 / 8), N=2 ** 15, r=8, p=1, num_keys=1)
        storage[user] = UserData(newNonce, derivedNewHash)

        fStorage.seek(0)
        fStorage.truncate()
        fStorage.write(jsonpickle.encode(storage))

    # Re-encrypt vault with new password if it exists
    vdata, _ = _vault_paths(user)
    if path.exists(vdata):
        old = _old_pwd if _old_pwd is not None else getpass.getpass(prompt='Current password (for vault re-encryption): ')
        try:
            vault = _vault_read(user, old)
            _vault_write(user, newPwd, vault)
        except (ValueError, FileNotFoundError):
            print("Warning: vault re-encryption failed — vault may be inaccessible until password is corrected")

    print("Password for user {} successfully updated".format(user))

def setChangeFlag(user: str):
    existed = checkFile()
    if not existed:
        print("Error: storage.txt doesn't exist, can't set 'change' flag. Add a user to create the file")
        return
    with open("storage.txt", mode='r+', encoding='utf-8') as fStorage:
        try:
            storage = jsonpickle.decode(fStorage.read())
        except json.decoder.JSONDecodeError:
            print("Error: storage.txt failed to decode because its integrity has been lost")
            return

        if user not in storage:
            print("Error: User {} doesn't exist".format(user))
            return

        userData = storage[user]
        userData.setChangeBool()
        storage[user] = userData

        fStorage.seek(0)
        fStorage.truncate()
        fStorage.write(jsonpickle.encode(storage))

    print("User {} will be requested to change password on next login".format(user))

def delUser(user: str):
    existed = checkFile()
    if not existed:
        print("Error: storage.txt doesn't exist, can't delete user. Add a user to create the file")
        return
    with open("storage.txt", mode='r+', encoding='utf-8') as fStorage:
        try:
            storage = jsonpickle.decode(fStorage.read())
        except json.decoder.JSONDecodeError:
            print("Error: storage.txt failed to decode because its integrity has been lost")
            return

        if user not in storage:
            print("Error: User {} doesn't exist".format(user))
            return

        del storage[user]

        fStorage.seek(0)
        fStorage.truncate()
        fStorage.write(jsonpickle.encode(storage))

    _vault_delete_files(user)
    print("User {} successfully deleted".format(user))

def login(user: str) -> str | None:
    """
    Authenticate user.  Returns the plaintext password on success (so the
    caller can use it as the vault key), or None on failure.
    If a forced/expired password change is required, handles it internally and
    returns the NEW password.
    """
    existed = checkFile()
    if not existed:
        print("Error: storage.txt doesn't exist, can't login. Add a user to create the file")
        return None
    with open("storage.txt", mode='r+', encoding='utf-8') as fStorage:
        try:
            storage = jsonpickle.decode(fStorage.read())
        except json.decoder.JSONDecodeError:
            print("Error: storage.txt failed to decode because its integrity has been lost")
            return None

        pwd = getPwd(login=True)

        if user not in storage:
            print("Username or password incorrect")
            return None

        userData = storage[user]
        storedNonce = userData.nonce
        newDerivedHash = scrypt(pwd, storedNonce, int(128 / 8), N=2 ** 15, r=8, p=1, num_keys=1)
        storedHash = userData.pwdHash

        if newDerivedHash != storedHash:
            print("Username or password incorrect")
            return None

        print("Login successful")

        if userData.changeBool() or userData.isPwdTooOld():
            # updatePwd will prompt for new password and re-encrypt vault
            updatePwd(user, forced=True, _old_pwd=pwd)
            # Read back the new hash to derive the new password — we can't get
            # the plaintext back from the hash, so we ask once more via getpass.
            # Instead, we call a helper that returns the new pwd directly.
            new_pwd = _forced_change_and_return(user, pwd)
            return new_pwd

        return pwd

def _forced_change_and_return(user: str, old_pwd: str) -> str | None:
    """
    Perform a forced password change and return the new plaintext password.
    Called by login() when changeBool or isPwdTooOld fires.
    """
    existed = checkFile()
    if not existed:
        return None
    with open("storage.txt", mode='r+', encoding='utf-8') as fStorage:
        try:
            storage = jsonpickle.decode(fStorage.read())
        except json.decoder.JSONDecodeError:
            return None

        if user not in storage:
            return None

        userData   = storage[user]
        storedHash  = userData.pwdHash
        storedNonce = userData.nonce

        same = True
        new_pwd = None
        while same:
            new_pwd = getPwd(forced=True)
            derivedCheck = scrypt(new_pwd, storedNonce, int(128 / 8), N=2 ** 15, r=8, p=1, num_keys=1)
            if derivedCheck == storedHash:
                print("New password must be different from the old password")
                continue
            same = False

        newNonce = get_random_bytes(16)
        derivedNewHash = scrypt(new_pwd, newNonce, int(128 / 8), N=2 ** 15, r=8, p=1, num_keys=1)
        storage[user] = UserData(newNonce, derivedNewHash)

        fStorage.seek(0)
        fStorage.truncate()
        fStorage.write(jsonpickle.encode(storage))

    # Re-encrypt vault
    vdata, _ = _vault_paths(user)
    if path.exists(vdata):
        try:
            vault = _vault_read(user, old_pwd)
            _vault_write(user, new_pwd, vault)
        except (ValueError, FileNotFoundError):
            print("Warning: vault re-encryption failed")

    print("Password for user {} successfully updated".format(user))
    return new_pwd
#endregion


#region vault functions
def vaultGet(user: str, pwd: str, address: str):
    """Print the stored password for address from user's vault."""
    try:
        vault = _vault_read(user, pwd)
    except FileNotFoundError:
        print("No vault found for user {}. Store a password first.".format(user))
        return
    except ValueError:
        print("Error: vault decryption failed — wrong password or corrupted vault")
        return

    if address in vault:
        stored = unpad(b64decode(vault[address]), 256).decode('utf-8')
        print("Password for {}: {}".format(address, stored))
    else:
        print("No entry found for {}".format(address))

def vaultPut(user: str, pwd: str, address: str, entry_pwd: str = None):
    """Store or update a password for address in user's vault."""
    # Initialise vault on first use
    _vault_init(user, pwd)

    try:
        vault = _vault_read(user, pwd)
    except ValueError:
        print("Error: vault decryption failed — wrong password or corrupted vault")
        return

    update = address in vault

    if entry_pwd is None:
        entry_pwd = getpass.getpass(prompt='Entry password: ')

    padded = b64encode(pad(entry_pwd.encode('utf-8'), 256)).decode('ascii')
    vault[address] = padded
    _vault_write(user, pwd, vault)

    if update:
        print("Updated password for {}".format(address))
    else:
        print("Stored password for {}".format(address))

def vaultList(user: str, pwd: str):
    """List all addresses stored in user's vault."""
    try:
        vault = _vault_read(user, pwd)
    except FileNotFoundError:
        print("No vault found for user {}. Store a password first.".format(user))
        return
    except ValueError:
        print("Error: vault decryption failed — wrong password or corrupted vault")
        return

    entries = [k for k in vault.keys() if k != "test"]
    if not entries:
        print("Vault is empty")
    else:
        print("Vault entries for {}:".format(user))
        for entry in entries:
            print("  - {}".format(entry))

def vaultDel(user: str, pwd: str, address: str):
    """Delete an entry from user's vault."""
    try:
        vault = _vault_read(user, pwd)
    except FileNotFoundError:
        print("No vault found for user {}.".format(user))
        return
    except ValueError:
        print("Error: vault decryption failed — wrong password or corrupted vault")
        return

    if address not in vault:
        print("No entry found for {}".format(address))
        return

    del vault[address]
    _vault_write(user, pwd, vault)
    print("Deleted entry for {}".format(address))
#endregion


#region calls&main
try:
    args = [arg for arg in sys.argv]
    args.pop(0)

    argNum = len(args) - 1
    if argNum <= 0:
        raise RuntimeError

    prog = args[0]

    if prog == "usermgmt" and argNum == 2:
        cmd  = args[1]
        user = args[2]
    elif prog == "login" and argNum == 1:
        user = args[1]
    elif prog == "vault" and argNum >= 2:
        cmd  = args[1]
        user = args[2]
    else:
        raise ProcessLookupError

    if len(user) > _max_input_len:
        raise ValueError

    if prog == "usermgmt" and cmd == "add":
        addUser(user)
    elif prog == "usermgmt" and cmd == "passwd":
        updatePwd(user)
    elif prog == "usermgmt" and cmd == "forcepass":
        setChangeFlag(user)
    elif prog == "usermgmt" and cmd == "del":
        delUser(user)
    elif prog == "login":
        login(user)
    elif prog == "vault" and cmd == "list":
        pwd = getpass.getpass(prompt='Password: ')
        vaultList(user, pwd)
    elif prog == "vault" and cmd == "get" and argNum == 3:
        address = args[3]
        pwd = getpass.getpass(prompt='Password: ')
        vaultGet(user, pwd, address)
    elif prog == "vault" and cmd == "put" and argNum == 3:
        address = args[3]
        pwd = getpass.getpass(prompt='Password: ')
        vaultPut(user, pwd, address)
    elif prog == "vault" and cmd == "del" and argNum == 3:
        address = args[3]
        pwd = getpass.getpass(prompt='Password: ')
        vaultDel(user, pwd, address)
    else:
        raise ProcessLookupError

except RuntimeError:
    print("Error: attempt to start the program with no command or parameter")
    printAvailableCommands()

except ProcessLookupError:
    print("Error: unknown command or wrong number of arguments")
    printAvailableCommands()

except IOError:
    print("Error: password mismatch")

except ValueError:
    print("Error: username must have less than {} characters".format(_max_input_len))

except Exception:
    print(traceback.format_exc())
#endregion
