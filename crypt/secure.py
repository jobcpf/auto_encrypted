"""
Cryptography Script.

Secure & serve content using cryptographic keys.

@Author: oliver.blakeman@carbonprojectfinance.co.uk
@Date: 2018-07-12

"""
################## Packages #################################### Packages #################################### Variables ##################

# Standard import
import sys
import os
import time
import json

from Crypto.PublicKey import RSA

################## Modules #################################### Modules #################################### Modules ##################

from .crypt import encrypt, decrypt

################## Variables #################################### Variables #################################### Variables ##################

import config as config

################## Functions ###################################### Functions ###################################### Functions ####################

def secure_config(current_env, source_dir = None):
    """Encrypt config files.
    
    1. if [source_dir] recurse subdirectories for plain text config file & encrypt to default dir
    2. else encrypt plain text config files in default dir
    
    > [source_dir] to search
    < True, False
    
    """
    func_name = sys._getframe().f_code.co_name
    
    confs = []
    
    # test if source dir passed
    if source_dir :
        # traverse source_dir to find configuration files (by extension)
        for dir_name, subdirs_name, file_names in os.walk(source_dir, topdown=True):
            for file_name in file_names:
                if config.CONF_EXT in file_name:
                    confs.append((file_name,dir_name))
    
    else:
        # get credential files from default configuration dir
        confs = [ (x,config.CONF_DIR) for x in os.listdir(config.CONF_DIR) if config.CONF_EXT in x]
    
    # return false if no config files present
    if not confs :
        return False
    
    # iterate config files
    for conf, conf_dir in confs :
        
        with open(os.path.join(conf_dir, conf)) as json_data:
            d = json.load(json_data)
        
        # keys to string
        string_data = json.dumps(d)
        
        # get private_key
        try:
            pkf = os.path.join(config.PRV_KEY_DIR.format(home=current_env), config.PRV_KF)
            with open(pkf, "r") as prv_file:
                private_key = prv_file.read()
        except IOError as e:
            logging.error('%s:%s: Private key not present: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), func_name, pkf))
            return False
        
        # encrypt config
        encrypted = encrypt(string_data, private_key)
        
        # new filename
        conf_encrypted = "%s%s" % (conf.split('.')[0], config.CONF_EXT_E)
        
        # write encrypted key file
        with open(os.path.join(config.CONF_DIR, conf_encrypted), "w") as config_file_encrypted:
            config_file_encrypted.write(encrypted)
    
    return True


def get_config(private_key, path):
    """Get configuration data from encrypted files.
    
    > path to encrypted config
    < decrypted config
    
    """
    func_name = sys._getframe().f_code.co_name
    
    try:
        # get encrypted config from config.CONF_BASE
        with open(path, "r") as config_file_encrypted:
            encrypted = config_file_encrypted.read()
    except IOError as e:
        # file not present
        return False
    
    else:
        # decrypt
        decrypted = decrypt(encrypted, private_key)
        
        # get dict from JSON decoded or remove config file if cannot decode
        try:
            decrypt_dict = json.loads(decrypted)
        except ValueError as e:
            return False
    
    return decrypt_dict


def test_keys(private_key, public_key):
    """Validate a public - private key pair.
    
    > private key, public_key
    < True / False
    
    https://stackoverflow.com/questions/18173007/validating-a-dsa-key-pair-with-pycrypto-getting-pqg-values
    
    """
    func_name = sys._getframe().f_code.co_name
    
    message = 'Encrypted message'
    
    if 'ssh-rsa' in public_key:
    
        public_key_container = RSA.importKey(public_key)
        private_key_container = RSA.importKey(private_key)
    
        encrypted_message = public_key_container.encrypt(message, 0)
        decrypted_message = private_key_container.decrypt(encrypted_message)
    
        if message == decrypted_message:
            return True
    
    return False
