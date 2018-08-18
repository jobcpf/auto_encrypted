"""
Configuration data.

@Author: oliver.blakeman@carbonprojectfinance.co.uk
@Date: 2018-07-28

"""

################## Variables #################################### Variables #################################### Variables ##################

# prog
VC = '/usr/bin/veracrypt'
SYS_SLEEP = 2

## device mount
DEV = 'sd' # look for in dev_search
DEV_DIR = '/dev/' # search for dev in dir
MNT_EXC = ['sda',] # avoid devices in dev_search
MNT_DIR = '/home/ferret/.auto_enc' # dir to mount device for credenital search
MNT_IDS = 'uid={uid},gid={gid}' # mount id string

## device security
PUB_KF = 'logfile0_364' # file name containing device public key
PRV_KEY_DIR = '{home}/.ssh' # private key dir, relative to user home
PRV_KF = 'auto_enc.ferret.linux' # private key

## secure config
CONF_DIR = '/home/ferret/dev/auto_encrypted/config' # location of config files
CONF_EXT = '.cnf' # config file extension
CONF_EXT_E = '.cfe' # encrypted config file extension

## encrypted device mount configurations
ENC_VOL_CFE = ['logfile0_80',
               ]
