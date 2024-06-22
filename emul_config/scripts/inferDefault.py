#!/usr/bin/env python3

import sys
import os
import subprocess

def GetKeyList(IID, scratch):
    keyList = []
    for i in open('{}/{}/qemu.initial.serial.log'.format(scratch,IID), 'rb').read().split(b'\n'):
        if i.startswith(b'[NVRAM]'):
            l = i.split(b' ')
            if len(l) < 3: continue
            if not l[1].decode().isnumeric(): continue
            keyLen = int(l[1].decode())
            key = l[2][:keyLen]
            # TODO: if you can parse null seperated key/value data in the binary, then remove equal character
            #key = (i.split(b':')[1].strip())
            try:
                key.decode()
            except:
                # invalid key info
                continue
            if key not in keyList:
                keyList.append(key)
    return keyList

def GetDefaultFiles(keyList, scratch):
    default_list = []
    for dir_name, dir_list, file_list in os.walk('{}/{}/image'.format(scratch, IID)):
        if dir_name.find('/firmadyne') != -1: continue

        for file_name in file_list:
            count = 0
            if not os.path.isfile(dir_name + '/' + file_name): continue
            data = open(dir_name + '/' + file_name, 'rb').read()
            for key in keyList:
                if data.find(key) != -1:
                    count += 1
            # TODO: adjust approximate value
            # TODO: need to save the start index of the nvram data to parsing from the binary
            if count > len(keyList) // 2:
                default_list.append((dir_name + '/' + file_name, count))
    return default_list

def Log(default_list, scratch):
    # logging found nvram keys
    with open('{}/{}/nvram_keys'.format(scratch,IID), 'w') as out:
        out.write(str(len(keyList)) + '\n')
        for i in keyList:
            out.write(i.decode() + '\n')

    # logging default nvram files
    if default_list:
        with open('{}/{}/nvram_files'.format(scratch, IID), 'w') as f:
            for i, j in default_list:
                path = i.split('image')[1]
                output = subprocess.check_output(['file', i]).decode()[:-1]
                fileType = output.split(' ', 1)[1].replace(' ', '_')
                if fileType.find('symbolic') == -1:
                    f.write('{} {} {}\n'.format(path, j, fileType))
        os.system('cp {}/{}/nvram_files {}/{}/image/firmadyne/'.format(scratch, IID, scratch, IID))

if __name__ == "__main__":
    # execute only if run as a script
    IID = sys.argv[1]
    scratch = sys.argv[2]
    keyList = GetKeyList(IID, scratch)
    if len(keyList) < 10:
        exit(0)
    defaultList = GetDefaultFiles(keyList, scratch)
    Log(defaultList, scratch)
