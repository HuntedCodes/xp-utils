#!/usr/bin/python

import re
from subprocess import call, check_output
import sys

def usage():
    print( "[*] Usage:\n\t"
           "%s i - information about OS stack protections\n\t"
           "%s d - disable ASLR (requires sudo)\n\t"
           "%s e - enable ASLR (requires sudo)\n\t" 
           % (sys.argv[0],sys.argv[0],sys.argv[0]))

def info_aslr():
    f = open("/proc/sys/kernel/randomize_va_space","rb")
    status = int(f.read()[0])
    f.close()
    return status

def info_display_aslr():
    status_code = info_aslr()
    status_msg = ""
    if status_code==0:
      status_msg = "Disabled"
    elif status_code==1 or status_code==2:
      status_msg = "Enabled"
    print("[*] ASLR \t %s (%d)" % (status_msg,status_code))

def info_nx():
    dmesg = check_output(['dmesg']).split('\n')
    pattern = '[NX|DX]*protection'
    for line in dmesg:
        result = re.search(pattern,line)
        if result:
            return True
    return False

def info_display_nx():
    nx_enabled = info_nx()
    msg = "Disabled"
    if nx_enabled:
      msg = "Enabled (check individual program attributes)"
    print("[*] NX-bit \t %s" % (msg))

def protection_info():
    info_display_aslr()
    info_display_nx()

def toggle_aslr(value):
    if int(value) < 3:
        f = open("/proc/sys/kernel/randomize_va_space","wb")
        call(["echo", value], stdout=f)
        f.close()
        info_display_aslr()

def disable_aslr():
    toggle_aslr('0')

def enable_aslr():
    toggle_aslr('2')

if __name__ == "__main__":
    if len(sys.argv)<2:
        usage()
    elif sys.argv[1] == 'i':
        protection_info()
    elif sys.argv[1] == 'd':
        disable_aslr()
    elif sys.argv[1] == 'e':
        enable_aslr()
    else:
        usage()
