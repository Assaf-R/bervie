# bervie.py
# eBpf based process yara scanner by Assaf R.
# --- --- ---

# Imports
from bcc import BPF
import socket, struct, ctypes
import yara, os, time, datetime, argparse

# Constants
EBPF_PROGRAM = "bervie_bpf.c"
BUFFER_SIZE = 128 * 1024  # 128KB
LOG_FOLDER = "/var/log/loch"
LOG_NAME = "bervie"
LOG_EXTENT = ".log"
LOG_MAX_SIZE = 8192

YARA_RULES_PATH = "example.yara"

# Globals
with open (EBPF_PROGRAM, 'r') as raw_program:
        program = raw_program.read()
b = BPF(text=program, cflags=["-Wno-macro-redefined"])
rules = yara.compile(filepath=YARA_RULES_PATH)

def check_against_yara(filepath):
    """ Scan the file with YARA and return True (1) if it's flagged, otherwise False (0). """
    matches = rules.match(filepath)
    if matches:
        return 1
    else:
        return 0
    # try:
    #     matches = rules.match(filepath)
    #     return 1 if matches else 0
    # except Exception as e:
    #     print(f"YARA scan error: {e}")
    #     return 0

def process_data(cpu, data, size):
    '''
    converts data to dictionary and print it
    '''
    data = b["output"].event(data)
    event = {
        "event_time": data.event_time,
        "syscall": data.syscall_name.decode(),
        "pid": data.pid,
        "ppid": data.ppid,
        "uid": data.uid,
        "process_path": data.process_path.decode(),
        "parent_process_name": data.parent_process_name.decode(),
    }
    
    b["is_block"][ctypes.c_int(0)] = ctypes.c_int(check_against_yara(event["process_path"]))
    
    # check_against_yara(event["process_path"])  # Key is always 0

    print(event)

def main():

    s_execve = b.get_syscall_fnname("execve")

    b.attach_kprobe(event=s_execve, fn_name="syscall__execve")


    b["output"].open_perf_buffer(process_data, page_cnt=BUFFER_SIZE // 4096) 
    
    while True:  
        try: 
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    main() 