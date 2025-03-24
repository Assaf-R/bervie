### Bervie
An eBpf security program that blocks the execution of files that were flagged as malicious by the give YARA detection rules. Named in convention with the other Scottish loch tools 

### How does this work?
The python program - **bervie.py** - loads the bpf c program - **bervie_bpf.c** - and hooks the execve syscall with a kprobe.
The eBpf program checks if the file that is set to be executed checks any YARA detections from the given .yara file and if so blocks the execution.
The results are logged to /var/log/loch/bervieX.log

### How to run
***RUN AS ROOT*** \

$ pip install yara-python