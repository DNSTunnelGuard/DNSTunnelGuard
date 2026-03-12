
#!/bin/bash
gcc -fPIC -shared -o libguard.so src/bpf/libguard.c -lbpf
