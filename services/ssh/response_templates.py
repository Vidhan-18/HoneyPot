PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"""

SHADOW = """root:$6$rounds=4046$vXqD...:18742:0:99999:7:::
daemon:*:18742:0:99999:7:::
bin:*:18742:0:99999:7:::
sys:*:18742:0:99999:7:::
sync:*:18742:0:99999:7:::
games:*:18742:0:99999:7:::
man:*:18742:0:99999:7:::
lp:*:18742:0:99999:7:::
mail:*:18742:0:99999:7:::
news:*:18742:0:99999:7:::
uucp:*:18742:0:99999:7:::
proxy:*:18742:0:99999:7:::
www-data:*:18742:0:99999:7:::
backup:*:18742:0:99999:7:::
list:*:18742:0:99999:7:::
irc:*:18742:0:99999:7:::
gnats:*:18742:0:99999:7:::
nobody:*:18742:0:99999:7:::
systemd-network:*:18742:0:99999:7:::
systemd-resolve:*:18742:0:99999:7:::
systemd-timesync:*:18742:0:99999:7:::
messagebus:*:18742:0:99999:7:::
syslog:*:18742:0:99999:7:::
_apt:*:18742:0:99999:7:::
tss:*:18742:0:99999:7:::
uuidd:*:18742:0:99999:7:::
tcpdump:*:18742:0:99999:7:::
landscape:*:18742:0:99999:7:::
pollinate:*:18742:0:99999:7:::
sshd:*:18742:0:99999:7:::
systemd-coredump:!!:18742::::::
ubuntu:$6$rounds=4046$zYz...:18742:0:99999:7:::"""

SECRET = "CONFIDENTIAL: aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

UNAME = "Linux ubuntu 5.15.0-71-generic #78-Ubuntu SMP Tue Apr 18 09:00:29 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"

PS = """  PID TTY          TIME CMD
    1 ?        00:00:01 init
   10 ?        00:00:00 kthreadd
 1432 ?        00:00:00 sshd
 1433 pts/0    00:00:00 bash
 1450 pts/0    00:00:00 ps"""

IFCONFIG = """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 172.31.22.18  netmask 255.255.240.0  broadcast 172.31.31.255
        ether 06:12:34:56:78:90  txqueuelen 1000  (Ethernet)
        RX packets 14532  bytes 1234567 (1.2 MB)
        TX packets 8923  bytes 987654 (987.6 KB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 24  bytes 1800 (1.8 KB)
        TX packets 24  bytes 1800 (1.8 KB)"""

ID_ROOT = "uid=0(root) gid=0(root) groups=0(root)"
ID_USER = "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),27(sudo)"
