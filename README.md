# Nsustain.com Deployment

<br>

> Nsustain is for anyone who loves the e[N]vironment and [sustain]ability.
> Anyone is welcome to join us if you'd like to volunteer to code for people who work in the field and write something that will have a direct impact.

<br>

## Infrastructure

| ***Program*** | ***Purpose*** |
| ---- | ---- |
| ***Hetzner*** | One of the best VPS service providers in the world; it's affordable and pleasant to use. Both my application server and logging server are hosted here. |
| ***rsyslog*** | "Rocket-fast System for Log Processing." I use `rsyslog` for aggregating all log entries (system logs, Docker container logs, etc) in my application server and relaying them to my logging and monitoring server. |
| ***Stunnel*** | "A multiplatform GNU/GPL-licensed proxy encrypting arbitrary TCP connections with SSL/TLS." Although `rsyslog` supports SSL/TLS, it's only single-threaded.<sup>[1]</sup> Using `Stunnel`, all my `rsyslog` transmissions are encrypted and multi-threaded. |
| ***Tarsnap*** | One of the most, if not the most, secure backup service. I use `Tarsnap` for regular backups of my servers. |

<sub>[1] https://coders-home.de/en/set-up-an-rsyslog-server-with-multithreaded-tls-encryption-using-stunnel-1245.html</sub>

<br>

> [!NOTE]  
> `syslog` is a plaintext logging system,<sup>[2]</sup> while `journald` is a binary
> logging system. `journald` was created more recently, but I chose to
> use `syslog` (rsyslog) because `syslog` is said to be simpler at
> spooling and saving logs to a centralized logging server.

<sub>[2] https://datatracker.ietf.org/doc/html/rfc5424</sub>

<br>

#### Deployment Code

```
Application Server - 3 vCPU, 4GB RAM, 80GB SSD. Ubuntu LTS
Monitoring Server - 2 vCPU, 2GB RAM, 40GB SSD. Ubuntu LTS
```

```bash
# ---------------------------------------------------------------------
# 1. [Both] Add a non-root user and configure sshd for security.
# ---------------------------------------------------------------------
# [Both] here means run the following commands in both the application
# server and the monitoring server.
adduser soobinrho
usermod -a -G sudo soobinrho

# By default on `journalctl`, users can only see logs limited to their own programs.
# Adding to the administrators group `adm` allows you to see all logs.
usermod -a -G adm soobinrho

# Change the hostname if desired.
hostnamectl set-hostname newHostName

# Copy the authorized ssh pub key from root to new user.
mkdir /home/soobinrho/.ssh
cp ~/.ssh/authorized_keys /home/soobinrho/.ssh/
chown -R soobinrho:soobinrho /home/soobinrho/.ssh

# Login to the new user.
su - soobinrho

# Test ssh connection to the new user.
# Then, open the sshd config file for more secure settings.
sudo vim /etc/ssh/sshd_config

# Add these two lines at the end of the config file:
PasswordAuthentication no
PermitRootLogin no

# Restart SSH
sudo service ssh restart

# -------------------------------------------------------------------
# 2. [Application Server] Configure firewall.
# -------------------------------------------------------------------
# Allow inbound traffic with port 443 TCP/UDP (Cloudflare Tunnel)
# Allow inbound traffic with port 80  TCP/UDP (Cloudflare Tunnel)
# Allow inbound traffic with port 22  TCP/UDP from your IP address (ssh)
sudo ufw reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 443
sudo ufw allow 80
sudo ufw allow from <home IP> to any port 22
sudo ufw enable

# Confirm current firewall rules.
sudo ufw status

# FYI, whenever a service has a designated port - e.g. 22 for SSH -
# it almost always uses just the TCP protocol, but it's often a good
# practice to open accept both TCP and UDP as future reserve.

# -------------------------------------------------------------------
# 3. [Logging Server] Configure firewall.
# -------------------------------------------------------------------
# Allow inbound traffic with port 6514 TCP/UDP (rsyslog & Stunnel TLS)
# Allow inbound traffic with port 22   TCP/UDP from your IP address (ssh)
sudo ufw reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from <application server IP> to any port 6514
sudo ufw allow from <home IP> to any port 22
sudo ufw enable

# Confirm current firewall rules.
sudo ufw status

# Also, apply the same firewall rules on Hetzner firewall.

# -------------------------------------------------------------------
# 4. [Logging Server] Configure SSL/TLS encrypted logging.
# -------------------------------------------------------------------
sudo systemctl start rsyslog
sudo systemctl enable rsyslog

# Append to the end of rsyslog config file.
# Source:
#   https://www.rsyslog.com/receiving-messages-from-a-remote-system/
sudo vim /etc/rsyslog.conf
```
```
# ---------------------------------------------------------------------
# Configure rsyslog to listen and receive remote logs.
# Source:
#   https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/system_administrators_guide/ch-viewing_and_managing_log_files#s1-configuring_rsyslog_on_a_logging_server
# ---------------------------------------------------------------------
template(name=”template_remote_auth” type=”list”) {
  constant(value="/var/log/remote/%HOSTNAME%/auth_%PROGRAMNAME:::secpath-replace%.log”)
}

template(name=”template_remote” type=”list”) {
  constant(value="/var/log/remote/%HOSTNAME%/%PROGRAMNAME:::secpath-replace%.log”)
}

module(load="imtcp")
ruleset(name="ruleset_remote"){
  authpriv.*  action(type="omfile" DynaFile="template_remote_autb")
  *.info;authpriv.none action(type="omfile" DynaFile="template_remote")
}
input(type="imtcp" port="514" ruleset="ruleset_remote")
```
```bash
# Configure logrotate so that logs don't take too much space.
# This config means compress `daily` and keep `365` copies of it,
# so there will be 365 days worth of logs, and the oldest ones will
# start to get deleted once 366th day is reached.
sudo vim /etc/logrotate.d/nsustain
```
```
/var/log/nsustain/*.log {
    daily
    rotate 365
    copytruncate
    compress
    delaycompress
    notifempty
    missingok
}
```
```bash
# Configure Stunnel to encrypt all incoming logs with SSL/TLS.
# Source:
#   https://www.stunnel.org/static/stunnel.html
sudo apt install -y stunnel
sudo vim /etc/stunnel/stunnel.conf
```
```
; It is recommended to drop root privileges if stunnel is started by root
;setuid = stunnel4
;setgid = stunnel4

; Debugging stuff (may be useful for troubleshooting)
;foreground = yes
;debug = info
;output = /var/log/stunnel.log

[rsyslog]
cert=/etc/stunnel/logging_server_public_key.pem
key=/etc/stunnel/logging_server_private_key.pem
sslVersionMin=TLSv1.3
accept=6514
connect=127.0.0.1:514
client=no
```
```bash
# Generate a self-signed certificate for the logging server.
cd /etc/stunnel
sudo openssl req -nodes -x509 -newkey rsa:4096 -keyout logging_server_private_key.pem -out logging_server_public_key.pem -sha256 -days 36500 -subj "/C=US/ST=South Dakota/L=Sioux Falls/O=Nsustain/OU=Devs/CN=nsustain.com"

# Add a systemd entry for Stunnel.
# Source:
#   http://kb.ictbanking.net/article.php?id=704
sudo vim /usr/lib/systemd/system/stunnel.service
```
```
[Unit]
Description=TLS tunnel for network daemons
After=syslog.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/stunnel /etc/stunnel/stunnel.conf
ExecStop=/bin/kill -9 $(pgrep stunnel)

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl enable stunnel
sudo systemctl start stunnel
sudo systemctl status stunnel
sudo systemctl restart rsyslog

# By the way, `sudo service rsyslog restart` works perfectly fine as
# well. `service` = more high level abstraction than `systemctl`.

# -------------------------------------------------------------------
# 5. [Application Server] Configure SSL/TLS encrypted logging.
# -------------------------------------------------------------------
sudo systemctl start rsyslog
sudo systemctl enable rsyslog

# Change the Docker's default logging driver from json to syslog.
sudo vim /etc/docker/daemon.json
```
```
{
  "log-driver": "syslog",
  "log-opts": {
    "syslog-address": "unixgram:///dev/log",
    "tag" : "docker/{{.Name}}"
  }
}
```
```bash
# Restart docker.
cd ~/deploy-nsustain.com
docker compose down
sudo service docker restart
docker compose up -d

# Confirm Docker's logging driver is correctly configured to syslog.
docker inspect <containerName> | grep -A 5 LogConfig

# How to check if rsyslog server is listening.
echo "This is a test log message." | nc <server_ip> <port>

# Append to the end of rsyslog config file.
# Source:
#   https://www.rsyslog.com/sending-messages-to-a-remote-syslog-server/
sudo vim /etc/rsyslog.conf
```
```
# "rsyslog keeps messages in memory if the remote server is not reachable.
# A file on disk is created only if rsyslog runs out of the configured memory queue space or needs to shut down."
# Source:
#   https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/system_administrators_guide/ch-viewing_and_managing_log_files#s2-defining_queues
*.*  action(type="omfwd" target="127.0.0.1" port="514" protocol="tcp"
  queue.type="linkedList"
  queue.filename=”queue_disk_backup”
  queue.saveonshutdown="on"
  action.resumeRetryCount="-1"
  queue.size="10000")
```
```bash

# Configure logs to be sent to the centralized server with TLS 1.3
# Source:
#   https://www.rsyslog.com/doc/historical/stunnel.html
sudo apt install -y stunnel
sudo vim /etc/stunnel/stunnel.conf
```
```
[rsyslog]
sslVersionMin=TLSv1.3
accept  = 127.0.0.1:514
connect = <Logging server IP>:6514
client=yes
```
```bash
# Add a systemd entry for Stunnel.
sudo vim /usr/lib/systemd/system/stunnel.service
```
```
[Unit]
Description=TLS tunnel for network daemons
After=syslog.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/stunnel /etc/stunnel/stunnel.conf
ExecStop=/bin/kill -9 $(pgrep stunnel)

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl enable stunnel
sudo systemctl start stunnel
sudo systemctl status stunnel
sudo systemctl restart rsyslog

# ---------------------------------------------------------------------
# 6. [Application Server] Run Docker Compose to deploy Nsustain.
# ---------------------------------------------------------------------
git clone https://github.com/soobinrho/deploy-nsustain.com.git
cd deploy-nsustain.com
docker compose build
docker compose up -d

# Issue a SSL/TLS certificate using Letsencrypt.
./certbot_runner.sh

# Set up a cron job for certbot renewal.
# This cron job is set to run every day. The `certbot` is smart enough
# to only renew the certificate when it is about to expire.
# Source:
#   https://stackoverflow.com/a/66638930
sudo ln -s /home/soobinrho/deploy-nsustain.com/certbot_runner.sh /etc/cron.daily/certbot_runner.sh

# ---------------------------------------------------------------------
# 7. Useful workflows.
# ---------------------------------------------------------------------
# How to kill Stunnel for debugging purposes.
sudo kill $(pgrep stunnel)

# How to get your public IP address.
curl https://ipinfo.io/ip

# How to see which process is listening on port 80.
sudo netstat -pna | grep 80

# Install lnav: the logfile navigator.
sudo snap install -y lnav

# How to view /etc/var/syslog in pretty format.
sudo lnav
```

<br>

## Extra Readings

### What are network protocols?

https://www.cloudflare.com/learning/network-layer/what-is-a-protocol/

"The Internet Protocol (IP) is responsible for routing data by indicating where data packets come from and what their destination is.
IP makes network-to-network communications possible.
Hence, IP is considered a network layer (layer 3) protocol."

"As another example, the Transmission Control Protocol (TCP) ensures that the transportation of packets of data across networks goes smoothly.
Therefore, TCP is considered a transport layer (layer 4) protocol ...
TCP is a transport layer protocol that ensures reliable data delivery.
TCP is meant to be used with IP, and the two protocols are often referenced together as TCP/IP."

"The Hypertext Transfer Protocol (HTTP) is the foundation of the World Wide Web, the Internet that most users interact with. It is used for transferring data between devices. HTTP belongs to the application layer (layer 7), because it puts data into a format that applications (e.g. a browser) can use directly, without further interpretation." HTTPS (HTTP Secure) is basically SSL/TLS on top of HTTP.

<br>

### What is Transport Layer Security (TLS)?

https://www.cloudflare.com/learning/ssl/transport-layer-security-tls/

Secure Sockets Layer (SSL) was invented in 1995 by Netscape, and was suceeded by TLS in 1999 by the Internet Engineering Task Force (IETF).
Websites that use the Hypertext transfer protocol secure (HTTPS) protocol are using TLS/SSL under the hood.
"HTTPS is an implementation of TLS encryption on top of the HTTP protocol."
The term SSL and TLS are used interchangeably, and in fact, TLS 1.0 was initially just SSL 3.1, but the name was changed to signify the change of ownership from Netscape to IETF in 1999.

SSL/TLS encrypts the data it transmits.
Moreover, "SSL initiates an authentication process called a handshake between two communicating devices to ensure that both devices are really who they claim to be.
SSL also digitally signs data in order to provide data integrity, verifying that the data is not tampered with before reaching its intended recipient."

"TLS handskaes occur after a TCP connection has been opened via a TCP handshake."
First, TLS handshake determines which TLS version is used (TLS 1.0 released in 1999, TLS 1.1 in 2006, TLS 1.2 in 2008 , TLS 1.3 in 2018) and which cipher suits are used.
TLS 1.3 by the way no longer uses the insecure RSA algorithm and instead implements more secure cipher suits (algorithms the protocol uses for encryption keys and session keys); also, TLS 1.3 simplified its handshaking steps, so it performs faster than earlier versions.
Then, the client "authenticates the identity of the server ... via the SSL certificate authroity's digital signature," and the server's public key, which is included in its TLS certificate.
The client encrypts a random string using the server's public key.
The server would be able to decrypt the random encrypted string only if the server actually has the private key to the public key previously provided.

<br>

### What is Cloudflare Tunnel?

https://www.cloudflare.com/products/tunnel/

"The Tunnel daemon [cloudflared] creates an encrypted tunnel between your origin web server and Cloudflare’s nearest data center, all without opening any public inbound ports."
Then, all requests to the origin web server is handled through the Cloudflare data center, which means the identity of the origin web server or even its IP address is hidden and therefore shielded from DDoS attacks, brute force login attacks, and so on.

<br>

### What is network tunneling?

https://www.cloudflare.com/learning/network-layer/what-is-tunneling/

"Tunneling works by encapsulating packets: wrapping packets inside of other packets.
(Packets are small pieces of data that can be re-assembled at their destination into a larger file.)
Tunneling is often used in virtual private networks (VPNs). It can also set up efficient and secure connections between networks."

"Many VPNs use the IPsec protocol suite.
IPsec is a group of protocols that run directly on top of IP at the network layer.
Network traffic in an IPsec tunnel is fully encrypted, but it is decrypted once it reaches either the network or the user device ... 
Another protocol in common use for VPNs is Transport Layer Security (TLS)."

<br>

### How does logging work in Linux?

https://www.loggly.com/ultimate-guide/linux-logging-basics/

"The syslog service receives and processes syslog messages and listens for events by creating a socket located at /dev/log, which applications can write to.
It can write messages to a local file or forward messages to a remote server.
There are different syslog implementations, including rsyslogd and syslog-ng."

"A syslog message is any log formatted in the syslog message format...
The Syslog protocol (RFC 5424) is a transport protocol specifying how to transmit logs over a network...
It uses port 514 for plaintext messages and port 6514 for encrypted messages."

"While RFC 5424 is the current Syslog protocol, it’s not the only standard you’ll see in the wild.
RFC 3164 (a.k.a. “BSD syslog” or “old syslog”) is an older syslog format still used by many devices...
Good indicators of an RFC 3164 syslog message are the absence of structured data and timestamps using an 'Mmm dd hh:mm:ss' format."

<br>

### How to view Linux logs

https://www.digitalocean.com/community/tutorials/how-to-view-and-configure-linux-logs-on-ubuntu-debian-and-centos

```bash
# See who is logged in.
who

# See who logged in last.
last

# See when was a certain command last executed.
last reboot

# See last login time of each user.
lastlog
```

<br>

### `rsyslog.conf` basics

https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/system_administrators_guide/ch-viewing_and_managing_log_files#s1-logfiles-locating

https://www.rsyslog.com/doc/configuration/properties.html

`syslog` requires all processes submitting logs to "provide two pieces of classification information with it."

`FACILITY.PRIORITY`. Example: `auth.* /var/log/auth.log`

```
# Facilities
# Source:
#   https://www.gnu.org/software/libc/manual/html_node/syslog_003b-vsyslog.html
user (user programs)
mail
daemon
auth (security authorizations)
syslog
lpr (printer)
news (network news)
uucp (Unix-to-Unix Copy)
cron
authpriv (private security authorization)
ftp
local{0..7} (logs reserved for local use)

# Priorities
0. emerg (System is unusable)
1. alert (Action must be taken immediately)
2. crit (Critical condition)
3. err (Error)
4. warn (Warning)
5. notice (Normal but important event)
6. info (Purely informational)
7. debug (Only for debugging purposes)
```

In `rsyslog.conf`, the first part of an instruction consists of a selector and an action -- e.g. `kern.*` or `kern.warn`.

The logging system will log priorities that are equal or higher priority.
For example, `kern.crit` will log `crit`, `alert`, and `emerg`.
The output path can be directed to the standard output on the console (`dev/console`).
The output can also be directed to a remote host (`@HOST:PORT` for UDP and `@@HOST:PORT` for TCP).
Use `stop` to discard logs (`local5.* stop`).
For multiple actions, use a newline amd `&`.

```
# Example
auth.* @@123.123.123.123:514
& /var/log/auth.log
```

We can also use an `*` to define all facilities or all priorities, and use `!` to denote not.
For example, `cron.!alert,!crit,!err,!warn,!notice,!info,!debug` is effectively the same as `cron.emerg`.
We call this facility/priority-based filtering.

Another way of filtering is property-based filtering.

`:PROPERTY, [!]COMPARE_OPERATION, "STRING"`. Example: `:msg, contains, "hello world"`, `:msg, !regex, "fetal .* error"`

```
# Properties
syslogseverity-text
syslogfacility-text
timegenerated
hostname
syslogtag
msg
programname (parsed by the syslog syntax)
inputname (The module that produced the log; for example, `imtcp` for remote logs and `rsyslogd` for internally-produced logs)

# Compare Operations
startswith
startswith_i (case insensitive)
contains
contains_i (case insensitive)
isequal
isempty
regex
ereregex (Extended Regular Expression)
```

The last filtering method is expression-based filtering.

`if EXPRESSION then ACTION else ACTION`. Example: `if $msg contains_i "nsustain docker" and $inputname == "imtcp then action(type="omfile" file="/var/log/nsustain/docker.log")`

"With expression-based filters, you can nest the conditions by using a script enclosed in curly braces...
The script allows you to use facility/priority-based filters inside the expression.
On the other hand, property-based filters are not recommended here.

We can use templates as such:

```
template(name=”exampleTemplate” type=”list”) {
  constant(value=”/var/log/example/”)
  property(name=”programname” lowercase="on")
  property(name="hostname" uppercase="on")
  constant(value”.log”)
}

*.* ?authTemplate
```

We can use rulesets as such:

```
# `secpath-replace' is secure path generation replacing `/` with `_`.
ruleset(name="remote_nsustain") {
  auth.* action(type="omfile" file="/var/log/nsustain/%programname:::secpath-replace%.log")
}

# omfile here means output module (file).
ruleset(name="remote_test") {
  cron.* action(type="omfile" file="/var/log/remote_test/cron.log")
}

# imtcp here means input module (tcp).
input(type="imtcp" port="514" ruleset="remote_nsustain");
input(type="imtcp" port="6514" ruleset="remote_test");
```

All rules are evaulated for all logs received until the end of all rules defined or until the log is discarded with `stop`, but using a ruleset allows you to "enhance the performance of rsyslog by defining a distinct set of actions bound to a specific input.
In other words, filter conditions that will be inevitably evaluated as false for certain types of messages can be skipped."
I prefer using a ruleset over using if statements for remote logs because its syntax is more pleasing to my eyes.

<br>

### `logrotate`

https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/system_administrators_guide/ch-viewing_and_managing_log_files#s2-log_rotation

`/etc/logrotate.conf` applies to all log files, and if you create a config for a specific log file such as `/etc/logrotate.d/example`, you can override it.

<br>

### What is `/dev/log`?

https://askubuntu.com/a/1510580

"`systemd` centralizes all log streams in the Journal daemon.
Messages coming in via `/dev/log`, via the native protocol, via STDOUT/STDERR of all services and via the kernel are received in the journal daemon.
The journal daemon then stores them to disk or in RAM (depending on the configuration of the Storage= option in journald.conf), and optionally forwards them to the console, the kernel log buffer, or to a classic BSD syslog daemon."

<br>

### Why `journalctl`?

https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/system_administrators_guide/ch-viewing_and_managing_log_files#s1-basic_configuration_of_rsyslog

While I use `rsyslog` for storing and relaying logs to my centralized logging server, "the `journald` daemon is the primary tool for troubleshooting," and "the native journal file format, which is a structured and indexed binary file, improves searching and provides faster operation."

> [!warning]
> I use `journald` strictly when I'm SSH'ing to my application server because `journald` data is not persistent.
> `rsyslog` is in charge of storing all logs in files, while "the journal data is stored in memory and lost between reboots."
> Since the logging server is receiving the logs remotely from the application server, the logging server's `journald` won't show you the logs.
> Instead, use `vim` to see the `rsyslog` log files directly at `/var/log/remote`.
>
> Source:
>   https://gist.github.com/JPvRiel/b7c185833da32631fa6ce65b40836887

"Logging data is collected, stored, and processed by the Journal’s journald service.
It creates and maintains binary files called journals based on logging information that is received from the kernel, from user processes, from standard output, and standard error output of system services or via its native API...
The actual journal files are secured, and therefore cannot be manually edited."

```bash
# How to see all logs.
journalctl

# How to view logs real time.
# You can use -f with other filters as well (listed below).
journalctl -f

# How to view logs from the current boot.
journalctl -b

# How to filter by priority (equal or greater).
journalctl -p err

# How to filter by time.
journalctl --since="2024-9-16 23:59:59"

# How to filter by a specific field.
journalctl <field name>=<field value>

# Same as above but logical AND.
journalctl <...>=<...> <...>=<...>

# Same as above but logical OR.
journalctl <...>=<...> + <...>=<...>

# How to see all possible options of a field, press <tab> twice or enter this.
journalctl -F <field name>
```

"Lines of error priority and higher are highlighted with red color and a bold font is used for lines with notice and warning priority...
The time stamps are converted for the local time zone of your system...
All logged data is shown, including rotated logs."

<br>
