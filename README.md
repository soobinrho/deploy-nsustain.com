# Nsustain.com Deployment

<br>

> Nsustain is a group of volunteer programmers who love the e[N]vironment and [sustain]ability.
> We write code for whoever needs our code (researchers, farmers, doctors, etc) as long as their work is realted to the environmental sustainability.

<br>

## Applications

| ***Web Apps Deployed*** |
| ---------- |
| https://nsustain.com |
| https://BeeMovr.nsustain.com |
| https://GoodLifeFarms.nsustain.com |

<br>

## Infrastructure

| ***Program*** | ***Purpose*** |
| ---- | ---- |
| ***Hetzner*** | One of the best VPS service providers in the world. Hosts both of my application server and logging server. I like it because it's affordable and pleasant to use (creating new servers, applying firewalls, etc). $8 per month for my application server. $4 per month for my logging server.  |
| ***rsyslog*** | "Rocket-fast System for Log Processing." Aggregates all my `auth.log`, other system logs, and Docker container logs. Relays them to my central logging server, which is soley used for logging purposes with no other exposed services. This way, we can ensure the integrity of the logs even if my application server gets compromised due to zero-day vulnerabilities. |
| ***Stunnel*** | Listens to localhost TCP port `514` for `rsyslog` and tunnels all the logs to the central logging server via TCP port `6514` with SSL/TLS protocol. Although `rsyslog` supports SSL/TLS out of the box, it's only single-threaded.<sup>[1]</sup> So, I use the TCP protocol in `rsyslog`, which has great support for multithreading, and use `Stunnel` to implement the SSl/TCP protocol for encryption. |
| ***Tarsnap*** | One of the most, if not the most, secure backup services. `tarsnap -c -v -f "$(uname -n)-$(date +%Y-%m-%d_%H-%M-%S)" /var/lib/docker/volumes` deduplicates, compresses, and encrypts the data to their AWS backup server. I use `Tarsnap` for scheduled backups with `cron`. $0.25 per GB per month of storage. $0.25 per GB of bandwith. Less than $1 per month total. |

<sub>[1] https://coders-home.de/en/set-up-an-rsyslog-server-with-multithreaded-tls-encryption-using-stunnel-1245.html</sub>

<br>

> [!NOTE]  
> `rsyslog` is a plaintext logging system,<sup>[2]</sup> while `journald` is a binary logging system.
> `journald` and `rsyslog` complement each other.
> While `rsyslog` is especially good at storing and relaying logs to a centralized logging server, `journald` is great at viewing and filtering logs for analysis.
> I normally use `sudo lnav /var/log` to view logs from `rsyslog` for almost all tasks related to logs, but use `sudo journalctl -f <field name>=<field value>` for when I need to use filters.

<sub>[2] https://datatracker.ietf.org/doc/html/rfc5424</sub>

<br>

## Deployment Code

```
Application Server - 3 vCPU, 4GB RAM, 80GB SSD. Ubuntu LTS
Monitoring Server - 2 vCPU, 2GB RAM, 40GB SSD. Ubuntu LTS
```

<br>

### 1. [Both] Add a non-root user and configure `sshd` for security.

```bash
# Enable auto updates so that security patches are installed promptly.
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Set timezone so that log times match with each other.
 sudo timedatectl set-timezone "America/Chicago"

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

# "All Diffie-Hellman moduli in use should be at least 3072-bit-long."
# Source:
#   https://infosec.mozilla.org/guidelines/openssh#modern-openssh-67
sudo awk '$5 >= 3071' /etc/ssh/moduli > ~/moduli.tmp && sudo mv ~/moduli.tmp /etc/ssh/moduli

# Test ssh connection to the new user.
# Then, make sure sshd is securely configured.
sudo mv /etc/ssh/sshd_confg /etc/ssh/sshd_config.backup
sudo vim /etc/ssh/sshd_config
```

Copy and paste to `/etc/ssh/ssd_config`.

```
# Name: K4YT3X Hardened OpenSSH Configuration
# Author: K4YT3X
# Contributor: IceCodeNew
# Contributor: brxken128
# Contributor: CookieCr2nk
# Date Created: October 5, 2020
# Last Updated: May 6, 2024

# Licensed under the GNU General Public License Version 3 (GNU GPL v3),
#   available at: https://www.gnu.org/licenses/gpl-3.0.txt
# (C) 2020-2024 K4YT3X

########## Features ##########

# accept locale-related environment variables
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS

# disallow ssh-agent forwarding to prevent lateral movement
AllowAgentForwarding no

# prevent TCP ports from being forwarded over SSH tunnels
# **please be aware that disabling TCP forwarding does not prevent port forwarding**
# any user with an interactive login shell can spin up his/her own instance of sshd
AllowTcpForwarding no

# prevent StreamLocal (Unix-domain socket) forwarding
AllowStreamLocalForwarding no

# disables all forwarding features
# overrides all other forwarding switches
DisableForwarding yes

# disallow remote hosts from connecting to forwarded ports
# i.e. forwarded ports are forced to bind to 127.0.0.1 instead of 0.0.0.0
GatewayPorts no

# prevent tun device forwarding
PermitTunnel no

# suppress MOTD
PrintMotd no

# disable X11 forwarding since it is not necessary
X11Forwarding no

########## Authentication ##########

# permit only the specified users to login
#AllowUsers k4yt3x

# permit only users within the specified groups to login
#AllowGroups k4yt3x

# uncomment the following options to permit only pubkey authentication
# be aware that this will disable password authentication
#   - AuthenticationMethods: permitted authentication methods
#   - PasswordAuthentication: set to no to disable password authentication
#   - UsePAM: set to no to disable all PAM authentication, also disables PasswordAuthentication when set to no
AuthenticationMethods publickey
PasswordAuthentication no
UsePAM no

# PAM authentication enabled to make password authentication available
# remove this if password authentication is not needed
#UsePAM yes

# challenge-response authentication backend it not configured by default
# therefore, it is set to "no" by default to avoid the use of an unconfigured backend
ChallengeResponseAuthentication no

# set maximum authentication retries to prevent brute force attacks
MaxAuthTries 3

# disallow connecting using empty passwords
PermitEmptyPasswords no

# prevent root from being logged in via SSH
PermitRootLogin no

# enable pubkey authentication
PubkeyAuthentication yes

########## Cryptography ##########

# explicitly define cryptography algorithms to avoid the use of weak algorithms
# AES-CTR and Chacha20-Poly1305 modes have been removed to mitigate the Terrapin attack
#   https://terrapin-attack.com/
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com
HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256,ssh-ed25519
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# only use host keys with secure HostKeyAlgorithms
# omit the ECDSA key since it is only used in conjunction with the NIST P-curves
HostKey /etc/ssh/ssh_host_ed25519_key
#HostKey /etc/ssh/ssh_host_rsa_key

# short moduli should be deactivated before enabling the use of diffie-hellman-group-exchange-sha256
#   see this link for more details: https://github.com/k4yt3x/sshd_config#deactivating-short-diffie-hellman-moduli
# AES-CTR and Chacha20-Poly1305 modes have been removed to mitigate the Terrapin attack
#   https://terrapin-attack.com/
# ecdh-sha2-nistp* algorithms have been removed due to concerns around NIST P-curves' design
#   https://github.com/jtesta/ssh-audit/issues/213#issuecomment-1774204745
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512

########## Connection Preferences ##########

# number of client alive messages sent without client responding
ClientAliveCountMax 2

# send a keepalive message to the client when the session has been idle for 300 seconds
# this prevents/detects connection timeouts
ClientAliveInterval 300

# compression before encryption might cause security issues
Compression no

# prevent SSH trust relationships from allowing lateral movements
IgnoreRhosts yes

# log verbosely for additional information
LogLevel VERBOSE

# allow a maximum of two multiplexed sessions over a single TCP connection
MaxSessions 2

# enforce SSH server to only use SSH protocol version 2
# SSHv1 contains security issues and should be avoided at all costs
# SSHv1 is disabled by default after OpenSSH 7.0, but this option is
#   specified anyways to ensure this configuration file's compatibility
#   with older versions of OpenSSH server
Protocol 2

# let ClientAliveInterval handle keepalive
TCPKeepAlive no

# disable reverse DNS lookups
UseDNS no

# Log sftp level file access (read/write/etc.) that would not be easily logged otherwise.
# Source:
#   https://infosec.mozilla.org/guidelines/openssh#modern-openssh-67
Subsystem sftp  /usr/lib/ssh/sftp-server -f AUTHPRIV -l INFO
```
```bash
# Restart SSH
sudo service ssh restart
```

<br>

### 2. [Application Server] Configure firewall.

```bash
# Allow inbound traffic with port 443 TCP/UDP (Cloudflare Tunnel)
# Allow inbound traffic with port 80  TCP/UDP (Cloudflare Tunnel)
# Allow inbound traffic with port 22  TCP/UDP from your IP address (ssh)
sudo ufw reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 443
sudo ufw allow 80
sudo ufw allow 22
sudo ufw enable

# Confirm current firewall rules.
sudo ufw status

# FYI, whenever a service has a designated port, it almost always uses
# just one of TCP or UDP, but it's customary to accept both TCP and UDP
# as future reserve in case of implementation changes in the program.

# Apply the same firewall rules on Hetzner's firewall settings as
# an extra layer of security.
```

<br>

### 3. [Application Server] Configure Cloudflare Firewall.

I noticed when I was looking at `sudo lnav /var/log/remote/nsustain/docker.log` that there are too many http attempts from botnets requesting for URL's that match known vulnerabilities.
To drop these requests entirely, go to Cloudflare - Security - WAF (Web Application Firewall) - Custom Rules.
Add the following two rules:

1. `Allowlist`

```
(http.request.uri.path eq "/") or (http.request.uri.path wildcard r"/*.jpg") or (http.request.uri.path wildcard r"/*.jpeg") or (http.request.uri.path wildcard r"/*.png") or (http.request.uri.path wildcard r"/*.svg") or (http.request.uri.path wildcard r"/api/*") or (http.request.uri.path wildcard r"/auth/*") or (http.request.uri.path wildcard r"/assets/*") or (http.request.uri.path wildcard r"/d/*") or (http.request.uri.path eq "/tags") or (http.request.uri.path wildcard r"/t/*") or (http.request.uri.path wildcard r"/u/*") or (http.request.uri.path eq "/settings") or (http.request.uri.path eq "/admin") or (http.request.uri.path wildcard r"/t/*") or (http.request.uri.path wildcard r"/cdn-cgi/*") or (http.request.uri.path wildcard r"/_next/*") or (http.request.uri.path eq "/list") or (http.request.uri.path wildcard r"/list/*") or (http.request.uri.path wildcard r"/*.txt") or (http.request.uri.path wildcard r"/*.ico") or (http.request.uri.path wildcard r"/*.xml") or (http.request.uri.path wildcard r"/*.json") or (http.request.uri.path wildcard r"/p/*") or (http.request.uri.path eq "/logout") or (http.request.uri.path wildcard r"/.well-known/*")
```

```
Choose action: Skip
Place at: First
```

2. `Block All Except Allowlist`

```
(http.request.full_uri wildcard r"*")
```

```
Choose action: Block
Place at: Custom
Select which rule this will fire after: Allowlist
```

Now, all requests to non-existent URL paths will be dropped and therefore the log files will not be flooded with requests from botnets anymore.
All requests to the allowlist will pass through as expected.
If new URL paths need to be added, add the new URL path to `Allowlist` and use Chrome developer tool (F12, Network) to confirm all resources are coming through.

<br>

### 4. [Logging Server] Configure firewall.

```bash
# Allow inbound traffic with port 6514 TCP/UDP (rsyslog & Stunnel TLS)
# Allow inbound traffic with port 22   TCP/UDP from your IP address (ssh)
sudo ufw reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from <application server IP> to any port 6514
sudo ufw allow 22
sudo ufw enable

# Confirm current firewall rules.
sudo ufw status

# Apply the same firewall rules on Hetzner's firewall settings as
# an extra layer of security.
```

<br>

### 5. [Logging Server] Configure SSL/TLS encrypted logging.

```bash
sudo systemctl start rsyslog
sudo systemctl enable rsyslog

# Configure rsyslog to receive remote logs.
# Source:
#   https://www.rsyslog.com/receiving-messages-from-a-remote-system/
sudo mv /etc/syslog.conf /etc/syslog.conf.backup
sudo vim /etc/rsyslog.conf
```

Copy and paste this to `/etc/rsyslog.conf`.

```
# ---------------------------------------------------------------------
# Default rules that come installed with `rsyslog`.
# ---------------------------------------------------------------------
# /etc/rsyslog.conf configuration file for rsyslog
#
# For more information install rsyslog-doc and see
# /usr/share/doc/rsyslog-doc/html/configuration/index.html

# provides support for local system logging
module(load="imuxsock") 

# provides kernel logging support and enable non-kernel klog messages
module(load="imklog" permitnonkernelfacility="on")

# Filter duplicated messages
$RepeatedMsgReduction on

# Set the default permissions for all log files.
$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022
$PrivDropToUser syslog
$PrivDropToGroup syslog

# Where to place spool and state files
$WorkDirectory /var/spool/rsyslog

# ---------------------------------------------------------------------
# Configure rsyslog to listen and receive remote logs.
# Source
#   https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/system_administrators_guide/ch-viewing_and_managing_log_files#s1-configuring_rsyslog_on_a_logging_server
# ---------------------------------------------------------------------
template(name="template_remote_auth" type="list") {
  constant(value="/var/log/remote/")
  property(name="hostname" SecurePath="replace")
  constant(value="/auth.log")
}

template(name="template_remote" type="list") {
  constant(value="/var/log/remote/")
  property(name="hostname" SecurePath="replace")
  constant(value="/")
  property(name="programname" SecurePath="replace")
  constant(value=".log")
}

# This ruleset applies to all remote logs.
ruleset(name="ruleset_remote") {
  # Save all `auth` logs separately so that it's easy to view them.
  authpriv.*;auth.* action(type="omfile" DynaFile="template_remote_auth")
  & stop

  # Every log with a priority of `info` or greater, except for `auth`.
  *.info;authpriv.none;auth.none action(type="omfile" DynaFile="template_remote")
  & stop
}

module(load="imtcp")
input(type="imtcp" port="514" ruleset="ruleset_remote")

# ---------------------------------------------------------------------
# Configure rules for local logs.
# ---------------------------------------------------------------------
template(name="template_local_auth" type="list") {
  constant(value="/var/log/auth.log")
}

template(name="template_local" type="list") {
  constant(value="/var/log/")
  property(name="programname" SecurePath="replace")
  constant(value=".log")
}

# Save all `auth` logs separately so that it's easy to view them.
authpriv.*;auth.* action(type="omfile" DynaFile="template_local_auth")
& stop

# Every log with a priority of `info` or greater, except for `auth`.
*.info;authpriv.none;auth.none action(type="omfile" DynaFile="template_local")
& stop

# You can test `rsyslog` config files with `rsyslogd -N1` command.
```
```bash
# Configure Stunnel to encrypt all incoming logs with SSL/TLS.
# Source:
#   https://www.stunnel.org/static/stunnel.html
sudo apt install -y stunnel
sudo vim /etc/stunnel/stunnel.conf
```

Copy and paste to `/etc/stunnel/stunnel.conf`.

```
; chroot for security enhancement.
; Source:
;   https://stunnel-users.mirt.narkive.com/G6ONH6Wr/stunnel-in-client-server-configuration
chroot = /var/lib/stunnel4

; It is recommended to drop root privileges if stunnel is started by root
setuid=stunnel4
setgid=stunnel4

; PID is created inside chroot jail
pid = /stunnel.pid

; Debugging stuff (may be useful for troubleshooting)
;foreground=yes
;debug=info
;output=/var/log/stunnel.log

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

Copy and paste to `/usr/lib/systemd/system/stunnel.service`.

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
```

<br>

### 6. [Application Server] Configure SSL/TLS encrypted logging.

```bash
sudo systemctl start rsyslog
sudo systemctl enable rsyslog

# Change the Docker's default logging driver from json to syslog.
sudo vim /etc/docker/daemon.json
```

Copy and paste to `/etc/docker/daemon.json`.

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

# If it exits with an error saying that there's no volume,
# go to `deploy-nsustain.com/compose.yaml` and change all
# `external: true` to `external:false`.

# Confirm Docker's logging driver is correctly configured to syslog.
docker inspect <containerName> | grep -A 5 LogConfig

# How to check if rsyslog server is listening.
echo "This is a test log message." | nc <server_ip> <port>

# Configure rsyslog to relay all log messages to the centralized
# logging server.
# Source:
#   https://www.rsyslog.com/sending-messages-to-a-remote-syslog-server/
sudo mv /etc/rsyslog.conf /etc/rsyslog.conf.backup
sudo vim /etc/rsyslog.conf
```

Copy and paste to `/etc/rsyslog.conf`.

```
# ---------------------------------------------------------------------
# Default rules that come installed with `rsyslog`.
# ---------------------------------------------------------------------
# /etc/rsyslog.conf configuration file for rsyslog
#
# For more information install rsyslog-doc and see
# /usr/share/doc/rsyslog-doc/html/configuration/index.html

# provides support for local system logging
module(load="imuxsock") 

# provides kernel logging support and enable non-kernel klog messages
module(load="imklog" permitnonkernelfacility="on")

# Filter duplicated messages
$RepeatedMsgReduction on

# Set the default permissions for all log files.
$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022
$PrivDropToUser syslog
$PrivDropToGroup syslog

# Where to place spool and state files
$WorkDirectory /var/spool/rsyslog

# ---------------------------------------------------------------------
# Configure rsyslog to send all logs to the remote logging server.
# Source
#   https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/system_administrators_guide/ch-viewing_and_managing_log_files#s1-configuring_rsyslog_on_a_logging_server
# ---------------------------------------------------------------------
# "rsyslog keeps messages in memory if the remote server is not reachable.
# A file on disk is created only if rsyslog runs out of the configured memory queue space or needs to shut down."
# Source:
#   https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/system_administrators_guide/ch-viewing_and_managing_log_files#s2-defining_queues
*.* action(
  type="omfwd"
  target="127.0.0.1"
  port="514"
  protocol="tcp"
  queue.type="linkedList"
  queue.filename="queue_disk_backup"
  queue.saveonshutdown="on"
  action.resumeRetryCount="-1"
  queue.size="10000"
)

# You can test `rsyslog` config files with `rsyslogd -N1` command.
```
```bash
# Configure logs to be sent to the centralized server with TLS 1.3
# Source:
#   https://www.rsyslog.com/doc/historical/stunnel.html
sudo apt install -y stunnel
sudo vim /etc/stunnel/stunnel.conf
```

Copy and paste to `/etc/stunnel/stunnel.conf`.

```
; chroot for security enhancement.
; Source:
;   https://stunnel-users.mirt.narkive.com/G6ONH6Wr/stunnel-in-client-server-configuration
chroot = /var/lib/stunnel4

; It is recommended to drop root privileges if stunnel is started by root
setuid=stunnel4
setgid=stunnel4

; PID is created inside chroot jail
pid = /stunnel.pid

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

Copy and paste to `/usr/lib/systemd/system/stunnel.service`.

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
```

<br>

### 7. [Logging Server] Configure `logrotate`.

```bash
cd /etc/logrotate.d

# This config means rotate `monthly` and keep `12` copies of it.
# There will be 365 days worth of logs, and the oldest ones will
# start to get deleted once 366th day is reached.
sudo vim remote
```

Copy and paste this to `/etc/logrotate.d/all`.

```
# see "man logrotate" for detail

/var/log/remote/*/*.log {
    monthly
    rotate 12
    copytruncate
    compress
    delaycompress
    notifempty

    # "If the log file is missing, go on to the next one without issuing
    # an error message."
    # Source:
    #   https://access.redhat.com/solutions/646903
    missingok
}
```
<br>

### 8. [Application Server] Run Docker Compose to deploy Nsustain.

```bash
cd ~/
git clone https://github.com/soobinrho/deploy-nsustain.com.git
cd deploy-nsustain.com
docker compose build
docker compose up -d

# Issue a SSL/TLS certificate using Letsencrypt.
./cron/certbot_runner

# Set up a cron job for certbot renewal.
# This cron job is set to run every day. The `certbot` is smart enough
# to only renew the certificate when it is about to expire.
# Source:
#   https://stackoverflow.com/a/66638930
sudo ln -s /home/soobinrho/deploy-nsustain.com/cron/certbot_runner /etc/cron.daily/certbot_runner

# Docker stores various temporary files, such as filesystem layers at
# `/var/lib/docker/overlay2`, and this can grow fast -- e.g. 70GB in a week.
# So, set up a cron job to clean this daily.
sudo ln -s /home/soobinrho/deploy-nsustain.com/cron/docker_prune_temp_files /etc/cron.daily/docker_prune_temp_files
```

<br>

### 9. [Application Server] Configure `tarsnap` for backups.

```bash
# Install `tarsnap` by following the instructions at:
#   https://www.tarsnap.com/pkg-deb.html

# This is the super privilege key. Move this to another device that is
# secured and use it only when you need it to view and/or restore
# the backup archives. This key contains all the read, write, and delete
# privileges. This must not be used unless necessary. This way, even if
# the application server gets compromised, the backups are isolated.
sudo tarsnap-keygen \
  --keyfile /root/tarsnap_all_privileges.key \
  --passphrased \
  --user soobinrho@gmail.com \
  --machine nsustain

# Generate key with only the write privilege. Keep the key in
# the application server. This will be used with `cron` for daily
# automatic backups.
sudo tarsnap-keymgmt -w \
  --outkeyfile /root/tarsnap.key \
  /root/tarsnap_all_privileges.key

# Create a daily cron job compressing the Docker volume files.
# "Don't apply any compression (gzip, bzip2, zip, tar.gz, etc.) to your
# data -- Tarsnap itself will compress data after it performs
# deduplication.
sudo ln -s /home/soobinrho/deploy-nsustain.com/cron/tarsnap_runner /etc/cron.daily/tarsnap_runner

# How to check how much data would be uploaded after deduplication and compression.
sudo tarsnap -c -v -f testbackup --dry-run --print-stats --humanize-numbers /usr/home

# How to see all stored archives.
sudo tarsnap -v --list-archives --keyfile /root/tarsnap_all_privileges.key

# How to restore an archive.
sudo tarsnap -x -v -f ./restored_data --keyfile /root/tarsnap_all_privileges.key

# How to print all global status and of all backed-up archives.
sudo tarsnap --print-stats --humanize-numbers -f '*' --keyfile /root/tarsnap_all_privileges.key
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
> I use `journald` only when I'm SSH'ing to my application server, and use `rsyslog` files in the logging server.
> While `journald` data is not persistent, `rsyslog` stores all logs.
> "The journal data is stored in memory and lost between reboots."
> 
> Since the logging server is receiving the logs remotely from the application server, the logging server's `journald` won't show you the logs.
> Instead, if I'm SSH'ing to the logging server, I would use `lnav` to see the `rsyslog` log files directly at `/var/log/remote`.
> For example, `sudo lnav /var/log/remote/nsustain` shows all logs from my application server.
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

### Why do I use `Tarsnap`?

https://www.tarsnap.com/flexibility.html

"Unlike backup systems (tar included) which work on a 'full plus incrementals' model of backups — that is, you start by creating an archive containing everything, and thereafter you create archives which only contain modified files — Tarsnap works on a snapshotting model: Every Tarsnap archive acts like it is completely independent of all other archives.
(Tarsnap has magic going on behind the scenes to efficiently store archives, so you get the same or better performance than the full-plus-incrementals model provides.)"

"Due to Tarsnap's 'de-duplication' functionality, it uses the same or less storage than a traditional full-plus-incrementals backup system, while still providing the flexibility of allowing archives to be created and deleted independently of each other — and in the case of log files, mail spools, and other large files which have small amounts of data appended to them frequently, Tarsnap uses far less bandwidth and storage than incremental backups, since Tarsnap avoids storing multiple copies of the unchanging segments of files. We have collected a few examples of deduplication efficiency."

"When a system is registered with the Tarsnap service via the tarsnap-keygen utility, all of these keys are generated and stored in a single key file; but using the tarsnap-keymgmt utility, 'restricted' key files can be created which can be used to do any subset of...
the -r (list and extract archives), -w (write archives), [and] -d (delete archives)...
This makes it possible to set up a system to automatically store archives daily (e.g., via a cron job) while not being able to read those archives back or delete them — ensuring that even if someone breaks into the system and does his best to delete everything, your data will still be safe."

<br>

## Useful Commands

```bash
# How to re-deploy whenever there's change to source code.
cd ~/deploy-nsustain.com
docker compose up --build --force-recreate -d

# How to update all git submodules (required for first time).
git submodule update --init --recursive

# How to update all git submodules.
git submodule update --recursive --remote

# How to kill Stunnel for debugging purposes.
sudo kill $(pgrep stunnel)

# How to get your public IP address.
curl https://ipinfo.io/ip

# How to see which process is listening on port 80.
sudo netstat -pna | grep 80

# Install lnav: the logfile navigator.
sudo snap install lnav

# How to read logs. Automatically follows all the log files in
# the selected directory in real time, and it does so with color coding
# and vim key bindings for navigation (hjkl, gg, GG, / for search, etc).
cd /var/log
sudo lnav .

# How to copy files using the SSH protocol.
rsync --recursive --progress nsustain:/home/soobinrho/deploy-nsustain.com/example ./
```

<br>
