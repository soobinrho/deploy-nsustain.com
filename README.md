# Nsustain.com Deployment

<br>

> Nsustain is for anyone who loves the e[N]vironment and [sustain]ability.
> Anyone is welcome to join us if you'd like to volunteer to code for people who work in the field and write something that will have a direct impact.

<br>

## Infrastructure

| ***Program*** | ***Purpose*** |
| ---- | ---- |
| ***Hetzner*** | One of the best VPS service providers in the world; it's affordable and pleasant to use. Both my application server and logging server are hosted here. |
| ***Cloudflare Tunnel*** | A reverse proxy first between my server and Cloudflare's nearest data center and thereafter from any user that wants to connect to my server to the Cloudflare data center. |
| ***rsyslog*** | "Rocket-fast System for Log Processing." I use `rsyslog` for aggregating all log entries (system logs, Docker container logs, etc) in my application server and relaying them to my logging and monitoring server. |
| ***Stunnel*** | "A multiplatform GNU/GPL-licensed proxy encrypting arbitrary TCP connections with SSL/TLS." Although `rsyslog` supports SSL/TLS, it's only single-threaded.<sup>[1]</sup> Using `Stunnel`, all my `rsyslog` transmissions are encrypted and multi-threaded. |
| ***Tarsnap*** | One of the most, if not the most, secure backup service. I use `Tarsnap` for regular backups of my servers. |

<sub>[1] https://coders-home.de/en/set-up-an-rsyslog-server-with-multithreaded-tls-encryption-using-stunnel-1245.html</sub>

<br>

> [!NOTE]  
> To encrypt the network traffic with https, one commonly-used way is to obtain an SSL/TLS certificate from certificate authorities such as Let's Encrypt.
> Here, however, I opted to use Cloudflare Tunnel.
> It has two advantages:
> (a) Ease of use.
> To implement it, I just need to add it to my Docker Compose `compose.yaml`, and configure the rest from the Cloudflare Tunnel dashboard.
> (b) Automatic encryption of all traffic.
> Setting up a Cloudflare Tunnel provides automatic encryption of all web traffic, which to me is a little bit simpler than setting up a SSL/TLS certificate myself and having to configure a new `nginx.conf` for that use case.

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
adduser soobinrho sudo

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
# Allow inbound traffic with port 7844 TCP/UDP (Cloudflare Tunnel)
# Allow inbound traffic with port 443  TCP/UDP (Cloudflare Tunnel)
# Allow inbound traffic with port 22   TCP/UDP from your IP address (ssh)
sudo ufw reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 7844,443/tcp
sudo ufw allow 7844,443/udp
sudo ufw allow from <home ip address> to any port 22
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
sudo ufw allow 6514
sudo ufw allow from <home ip address> to any port 22
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
# ---------------------------------------------------------------------
module(load="imtcp")
input(type="imtcp" port="514")

$template FILENAME,"/var/log/%hostname%/%$YEAR%%$MONTH%%$DAY%_%PROGRAMNAME%.log"
*.* ?FILENAME

if ($msg contains " nsustain ") then { Action (type="omfile" File="/var/log/nsustain/%$YEAR%%$MONTH%$DAY%_noName.log") stop }
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
*.*  action(type="omfwd" target="127.0.0.1" port="514" protocol="tcp"
            action.resumeRetryCount="100"
            queue.type="linkedList" queue.size="10000")
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

# Get Cloudflare Tunnel token by following instructions at:
#   https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/create-remote-tunnel/
cp .env_cloudflared.example .env_cloudflared

# Enter the token from the previous step into `.env_cloudflared`
vim .env_cloudflared

docker compose build
docker compose up -d

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

#### Extra Readings

- What are network protocols? https://www.cloudflare.com/learning/network-layer/what-is-a-protocol/

"The Internet Protocol (IP) is responsible for routing data by indicating where data packets come from and what their destination is.
IP makes network-to-network communications possible.
Hence, IP is considered a network layer (layer 3) protocol."

"As another example, the Transmission Control Protocol (TCP) ensures that the transportation of packets of data across networks goes smoothly.
Therefore, TCP is considered a transport layer (layer 4) protocol ...
TCP is a transport layer protocol that ensures reliable data delivery.
TCP is meant to be used with IP, and the two protocols are often referenced together as TCP/IP."

"The Hypertext Transfer Protocol (HTTP) is the foundation of the World Wide Web, the Internet that most users interact with. It is used for transferring data between devices. HTTP belongs to the application layer (layer 7), because it puts data into a format that applications (e.g. a browser) can use directly, without further interpretation." HTTPS (HTTP Secure) is basically SSL/TLS on top of HTTP.

<br>

- What is Transport Layer Security (TLS)? https://www.cloudflare.com/learning/ssl/transport-layer-security-tls/

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

- What is Cloudflare Tunnel? https://www.cloudflare.com/products/tunnel/

"The Tunnel daemon [cloudflared] creates an encrypted tunnel between your origin web server and Cloudflare’s nearest data center, all without opening any public inbound ports."
Then, all requests to the origin web server is handled through the Cloudflare data center, which means the identity of the origin web server or even its IP address is hidden and therefore shielded from DDoS attacks, brute force login attacks, and so on.

<br>

- What is network tunneling? https://www.cloudflare.com/learning/network-layer/what-is-tunneling/

"Tunneling works by encapsulating packets: wrapping packets inside of other packets.
(Packets are small pieces of data that can be re-assembled at their destination into a larger file.)
Tunneling is often used in virtual private networks (VPNs). It can also set up efficient and secure connections between networks."

"Many VPNs use the IPsec protocol suite.
IPsec is a group of protocols that run directly on top of IP at the network layer.
Network traffic in an IPsec tunnel is fully encrypted, but it is decrypted once it reaches either the network or the user device ... 
Another protocol in common use for VPNs is Transport Layer Security (TLS)."

<br>

- How does logging work in Linux? https://www.loggly.com/ultimate-guide/linux-logging-basics/

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

- How to view Linux logs https://www.digitalocean.com/community/tutorials/how-to-view-and-configure-linux-logs-on-ubuntu-debian-and-centos

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

In `rsyslog.conf`, the first part of an instruction consists of a selector and an action.
The selector - e.g. `kern.*` or `kern.warn` - consists of two parts:

```
# First Part's Possible Values
auth
kern
mail
cron
daemon
news (logs onnetwork news subsystem)
lpr (logs on printing)
user (logs on user programs)
local{0..7} (logs reserved for local use)

# Second part's Possible Values
# The logging system will log priorities that are greater or equal.
debug
info
notice
warn
err
crit
alert
emerg
```

<br>
