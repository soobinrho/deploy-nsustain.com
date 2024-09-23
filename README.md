# Nsustain.com Deployment

<br>

> Nsustain is for anyone who loves the e[N]vironment and [sustain]ability.
> Anyone is welcome to join us if you'd like to volunteer to code for people who work in the field and need our help in solving a problem.

<br>

## Infrastructure

| ***Program*** | ***Purpose*** |
| ---- | ---- |
| ***Hetzner*** | Hetzner is one of the best VPS service providers in the world; it's affordable and pleasant to use. I have two servers -- main applicatoin server with 3 vCPU, 4GB RAM, and 80GB SSD, and `rsyslog` server with 2 vCPU, 2GB RAM, and 40GB SSD. |
| ***Cloudflare Tunnel*** | Cloudflare Tunnel acts as a reverse proxy first between my server and Cloudflare's nearest data center and thereafter from any user that wants to connect to my server to the Cloudflare data center. |
| ***rsyslog*** | "Rocket-fast System for Log Processing." I use this for collecting all my logs in my centralized logging server. |
| ***Tarsnap*** | One of the most, if not the most, secure backup service. I use this for regular backups of my servers. |

> [!NOTE]  
> To encrypt the network traffic with https, one commonly-used way is to obtain an SSL/TLS certificate from certificate authorities such as Let's Encrypt.
> Here, however, I opted to use Cloudflare Tunnel.
> It has two advantages:
> (a) Ease of use.
> To implement it, I just need to add it to my Docker Compose `compose.yaml`, and configure the rest from the Cloudflare Tunnel dashboard.
> (b) Automatic encryption of all traffic.
> Setting up a Cloudflare Tunnel provides automatic encryption of all web traffic, which to me is a little bit simpler than setting up a SSL/TLS certificate myself and having to configure a new `nginx.conf` for that use case.

> [!NOTE]  
> `syslog` is a plaintext logging system,<sup>[1]</sup> while `journald` is a binary
> logging system. `journald` was created more recently, but I chose to
> use `syslog` (rsyslog) because `syslog` is said to be simpler at
> spooling and saving logs to a centralized logging server with TLS/SSL encryption.
> 
> [1] https://datatracker.ietf.org/doc/html/rfc5424

<br>

## Applications

| ***Program*** | ***Purpose*** |
| ------------- | ------------- |
| ***Nsustain***<sup>[1]</sup> | Help the e[N]vironment and [sustain]ability by coding for anyone who works in the field. Open to any programmer who wants to contribute to environmental sustainability. |
| ***BeeMovr***<sup>[2]</sup> | Help beekeepers by coding whatever they need for their bees. |
| ***Good Life Farms***<sup>[3]</sup> | Help local producers (farmers, beekeeprs, florists, and so on) by giving them a free, low-maintenance platform to sell their goods to local consumers. Deisnged to be as self-sustainable as possible: it's built with Google Sheets and Google Forms instead of fancy, expensive databases. |

<sub>[1] https://nsustain.com</sub><br>
<sub>[2] https://BeeMovr.nsustain.com</sub><br>
<sub>[3] https://GoodLifeFarms.nsustain.com</sub><br>


<br>


#### Deployment Code Snippets

```bash
# ---------------------------------------------------------------------
# 1. Create a VPS at Hetzner and setup an SSH access:
#      https://docs.digitalocean.com/products/droplets/how-to/add-ssh-keys/to-existing-droplet/
# ---------------------------------------------------------------------

# How to configure sshd after booting up a fresh VPS.
# ===================================================
# Source:
#   https://www.digitalocean.com/community/tutorials/ssh-essentials-working-with-ssh-servers-clients-and-keys
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
sudo service sshd restart    # Fedora
sudo service ssh restart    # Ubuntu

# How I set up my client-side SSH configs.
# ========================================
# Source:
#   https://unix.stackexchange.com/questions/708206/ssh-timeout-does-not-happen-and-not-disconnect

# How to configure the SSH client to time-out less frequently.
cat >> ~/.ssh/config
Host *
  ServerAliveInterval 15
  ServerAliveCountMax 3

# How to create an alias so that we can `ssh myserver` instead of
# `ssh main@ip_address` everytime.
cat >> ~/.ssh/config
Host myserver
    HostName ip_address
    User main

# How to setup public / private key access for private GitHub repo.
# =================================================================
# Source:
#   https://leangaurav.medium.com/setup-ssh-key-with-git-github-clone-private-repo-using-ssh-d983ab7bb956
ssh-keygen -t ed25519 -C "name@example.com"

# Copy and paste the public key to github.com repo - Code - SSH .
vim ~/.ssh/id_ed25519.pub

# How to check the https header on command line.
curl --insecure -vvI https://nsustain.com 2>&1

# -------------------------------------------------------------------
# 2. On Hetzner firewall settings, Allow any inbound IPv4 or IPv6 for
#    port 80 and 443, but only allow your whitelisted IP address for
#    incoming port 22 traffic.
# -------------------------------------------------------------------
# How to get your public IP address.
curl https://ipinfo.io/ip

# -------------------------------------------------------------------
# 3. Configure rsyslog server and clients.
# -------------------------------------------------------------------
# Configure the logging and monitoring server.
# ============================================
sudo systemctl start rsyslog
sudo systemctl enable rsyslog

# TODO: Procedures for the rsyslog server.

# Configure the client's Docker settings.
# =======================================
# Change the Docker's default logging driver from json to syslog.
sudo vim /etc/docker/daemon.json

# Copy and paste | Start
{
  "log-driver": "syslog",
  "log-opts": {
    "syslog-address": "unixgram:///dev/log",
    "tag" : "docker/{{.Name}}"
  }
}
# Copy and paste | End

# Restart docker.
cd ~/deploy-nsustain.com
docker compose down
sudo service docker restart
docker compose up -d

# Confirm Docker's logging driver is correctly configured to syslog.
docker inspect <containerName> | grep -A 5 LogConfig

# Configure logrotate so that logs don't take too much space.
sudo vim /etc/logrotate.d/docker

# Copy and paste | Start
/var/log/docker/*.log {
    daily
    rotate 7
    copytruncate
    compress
    delaycompress
    notifempty
    missingok
}
# Copy and paste | End

# Configure the client's rsyslog configs.
# =======================================
# Source:
#   https://chabik.com/rsyslog-and-docker/
sudo mkdir /var/log/docker
sudo chmod -R 0755 /var/log/docker
sudo chown -R syslog:adm /var/log/docker
sudo vim /etc/rsyslog.conf

# Copy and paste | Start
template(name="DockerLogFileName" type="list") {
   constant(value="/var/log/docker/")
   property(name="syslogtag" securepath="replace" regex.expression="docker/\\(.*\\)\\[" regex.submatch="1")
   constant(value=".log")
}

if $programname == "docker" then {
  if $syslogtag contains "docker/" then {
    ?DockerLogFileName
  } else {
    action(type="omfile" file="/var/log/docker/no_tag.log")
  }
  stop
}
# Copy and paste | End

# After restarting, the logs will go to /var/log/docker_all.log
# By the way, `sudo service rsyslog restart` works perfectly fine as
# well. `service` = more high level abstraction than `systemctl`.
sudo systemctl restart rsyslog

# How to check if rsyslog server is listening.
echo "This is a test log message." | nc <server_ip> <port>

# TODO: Use TCP protocol for logging in the central log server, and
# enable SSL/TLS encryption through stunnel.
# Source:
#   https://github.com/jmaas/rsyslog-configs
#   https://www.rsyslog.com/doc/historical/stunnel.html
#   https://www.linuxhowtos.org/Security/stunnel.htm

# ---------------------------------------------------------------------
# 4. Run Docker Compose.
# ---------------------------------------------------------------------
git clone https://github.com/soobinrho/deploy-nsustain.com.git
cd deploy-nsustain.com
docker compose build
docker compose up -d

# ---------------------------------------------------------------------
# 5. Useful workflows.
# ---------------------------------------------------------------------
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

- What is Transport Layer Security (TLS)? https://www.cloudflare.com/learning/ssl/transport-layer-security-tls/

Secure Sockets Layer (SSL) was invented in 1995 by Netscape, and was suceeded by TLS in 1995 by the Internet Engineering Task Force (IETF).
Websites that use the Hypertext transfer protocol secure (HTTPS) protocol are using TLS/SSL too.
"HTTPS is an implementation of TLS encryption on top of the HTTP protocol."
The term SSL and TLS are used interchangeably, and in fact, TLS 1.0 was initially just SSL 3.1, but the name was changed when IETF took over the control.

SSL/TLS encrypts the data it transmits.
Moreover, "SSL initiates an authentication process called a handshake between two communicating devices to ensure that both devices are really who they claim to be.
SSL also digitally signs data in order to provide data integrity, verifying that the data is not tampered with before reaching its intended recipient."

- What is Cloudflare Tunnel? https://www.cloudflare.com/products/tunnel/

"The Tunnel daemon [cloudflared] creates an encrypted tunnel between your origin web server and Cloudflare’s nearest data center, all without opening any public inbound ports."
Then, all requests to the origin web server is handled through the Cloudflare data center, which means the identity of the origin web server or even its IP address is hidden and therefore shielded from DDoS attacks, brute force login attacks, and so on.

<br>

