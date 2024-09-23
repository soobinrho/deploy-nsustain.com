# Nsustain.com Deployment

> Nsustain is for anyone who loves the e[N]vironment and [sustain]ability.
> Anyone is welcome to join us if you'd like to volunteer to code for people who work in the field and need our help in solving a problem.

## Infrastructure

| ***Program*** | ***Purpose*** |
| ---- | ---- |
| ***Hetzner*** | I use this for hosting my servers. Main applications server = 3 vCPU, 4GB RAM, 80GB disk. Security logging and monitoring server = 2 vCPU, 4GB RAM, 40GB disk. |
| ***rsyslog*** | "Rocket-fast System for Log Processing." I use this for collecting all my logs in my centralized logging server. |
| ***Tarsnap*** | One of the most, if not the most, secure backup service. I use this for regular backups of my servers. |

> [!NOTE]  
> syslog is a plaintext logging system, [1] while journald is a binary
> logging system. journald was created more recently, but I chose to
> use syslog-ng because syslog is said to be better at remote logging
> at central logging & monitoring server than journald.
> [1] https://datatracker.ietf.org/doc/html/rfc5424

## Applications

| ***Program*** | ***Purpose*** |
| ------------- | ------------- |
| Nsustain | Help the e[N]vironment and [sustain]ability by coding for anyone who works in the field. Open to any programmer who wants to contribute to environmental sustainability. |
| BeeMovr | Help beekeepers by coding whatever they need for their bees. |
| Good Life Farms | Help local producers (farmers, beekeeprs, florists, and so on) by giving them a free, low-maintenance platform to sell their goods to local consumers. Deisnged to be as self-sustainable as possible: it's built with Google Sheets and Google Forms instead of fancy, expensive databases. |

| ***Program*** | ***Domain*** |
| ------------- | ------------- |
| Nsustain | https://nsustain.com |
| BeeMovr | https://BeeMovr.nsustain.com |
| Good Life Farms | https://GoodLifeFarms.nsustain.com |

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
