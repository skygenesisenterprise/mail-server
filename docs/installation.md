# Installation Guide

This guide covers the complete installation process for the Rust Mail Server.

## Prerequisites

### System Requirements
- Linux server (Ubuntu 20.04+, CentOS 8+, or Debian 11+)
- Root or sudo access
- Minimum 2GB RAM, 2 CPU cores
- 10GB+ available disk space
- Static IP address with reverse DNS configured

### Domain Setup
Before installation, ensure you have:
- A registered domain name
- DNS control for the domain
- MX record pointing to your server's IP

## Automated Installation

The easiest way to install the mail server is using the provided installation script:

```bash
# Download and run the installation script
curl -sSL https://raw.githubusercontent.com/your-repo/rust-mail-server/main/install.sh | sudo bash
```

Or clone the repository and run locally:

```bash
git clone https://github.com/your-repo/rust-mail-server.git
cd rust-mail-server
sudo chmod +x install.sh
sudo ./install.sh
```

## Manual Installation

### Step 1: Install Dependencies

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y curl build-essential pkg-config libssl-dev postgresql postgresql-contrib nginx certbot python3-certbot-nginx
```

#### CentOS/RHEL
\`\`\`bash
sudo yum update -y
sudo yum groupinstall -y "Development Tools"
sudo yum install -y curl openssl-devel postgresql-server postgresql-contrib nginx certbot python3-certbot-nginx
sudo postgresql-setup initdb
```

### Step 2: Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### Step 3: Create System User
```bash
sudo useradd --system --home-dir /var/lib/rust-mail-server --shell /bin/false mailserver
```

### Step 4: Create Directories
```bash
sudo mkdir -p /opt/rust-mail-server /etc/rust-mail-server /var/log/rust-mail-server /var/lib/rust-mail-server
sudo chown mailserver:mailserver /var/log/rust-mail-server /var/lib/rust-mail-server
sudo chmod 750 /var/log/rust-mail-server /var/lib/rust-mail-server
```

### Step 5: Build and Install
```bash
# Clone the repository
git clone https://github.com/your-repo/rust-mail-server.git
cd rust-mail-server

# Build the server
cargo build --release

# Install the binary
sudo cp target/release/rust-mail-server /opt/rust-mail-server/
sudo chown root:root /opt/rust-mail-server/rust-mail-server
sudo chmod 755 /opt/rust-mail-server/rust-mail-server
```

### Step 6: Configure Database
```bash
# Start PostgreSQL
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE mailserver;
CREATE USER mailserver WITH ENCRYPTED PASSWORD 'your-secure-password';
GRANT ALL PRIVILEGES ON DATABASE mailserver TO mailserver;
\q
EOF
```

### Step 7: Create Configuration
```bash
sudo tee /etc/rust-mail-server/config.toml << EOF
[server]
bind_address = "0.0.0.0"
smtp_port = 25
imap_port = 143
pop3_port = 110
smtp_tls_port = 465
imap_tls_port = 993
pop3_tls_port = 995

[database]
url = "postgresql://mailserver:your-secure-password@localhost/mailserver"
max_connections = 10

[tls]
cert_path = "/etc/letsencrypt/live/mail.yourdomain.com/fullchain.pem"
key_path = "/etc/letsencrypt/live/mail.yourdomain.com/privkey.pem"

[logging]
level = "info"
file = "/var/log/rust-mail-server/server.log"

[powerdns]
api_url = "http://your-powerdns-server:8081"
api_key = "your-powerdns-api-key"
EOF

sudo chown root:mailserver /etc/rust-mail-server/config.toml
sudo chmod 640 /etc/rust-mail-server/config.toml
```

### Step 8: Create Systemd Service
```bash
sudo tee /etc/systemd/system/rust-mail-server.service << EOF
[Unit]
Description=Rust Mail Server
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=mailserver
Group=mailserver
WorkingDirectory=/var/lib/rust-mail-server
ExecStart=/opt/rust-mail-server/rust-mail-server serve --config /etc/rust-mail-server/config.toml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rust-mail-server

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/rust-mail-server /var/lib/rust-mail-server

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable rust-mail-server
```

### Step 9: Configure Firewall
```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 25/tcp   # SMTP
sudo ufw allow 143/tcp  # IMAP
sudo ufw allow 110/tcp  # POP3
sudo ufw allow 465/tcp  # SMTP TLS
sudo ufw allow 993/tcp  # IMAP TLS
sudo ufw allow 995/tcp  # POP3 TLS
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS

# Or firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-port=25/tcp
sudo firewall-cmd --permanent --add-port=143/tcp
sudo firewall-cmd --permanent --add-port=110/tcp
sudo firewall-cmd --permanent --add-port=465/tcp
sudo firewall-cmd --permanent --add-port=993/tcp
sudo firewall-cmd --permanent --add-port=995/tcp
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --reload
```

### Step 10: Run Database Migrations
```bash
sudo -u mailserver /opt/rust-mail-server/rust-mail-server migrate --config /etc/rust-mail-server/config.toml
```

### Step 11: Obtain SSL Certificates
```bash
# Replace mail.yourdomain.com with your actual domain
sudo certbot certonly --nginx -d mail.yourdomain.com
```

### Step 12: Start Services
```bash
sudo systemctl start rust-mail-server
sudo systemctl start nginx
```

## Post-Installation

### Verify Installation
```bash
# Check service status
sudo systemctl status rust-mail-server

# Check logs
sudo journalctl -u rust-mail-server -f

# Test SMTP connection
telnet localhost 25

# Test IMAP connection
telnet localhost 143
```

### Create First User
```bash
# Use the admin CLI (if implemented) or direct database insertion
sudo -u mailserver /opt/rust-mail-server/rust-mail-server user create --email admin@yourdomain.com --password secure-password
```

## Troubleshooting

### Common Issues

1. **Service fails to start**
   - Check configuration file syntax
   - Verify database connection
   - Check file permissions

2. **Cannot connect to ports**
   - Verify firewall settings
   - Check if ports are already in use
   - Ensure services are listening on correct interfaces

3. **TLS/SSL errors**
   - Verify certificate paths in configuration
   - Check certificate validity
   - Ensure proper file permissions

### Log Locations
- Service logs: `journalctl -u rust-mail-server`
- Application logs: `/var/log/rust-mail-server/server.log`
- PostgreSQL logs: `/var/log/postgresql/`

## Next Steps

After successful installation:
1. [Configure your mail server](configuration.md)
2. [Set up DNS records](deployment.md#dns-configuration)
3. [Configure security settings](security.md)
4. [Test mail functionality](troubleshooting.md#testing)
