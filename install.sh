#!/bin/bash

# Rust Mail Server Installation Script
# This script automates the deployment and setup of the Rust mail server

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/rust-mail-server"
SERVICE_USER="mailserver"
CONFIG_DIR="/etc/rust-mail-server"
LOG_DIR="/var/log/rust-mail-server"
DATA_DIR="/var/lib/rust-mail-server"

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
    print_status "Detected OS: $OS $VER"
}

install_dependencies() {
    print_status "Installing system dependencies..."
    
    case $OS in
        "Ubuntu"*)
            apt-get update
            apt-get install -y curl build-essential pkg-config libssl-dev postgresql postgresql-contrib nginx certbot python3-certbot-nginx
            ;;
        "CentOS"*|"Red Hat"*)
            yum update -y
            yum groupinstall -y "Development Tools"
            yum install -y curl openssl-devel postgresql-server postgresql-contrib nginx certbot python3-certbot-nginx
            postgresql-setup initdb
            ;;
        "Debian"*)
            apt-get update
            apt-get install -y curl build-essential pkg-config libssl-dev postgresql postgresql-contrib nginx certbot python3-certbot-nginx
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    
    print_success "System dependencies installed"
}

install_rust() {
    print_status "Installing Rust..."
    
    if ! command -v rustc &> /dev/null; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source ~/.cargo/env
        print_success "Rust installed successfully"
    else
        print_status "Rust is already installed"
    fi
}

create_user() {
    print_status "Creating service user..."
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd --system --home-dir "$DATA_DIR" --shell /bin/false "$SERVICE_USER"
        print_success "Created user: $SERVICE_USER"
    else
        print_status "User $SERVICE_USER already exists"
    fi
}

create_directories() {
    print_status "Creating directories..."
    
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
    chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR" "$DATA_DIR"
    chmod 755 "$INSTALL_DIR" "$CONFIG_DIR"
    chmod 750 "$LOG_DIR" "$DATA_DIR"
    
    print_success "Directories created"
}

build_server() {
    print_status "Building mail server..."
    
    if [[ ! -f "Cargo.toml" ]]; then
        print_error "Cargo.toml not found. Please run this script from the project root."
        exit 1
    fi
    
    cargo build --release
    cp target/release/rust-mail-server "$INSTALL_DIR/"
    chown root:root "$INSTALL_DIR/rust-mail-server"
    chmod 755 "$INSTALL_DIR/rust-mail-server"
    
    print_success "Mail server built and installed"
}

setup_database() {
    print_status "Setting up PostgreSQL database..."
    
    # Start PostgreSQL service
    systemctl enable postgresql
    systemctl start postgresql
    
    # Create database and user
    sudo -u postgres psql -c "CREATE DATABASE mailserver;" 2>/dev/null || true
    sudo -u postgres psql -c "CREATE USER mailserver WITH ENCRYPTED PASSWORD 'changeme123';" 2>/dev/null || true
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE mailserver TO mailserver;" 2>/dev/null || true
    
    print_success "Database setup completed"
    print_warning "Please change the default database password in production!"
}

create_config() {
    print_status "Creating configuration file..."
    
    cat > "$CONFIG_DIR/config.toml" << 'EOF'
[server]
bind_address = "0.0.0.0"
smtp_port = 25
imap_port = 143
pop3_port = 110
smtp_tls_port = 465
imap_tls_port = 993
pop3_tls_port = 995

[database]
url = "postgresql://mailserver:changeme123@localhost/mailserver"
max_connections = 10

[tls]
cert_path = "/etc/letsencrypt/live/mail.example.com/fullchain.pem"
key_path = "/etc/letsencrypt/live/mail.example.com/privkey.pem"

[logging]
level = "info"
file = "/var/log/rust-mail-server/server.log"

[powerdns]
api_url = "http://localhost:8081"
api_key = "your-powerdns-api-key"

[security]
max_login_attempts = 5
lockout_duration = 300
session_timeout = 3600
EOF
    
    chown root:$SERVICE_USER "$CONFIG_DIR/config.toml"
    chmod 640 "$CONFIG_DIR/config.toml"
    
    print_success "Configuration file created"
    print_warning "Please update the configuration file with your specific settings!"
}

create_systemd_service() {
    print_status "Creating systemd service..."
    
    cat > /etc/systemd/system/rust-mail-server.service << EOF
[Unit]
Description=Rust Mail Server
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$DATA_DIR
ExecStart=$INSTALL_DIR/rust-mail-server serve --config $CONFIG_DIR/config.toml
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
ReadWritePaths=$LOG_DIR $DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable rust-mail-server
    
    print_success "Systemd service created"
}

setup_firewall() {
    print_status "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        ufw allow 25/tcp   # SMTP
        ufw allow 143/tcp  # IMAP
        ufw allow 110/tcp  # POP3
        ufw allow 465/tcp  # SMTP TLS
        ufw allow 993/tcp  # IMAP TLS
        ufw allow 995/tcp  # POP3 TLS
        ufw allow 80/tcp   # HTTP (for Let's Encrypt)
        ufw allow 443/tcp  # HTTPS
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=25/tcp
        firewall-cmd --permanent --add-port=143/tcp
        firewall-cmd --permanent --add-port=110/tcp
        firewall-cmd --permanent --add-port=465/tcp
        firewall-cmd --permanent --add-port=993/tcp
        firewall-cmd --permanent --add-port=995/tcp
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --reload
    fi
    
    print_success "Firewall configured"
}

run_migrations() {
    print_status "Running database migrations..."
    
    sudo -u "$SERVICE_USER" "$INSTALL_DIR/rust-mail-server" migrate --config "$CONFIG_DIR/config.toml"
    
    print_success "Database migrations completed"
}

setup_ssl() {
    print_status "Setting up SSL certificates..."
    
    read -p "Enter your mail server domain (e.g., mail.example.com): " DOMAIN
    
    if [[ -n "$DOMAIN" ]]; then
        certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos --email admin@"$DOMAIN"
        
        # Update config with actual domain
        sed -i "s/mail.example.com/$DOMAIN/g" "$CONFIG_DIR/config.toml"
        
        print_success "SSL certificates obtained for $DOMAIN"
    else
        print_warning "Skipping SSL setup. Please configure manually."
    fi
}

start_services() {
    print_status "Starting services..."
    
    systemctl start rust-mail-server
    systemctl start nginx
    
    print_success "Services started"
}

print_completion() {
    print_success "Installation completed successfully!"
    echo
    echo "Next steps:"
    echo "1. Update the configuration file: $CONFIG_DIR/config.toml"
    echo "2. Change the default database password"
    echo "3. Configure your PowerDNS API settings"
    echo "4. Set up your domain's MX records"
    echo "5. Test the mail server functionality"
    echo
    echo "Service management:"
    echo "  Start:   systemctl start rust-mail-server"
    echo "  Stop:    systemctl stop rust-mail-server"
    echo "  Status:  systemctl status rust-mail-server"
    echo "  Logs:    journalctl -u rust-mail-server -f"
    echo
    echo "Configuration file: $CONFIG_DIR/config.toml"
    echo "Log files: $LOG_DIR/"
}

# Main installation flow
main() {
    print_status "Starting Rust Mail Server installation..."
    
    check_root
    detect_os
    install_dependencies
    install_rust
    create_user
    create_directories
    build_server
    setup_database
    create_config
    create_systemd_service
    setup_firewall
    run_migrations
    
    # Optional SSL setup
    read -p "Do you want to set up SSL certificates now? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        setup_ssl
    fi
    
    start_services
    print_completion
}

# Handle command line arguments
case "${1:-install}" in
    "install")
        main
        ;;
    "uninstall")
        print_status "Uninstalling Rust Mail Server..."
        systemctl stop rust-mail-server 2>/dev/null || true
        systemctl disable rust-mail-server 2>/dev/null || true
        rm -f /etc/systemd/system/rust-mail-server.service
        rm -rf "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
        userdel "$SERVICE_USER" 2>/dev/null || true
        systemctl daemon-reload
        print_success "Uninstallation completed"
        ;;
    "update")
        print_status "Updating Rust Mail Server..."
        systemctl stop rust-mail-server
        build_server
        systemctl start rust-mail-server
        print_success "Update completed"
        ;;
    *)
        echo "Usage: $0 [install|uninstall|update]"
        exit 1
        ;;
esac
