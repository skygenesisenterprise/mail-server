# Configuration Reference

The Enterprise Mail Server uses TOML format for configuration. The main configuration file is located at `/etc/enterprise-mail-server/config.toml`.

## Configuration Sections

### Server Configuration

```toml
[server]
bind_address = "0.0.0.0"        # IP address to bind to
smtp_port = 25                  # SMTP port (standard)
imap_port = 143                 # IMAP port (standard)
pop3_port = 110                 # POP3 port (standard)
smtp_tls_port = 465             # SMTP over TLS port
imap_tls_port = 993             # IMAP over TLS port
pop3_tls_port = 995             # POP3 over TLS port
max_connections = 1000          # Maximum concurrent connections
connection_timeout = 300        # Connection timeout in seconds
```

### Database Configuration

```toml
[database]
url = "postgresql://user:password@localhost/mailserver"
max_connections = 10            # Connection pool size
connection_timeout = 30         # Connection timeout in seconds
idle_timeout = 600             # Idle connection timeout
```

### TLS/SSL Configuration

```toml
[tls]
cert_path = "/path/to/certificate.pem"
key_path = "/path/to/private-key.pem"
ca_path = "/path/to/ca-bundle.pem"     # Optional CA bundle
protocols = ["TLSv1.2", "TLSv1.3"]    # Supported TLS versions
ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
```

### Logging Configuration

```toml
[logging]
level = "info"                  # Log level: trace, debug, info, warn, error
file = "/var/log/rust-mail-server/server.log"
max_size = "100MB"             # Maximum log file size
max_files = 10                 # Number of log files to keep
format = "json"                # Log format: json, text
```

### Authentication Configuration

```toml
[auth]
password_min_length = 8         # Minimum password length
password_require_uppercase = true
password_require_lowercase = true
password_require_numbers = true
password_require_symbols = true
max_login_attempts = 5          # Maximum failed login attempts
lockout_duration = 300          # Account lockout duration in seconds
session_timeout = 3600          # Session timeout in seconds
totp_enabled = true            # Enable two-factor authentication
```

### Security Configuration

```toml
[security]
rate_limit_enabled = true       # Enable rate limiting
rate_limit_requests = 100       # Requests per window
rate_limit_window = 60          # Rate limit window in seconds
ip_whitelist = []              # Whitelisted IP addresses
ip_blacklist = []              # Blacklisted IP addresses
fail2ban_enabled = true        # Enable automatic IP blocking
fail2ban_threshold = 10        # Failed attempts before blocking
fail2ban_duration = 3600       # Block duration in seconds
```

### PowerDNS Integration

```toml
[powerdns]
api_url = "http://localhost:8081"
api_key = "your-api-key"
default_ttl = 3600             # Default TTL for DNS records
auto_create_records = true     # Automatically create DNS records
verify_domains = true          # Verify domain ownership
```

### Storage Configuration

```toml
[storage]
compression_enabled = true      # Enable message compression
compression_algorithm = "gzip"  # Compression algorithm: gzip, lz4, zstd
deduplication_enabled = true   # Enable message deduplication
max_message_size = "25MB"      # Maximum message size
attachment_storage = "database" # Attachment storage: database, filesystem, s3
attachment_path = "/var/lib/rust-mail-server/attachments"
```

### SMTP Configuration

```toml
[smtp]
hostname = "mail.example.com"   # Server hostname
max_message_size = "25MB"       # Maximum message size
max_recipients = 100           # Maximum recipients per message
require_auth = true            # Require authentication for sending
allow_relay = false            # Allow mail relay
relay_domains = []             # Domains allowed for relay
```

### IMAP Configuration

```toml
[imap]
max_connections_per_user = 10   # Maximum IMAP connections per user
idle_timeout = 1800            # IDLE command timeout
search_timeout = 30            # SEARCH command timeout
fetch_timeout = 60             # FETCH command timeout
enable_extensions = ["IDLE", "SORT", "THREAD", "QUOTA"]
```

### POP3 Configuration

```toml
[pop3]
max_connections_per_user = 5    # Maximum POP3 connections per user
session_timeout = 600          # Session timeout in seconds
delete_on_retrieve = false     # Delete messages after retrieval
```

## Environment Variables

You can override configuration values using environment variables:

```bash
# Database URL
export RUST_MAIL_SERVER_DATABASE_URL="postgresql://user:pass@host/db"

# TLS certificate paths
export RUST_MAIL_SERVER_TLS_CERT_PATH="/path/to/cert.pem"
export RUST_MAIL_SERVER_TLS_KEY_PATH="/path/to/key.pem"

# PowerDNS API settings
export RUST_MAIL_SERVER_POWERDNS_API_URL="http://dns-server:8081"
export RUST_MAIL_SERVER_POWERDNS_API_KEY="secret-key"

# Logging level
export RUST_MAIL_SERVER_LOGGING_LEVEL="debug"
```

## Configuration Validation

The server validates the configuration on startup. Common validation errors:

- **Invalid database URL**: Check connection string format
- **Missing TLS certificates**: Verify file paths and permissions
- **Invalid port numbers**: Ensure ports are within valid range (1-65535)
- **Conflicting settings**: Some options are mutually exclusive

## Configuration Examples

### Development Configuration

```toml
[server]
bind_address = "127.0.0.1"
smtp_port = 2525
imap_port = 1143
pop3_port = 1110

[database]
url = "postgresql://mailserver:password@localhost/mailserver_dev"

[logging]
level = "debug"
format = "text"

[auth]
max_login_attempts = 10
lockout_duration = 60

[security]
rate_limit_enabled = false
```

### Production Configuration

```toml
[server]
bind_address = "0.0.0.0"
max_connections = 5000
connection_timeout = 120

[database]
url = "postgresql://mailserver:secure-password@db-server/mailserver"
max_connections = 50

[tls]
cert_path = "/etc/letsencrypt/live/mail.example.com/fullchain.pem"
key_path = "/etc/letsencrypt/live/mail.example.com/privkey.pem"
protocols = ["TLSv1.3"]

[logging]
level = "warn"
format = "json"
max_size = "500MB"
max_files = 30

[security]
rate_limit_enabled = true
rate_limit_requests = 50
rate_limit_window = 60
fail2ban_enabled = true
```

## Configuration Management

### Reloading Configuration

The server supports configuration reloading without restart:

```bash
# Send SIGHUP to reload configuration
sudo systemctl reload rust-mail-server

# Or use the admin command
sudo -u mailserver /opt/rust-mail-server/rust-mail-server config reload
```

### Configuration Backup

Always backup your configuration before making changes:

```bash
sudo cp /etc/rust-mail-server/config.toml /etc/rust-mail-server/config.toml.backup
```

### Configuration Testing

Test configuration changes before applying:

```bash
sudo -u mailserver /opt/rust-mail-server/rust-mail-server config validate --config /etc/rust-mail-server/config.toml
```