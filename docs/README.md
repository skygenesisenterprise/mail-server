# Enterprise Mail Server Documentation

A comprehensive, high-performance mail server implementation in Rust supporting IMAP, SMTP, and POP3 protocols with enterprise-grade security and scalability features.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/skygenesisenterprise/mail-server
cd mail-server

# Run the installation script
sudo ./install.sh

# Start the server
sudo systemctl start rust-mail-server
```

## Documentation Structure

- [Installation Guide](installation.md) - Detailed installation and setup instructions
- [Configuration](configuration.md) - Complete configuration reference
- [API Reference](api.md) - Protocol implementations and API documentation
- [Security Guide](security.md) - Security features and best practices
- [Deployment](deployment.md) - Production deployment strategies
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
- [Development](development.md) - Development setup and contribution guidelines

## Features

### Protocol Support
- **SMTP** - Full SMTP server with authentication, TLS, and message routing
- **IMAP** - Complete IMAP4rev1 implementation with mailbox management
- **POP3** - POP3 server with secure authentication and message retrieval

### Security Features
- TLS/SSL encryption for all protocols
- Two-factor authentication (TOTP)
- Rate limiting and account lockout protection
- Comprehensive security event logging
- Password strength validation

### Storage & Performance
- PostgreSQL backend with optimized queries
- Message compression and deduplication
- Full-text search capabilities
- Efficient indexing and caching
- Horizontal scaling support

### Domain Management
- PowerDNS integration for DNS management
- Multi-domain support
- Automatic DNS record creation (MX, SPF, DKIM, DMARC)
- Domain verification workflows

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SMTP Server   │    │   IMAP Server   │    │   POP3 Server   │
│   Port 25/465   │    │  Port 143/993   │    │  Port 110/995   │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │     Core Services         │
                    │  ┌─────────────────────┐  │
                    │  │   Authentication    │  │
                    │  │   & Security        │  │
                    │  └─────────────────────┘  │
                    │  ┌─────────────────────┐  │
                    │  │   Email Storage     │  │
                    │  │   & Processing      │  │
                    │  └─────────────────────┘  │
                    │  ┌─────────────────────┐  │
                    │  │   Domain Management │  │
                    │  │   & DNS Integration │  │
                    │  └─────────────────────┘  │
                    └───────────┬───────────────┘
                                │
                    ┌───────────┴───────────────┐
                    │     PostgreSQL Database   │
                    └───────────────────────────┘
```

## System Requirements

### Minimum Requirements
- **CPU**: 2 cores
- **RAM**: 2GB
- **Storage**: 10GB SSD
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, Debian 11+)

### Recommended for Production
- **CPU**: 4+ cores
- **RAM**: 8GB+
- **Storage**: 50GB+ SSD with backup
- **Network**: Dedicated IP with reverse DNS
- **OS**: Debian 12 or Ubuntu 22.04 LTS

## Support

- [GitHub Issues](https://github.com/skygenesisenterprise/mail-server/issues)
- [Documentation](https://docs.skygenesisenterprise.com)
- [Community Forum](https://forum.skygenesisenterprise.com)

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.