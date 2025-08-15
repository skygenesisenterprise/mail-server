# Enterprise Mail Server

A high-performance, multi-protocol mail server written in Rust supporting IMAP, SMTP, and POP3 protocols with multi-domain support and PowerDNS integration.

## Features

- **Multi-Protocol Support**: IMAP, SMTP, and POP3 protocols
- **Multi-Domain**: Support for multiple email domains
- **Security**: TLS/SSL encryption, secure authentication with Argon2
- **Scalability**: Async/await architecture with connection pooling
- **PowerDNS Integration**: Automatic DNS record management
- **Database Storage**: PostgreSQL backend for reliable email storage
- **Modular Architecture**: Clean separation of concerns

## Quick Start

### Prerequisites

- Rust 1.70+
- PostgreSQL 12+
- PowerDNS (optional, for domain management)
- TLS certificates

### Installation

1. Clone the repository:
```bash
git clone https://github.com/skygenesisenterprise/mail-server
cd mail-server
```

2. Set up the database:
```bash
createdb mailserver
```

3. Configure the server:
```bash
cp config.toml.example config.toml
# Edit config.toml with your settings
```

4. Generate or obtain TLS certificates:
```bash
mkdir certs
# Place your server.crt and server.key in the certs directory
```

5. Run the server:
```bash
cargo run
```

## Configuration

The server is configured via `config.toml`. Key sections include:

- **server**: Basic server settings
- **database**: PostgreSQL connection settings
- **tls**: TLS certificate paths
- **smtp/imap/pop3**: Protocol-specific settings
- **powerdns**: PowerDNS API configuration
- **auth**: Authentication settings
- **storage**: Email storage configuration

## Architecture

The mail server is built with a modular architecture:

- **Core**: Main server orchestration and configuration
- **Protocols**: SMTP, IMAP, and POP3 protocol implementations
- **Auth**: Authentication and user management
- **Storage**: Database operations and email storage
- **Domain**: Domain management and PowerDNS integration
- **TLS**: SSL/TLS configuration and management

## Development

### Running Tests

```bash
cargo test
```

### Logging

The server uses structured logging with tracing. Set the `RUST_LOG` environment variable to control log levels:

```bash
RUST_LOG=debug cargo run
```

### Database Migrations

Database migrations run automatically on startup. The server will create all necessary tables and indexes.

## Security Considerations

- Always use TLS in production
- Regularly update dependencies
- Use strong passwords and proper certificate management
- Configure firewall rules appropriately
- Monitor logs for suspicious activity

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.
