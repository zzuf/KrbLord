# KrbLoad

KrbLoad is a command-line utility for importing Kerberos ticket files (`.kirbi` format) into the current Windows session or a specified Logon Session (LUID) using native Windows LSA APIs.  
This tool is useful for security professionals, penetration testers, and system administrators who need to inject Kerberos tickets for authentication testing or troubleshooting.

## Features

- Import Kerberos tickets into the current or specified logon session.
- Supports `.kirbi` ticket files.
- Uses native Windows LSA (Local Security Authority) APIs.
- Written in C# (.NET Framework 4.7.2).

## Requirements

- Windows OS
- .NET Framework 4.7.2
- Administrator privileges may be required for some operations

## Usage
