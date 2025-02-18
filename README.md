![CipherBox](https://socialify.git.ci/clueNA/CipherBox/image?font=Source+Code+Pro&language=1&name=1&owner=1&pattern=Transparent&stargazers=1&theme=Dark)
# CipherBox 🔒

CipherBox is a secure file encryption system that uses RSA and AES hybrid encryption to protect your files. Built with Python and Streamlit, it provides a user-friendly interface for file encryption and decryption while maintaining high security standards.

## Features

### 🛡️ Security
- Hybrid encryption (RSA + AES) for optimal security and performance
- Unique encryption keys for each user
- Secure password hashing with salt
- Protected private keys
- Session-based authentication

### 📁 File Management
- Support for all file types
- File size limit: 10MB (configurable)
- Encrypted file tracking
- Secure file storage
- Multi-user support

### 🎯 Key Features
- User registration and authentication
- File encryption with personal keys
- File decryption for authorized users
- File history tracking
- Data clearing option

## Installation

### Prerequisites
```bash
- Python 3.8 or higher
- pip (Python package manager)
```

### Setup
1. Clone the repository:
```bash
git clone https://github.com/clueNA/cipherbox.git
cd cipherbox
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Initialize the database:
```bash
python create_database.py
```

4. Run the application:
```bash
streamlit run app.py
```

## Usage

### 👤 User Management

1. **Registration**
   - Click the "Register" tab
   - Enter username and password
   - System generates encryption keys automatically

2. **Login**
   - Use the "Login" tab
   - Enter credentials
   - Access your encrypted files

### 🔒 File Encryption

1. Select "Encrypt File" tab
2. Upload file (up to 100MB)
3. Click "Encrypt"
4. Download encrypted file (*.encrypted)

### 🔓 File Decryption

1. Select "Decrypt File" tab
2. Upload encrypted file (*.encrypted)
3. Click "Decrypt"
4. Download original file

### 📋 File Management

- View all encrypted files in "File List" tab
- Track encryption dates
- Manage file access

## Technical Details

### Security Implementation

```python
# Encryption Process
- RSA 2048-bit key pair generation
- AES-256 for file encryption
- PBKDF2 for password hashing
- Secure random salt generation
```

### Database Structure

- Users Table
  - Username
  - Password hash
  - Public/Private keys
  - Salt

- FileKeys Table
  - Filename
  - File hash
  - Encrypted key
  - Owner reference

## File Support

### Supported File Types
- Documents (.pdf, .doc, .txt, etc.)
- Images (.jpg, .png, .gif, etc.)
- Media files (.mp3, .mp4, etc.)
- Archives (.zip, .rar, etc.)
- Any other file type

### Size Limitations
- Default: 100MB
- Configurable in config.py

## Security Considerations

### Best Practices
- Keep encrypted files backed up
- Store passwords securely
- Don't share private keys
- Log out after usage
- Regular password updates

### Data Protection
- Files encrypted with personal keys
- Only file owner can decrypt
- Secure key storage
- Protected user sessions

## Troubleshooting

### Common Issues

1. **Registration Fails**
   - Check username availability
   - Ensure password meets requirements

2. **Encryption Fails**
   - Verify file size limits
   - Check file permissions

3. **Decryption Fails**
   - Confirm file ownership
   - Verify correct user login
   - Check file integrity

## Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## License

Apache-2.0 license - See LICENSE file for details

## Contact

- GitHub Issues: [Create Issue](https://github.com/yourusername/cipherbox/issues)

## Acknowledgments

- Streamlit for the web interface
- cryptography.io for encryption
- SQLAlchemy for database management
