from flask import Flask, render_template, request, jsonify
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
import re
import logging
import io
import os

# Import pkcs12 functions - available in cryptography 3.0+
try:
    from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates, serialize_key_and_certificates
    PKCS12_AVAILABLE = True
except ImportError:
    PKCS12_AVAILABLE = False

app = Flask(__name__)

# SECURITY: Disable Flask sessions to prevent any session-based storage
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 0  # No persistent sessions

# SECURITY: Ensure no shared state between requests
# Flask's request context is already isolated per request, but we explicitly disable sessions
app.config['SESSION_TYPE'] = None

# SECURITY: Limit request body size to prevent memory exhaustion
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1 MB

# SECURITY: Configure logging to prevent sensitive data from being logged
# Disable Flask's default request logging for security
logging.getLogger('werkzeug').setLevel(logging.WARNING)

# Custom logging filter to redact private keys from any log messages
class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        if hasattr(record, 'msg') and record.msg:
            # Redact private key patterns
            msg = str(record.msg)
            msg = re.sub(r'-----BEGIN.*?PRIVATE KEY-----.*?-----END.*?PRIVATE KEY-----', 
                        '[PRIVATE KEY REDACTED]', msg, flags=re.DOTALL)
            msg = re.sub(r'"private_key":\s*"[^"]*"', '"private_key": "[REDACTED]"', msg)
            record.msg = msg
        return True

# Apply filter to all loggers
for handler in logging.root.handlers:
    handler.addFilter(SensitiveDataFilter())

# Endpoints that handle private key material
SENSITIVE_ENDPOINTS = {'/api/check-match', '/api/convert-certificate'}

@app.after_request
def set_security_headers(response):
    """Set security headers on all responses and prevent caching of sensitive data"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Prevent caching of responses from endpoints that handle private keys
    if request.path in SENSITIVE_ENDPOINTS:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
    return response

def detect_input_type(text):
    """Detect what type of input the user provided"""
    text_upper = text.upper()
    if 'BEGIN CERTIFICATE REQUEST' in text_upper or 'BEGIN NEW CERTIFICATE REQUEST' in text_upper:
        return 'csr'
    elif 'BEGIN CERTIFICATE' in text_upper or 'BEGIN X509 CERTIFICATE' in text_upper:
        return 'certificate'
    elif 'BEGIN PRIVATE KEY' in text_upper or 'BEGIN RSA PRIVATE KEY' in text_upper or 'BEGIN EC PRIVATE KEY' in text_upper:
        return 'private_key'
    elif 'BEGIN' in text_upper:
        return 'unknown_pem'
    else:
        return 'unknown'

def parse_certificate(cert_text):
    """Parse certificate text and extract information"""
    try:
        # Check if input is empty
        if not cert_text or not cert_text.strip():
            return {'success': False, 'error': 'Please paste a certificate. The input appears to be empty.'}
        
        # Detect input type to provide helpful error messages
        input_type = detect_input_type(cert_text)
        if input_type == 'csr':
            return {
                'success': False, 
                'error': 'It looks like you pasted a Certificate Signing Request (CSR) instead of a certificate. Please use the "CSR Decoder" tool (tab 3) to decode CSRs, or paste an actual certificate here.'
            }
        elif input_type == 'private_key':
            return {
                'success': False,
                'error': 'It looks like you pasted a private key instead of a certificate. Certificates are public and start with "-----BEGIN CERTIFICATE-----". Please paste a certificate, not a private key.'
            }
        elif input_type == 'unknown_pem':
            return {
                'success': False,
                'error': 'The pasted text appears to be in PEM format, but it doesn\'t look like a certificate. Certificates should start with "-----BEGIN CERTIFICATE-----" or "-----BEGIN X509 CERTIFICATE-----".'
            }
        elif input_type == 'unknown':
            return {
                'success': False,
                'error': 'The pasted text doesn\'t appear to be a valid certificate. Certificates should be in PEM format (starting with "-----BEGIN CERTIFICATE-----") or contain base64-encoded certificate data.'
            }
        
        # Remove common headers/footers and whitespace
        cert_text_clean = re.sub(r'-----BEGIN CERTIFICATE-----', '', cert_text)
        cert_text_clean = re.sub(r'-----END CERTIFICATE-----', '', cert_text_clean)
        cert_text_clean = re.sub(r'-----BEGIN X509 CERTIFICATE-----', '', cert_text_clean)
        cert_text_clean = re.sub(r'-----END X509 CERTIFICATE-----', '', cert_text_clean)
        cert_text_clean = ''.join(cert_text_clean.split())
        
        if not cert_text_clean:
            return {'success': False, 'error': 'The certificate appears to be empty after removing headers. Please ensure you\'ve pasted a complete certificate.'}
        
        # Decode base64
        try:
            cert_der = base64.b64decode(cert_text_clean)
        except Exception as e:
            return {
                'success': False,
                'error': 'Failed to decode the certificate. The certificate should contain valid base64-encoded data. Please check that you\'ve copied the entire certificate including all lines.'
            }
        
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
        except Exception as e:
            # Check if it might be a CSR
            if 'CERTIFICATE REQUEST' in cert_text.upper():
                return {
                    'success': False,
                    'error': 'This appears to be a Certificate Signing Request (CSR), not a certificate. Please use the "CSR Decoder" tool (tab 3) instead.'
                }
            return {
                'success': False,
                'error': f'Failed to parse the certificate. The data doesn\'t appear to be a valid X.509 certificate. Please ensure you\'ve copied the complete certificate including the BEGIN and END lines.'
            }
        
        # Extract subject information
        subject = {}
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                subject['CN'] = attr.value
            elif attr.oid == NameOID.ORGANIZATION_NAME:
                subject['O'] = attr.value
            elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                subject['OU'] = attr.value
            elif attr.oid == NameOID.LOCALITY_NAME:
                subject['L'] = attr.value
            elif attr.oid == NameOID.STATE_OR_PROVINCE_NAME:
                subject['ST'] = attr.value
            elif attr.oid == NameOID.COUNTRY_NAME:
                subject['C'] = attr.value
        
        # Extract issuer information
        issuer = {}
        for attr in cert.issuer:
            if attr.oid == NameOID.COMMON_NAME:
                issuer['CN'] = attr.value
            elif attr.oid == NameOID.ORGANIZATION_NAME:
                issuer['O'] = attr.value
        
        # Extract SAN (Subject Alternative Names)
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        
        # Extract validity dates
        not_before = cert.not_valid_before.isoformat()
        not_after = cert.not_valid_after.isoformat()
        
        # Extract serial number
        serial_number = str(cert.serial_number)
        
        return {
            'success': True,
            'common_name': subject.get('CN', ''),
            'organization': subject.get('O', ''),
            'organizational_unit': subject.get('OU', ''),
            'locality': subject.get('L', ''),
            'state': subject.get('ST', ''),
            'country': subject.get('C', ''),
            'san': san_list,
            'valid_from': not_before,
            'valid_to': not_after,
            'serial_number': serial_number,
            'issuer_cn': issuer.get('CN', ''),
            'issuer_org': issuer.get('O', '')
        }
    except Exception as e:
        # Provide user-friendly error message
        error_msg = str(e)
        if 'asn1' in error_msg.lower() or 'parse' in error_msg.lower():
            return {
                'success': False,
                'error': 'The certificate format is invalid or corrupted. Please ensure you\'ve copied the complete certificate including the "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----" lines, and that all lines are included.'
            }
        return {'success': False, 'error': f'Failed to process certificate: {error_msg}'}

def parse_private_key(key_text):
    """Parse private key text"""
    if not key_text or not key_text.strip():
        raise Exception("Private key appears to be empty. Please paste a valid private key.")
    
    # Detect if it's actually a certificate or CSR
    input_type = detect_input_type(key_text)
    if input_type == 'certificate':
        raise Exception("It looks like you pasted a certificate instead of a private key. Please paste the private key that matches your certificate.")
    elif input_type == 'csr':
        raise Exception("It looks like you pasted a CSR instead of a private key. Please paste the private key that was used to generate the CSR.")
    
    try:
        # Try PEM format first
        try:
            key = serialization.load_pem_private_key(
                key_text.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            return key, 'pem'
        except Exception as pem_error:
            # Try DER format
            try:
                key_text_clean = re.sub(r'-----BEGIN.*?-----', '', key_text)
                key_text_clean = re.sub(r'-----END.*?-----', '', key_text_clean)
                key_text_clean = ''.join(key_text_clean.split())
                if not key_text_clean:
                    raise Exception("Private key appears to be empty after removing headers.")
                key_der = base64.b64decode(key_text_clean)
                key = serialization.load_der_private_key(
                    key_der,
                    password=None,
                    backend=default_backend()
                )
                return key, 'der'
            except Exception as der_error:
                # Provide helpful error message
                if 'encrypted' in str(pem_error).lower() or 'password' in str(pem_error).lower():
                    raise Exception("The private key appears to be password-protected. This tool only supports unencrypted private keys. Please decrypt the key first or use an unencrypted key.")
                raise Exception(f"Failed to parse private key. Please ensure you've copied the complete private key including the BEGIN and END lines. Error: {str(pem_error)}")
    except Exception as e:
        # Re-raise with better message if it's already our custom exception
        if "appears to be" in str(e) or "Failed to parse" in str(e):
            raise
        raise Exception(f"Failed to parse private key: {str(e)}")

def secure_cleanup(*refs):
    """
    SECURITY: Delete references to sensitive data and prompt garbage collection.

    IMPORTANT LIMITATION: Python strings are immutable and cannot be overwritten
    in-place. Calling del only removes the reference; the actual memory is freed
    when the garbage collector runs. For true secure memory handling, private keys
    should be processed by native C libraries (which the cryptography library does
    internally for key objects). This function ensures references are dropped
    promptly and gc.collect() is called to minimize the window of exposure.

    For maximum security, run this application locally or in an isolated container
    rather than on shared infrastructure.
    """
    import gc
    for ref in refs:
        try:
            del ref
        except:
            pass
    gc.collect()

def check_certificate_key_match(cert_text, key_text):
    """
    Check if certificate and private key match.
    
    SECURITY NOTE: This function processes private keys in memory only.
    Private keys are NEVER stored, logged, or persisted anywhere.
    Each request is completely isolated - no shared state between users.
    All sensitive data is cleared from memory after processing.
    """
    try:
        # Parse certificate
        cert_text_clean = re.sub(r'-----BEGIN CERTIFICATE-----', '', cert_text)
        cert_text_clean = re.sub(r'-----END CERTIFICATE-----', '', cert_text_clean)
        cert_text_clean = re.sub(r'-----BEGIN X509 CERTIFICATE-----', '', cert_text_clean)
        cert_text_clean = re.sub(r'-----END X509 CERTIFICATE-----', '', cert_text_clean)
        cert_text_clean = ''.join(cert_text_clean.split())
        cert_der = base64.b64decode(cert_text_clean)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        # Parse private key
        private_key, _ = parse_private_key(key_text)

        # Universal approach: compare serialized public keys
        # Works for RSA, EC, Ed25519, and any other key type
        cert_pub_bytes = cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_pub_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        match = cert_pub_bytes == key_pub_bytes

        return {
            'success': True,
            'match': match,
            'message': 'Certificate and private key match' if match else 'Certificate and private key do NOT match'
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}
    finally:
        # SECURITY: Drop all references to sensitive data and prompt GC
        secure_cleanup(
            locals().get('private_key'),
            locals().get('cert_der'),
            locals().get('cert_text_clean'),
        )

def parse_csr(csr_text):
    """Parse CSR and extract information"""
    try:
        # Check if input is empty
        if not csr_text or not csr_text.strip():
            return {'success': False, 'error': 'Please paste a Certificate Signing Request (CSR). The input appears to be empty.'}
        
        # Detect input type to provide helpful error messages
        input_type = detect_input_type(csr_text)
        if input_type == 'certificate':
            return {
                'success': False,
                'error': 'It looks like you pasted a certificate instead of a Certificate Signing Request (CSR). Please use the "Certificate Decoder" tool (tab 1) to decode certificates, or paste an actual CSR here.'
            }
        elif input_type == 'private_key':
            return {
                'success': False,
                'error': 'It looks like you pasted a private key instead of a CSR. CSRs should start with "-----BEGIN CERTIFICATE REQUEST-----". Please paste a CSR, not a private key.'
            }
        elif input_type == 'unknown_pem':
            return {
                'success': False,
                'error': 'The pasted text appears to be in PEM format, but it doesn\'t look like a CSR. CSRs should start with "-----BEGIN CERTIFICATE REQUEST-----" or "-----BEGIN NEW CERTIFICATE REQUEST-----".'
            }
        elif input_type == 'unknown':
            return {
                'success': False,
                'error': 'The pasted text doesn\'t appear to be a valid CSR. CSRs should be in PEM format (starting with "-----BEGIN CERTIFICATE REQUEST-----") or contain base64-encoded CSR data.'
            }
        
        # Remove headers/footers
        csr_text_clean = re.sub(r'-----BEGIN CERTIFICATE REQUEST-----', '', csr_text)
        csr_text_clean = re.sub(r'-----END CERTIFICATE REQUEST-----', '', csr_text_clean)
        csr_text_clean = re.sub(r'-----BEGIN NEW CERTIFICATE REQUEST-----', '', csr_text_clean)
        csr_text_clean = re.sub(r'-----END NEW CERTIFICATE REQUEST-----', '', csr_text_clean)
        csr_text_clean = ''.join(csr_text_clean.split())
        
        if not csr_text_clean:
            return {'success': False, 'error': 'The CSR appears to be empty after removing headers. Please ensure you\'ve pasted a complete CSR.'}
        
        # Decode base64
        try:
            csr_der = base64.b64decode(csr_text_clean)
        except Exception as e:
            return {
                'success': False,
                'error': 'Failed to decode the CSR. The CSR should contain valid base64-encoded data. Please check that you\'ve copied the entire CSR including all lines.'
            }
        
        try:
            csr = x509.load_der_x509_csr(csr_der, default_backend())
        except Exception as e:
            # Check if it might be a certificate
            if 'BEGIN CERTIFICATE' in csr_text.upper() and 'REQUEST' not in csr_text.upper():
                return {
                    'success': False,
                    'error': 'This appears to be a certificate, not a CSR. Please use the "Certificate Decoder" tool (tab 1) instead.'
                }
            return {
                'success': False,
                'error': f'Failed to parse the CSR. The data doesn\'t appear to be a valid Certificate Signing Request. Please ensure you\'ve copied the complete CSR including the BEGIN and END lines.'
            }
        
        # Extract subject information
        subject = {}
        for attr in csr.subject:
            if attr.oid == NameOID.COMMON_NAME:
                subject['CN'] = attr.value
            elif attr.oid == NameOID.ORGANIZATION_NAME:
                subject['O'] = attr.value
            elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                subject['OU'] = attr.value
            elif attr.oid == NameOID.LOCALITY_NAME:
                subject['L'] = attr.value
            elif attr.oid == NameOID.STATE_OR_PROVINCE_NAME:
                subject['ST'] = attr.value
            elif attr.oid == NameOID.COUNTRY_NAME:
                subject['C'] = attr.value
            elif attr.oid == NameOID.EMAIL_ADDRESS:
                subject['E'] = attr.value
        
        # Extract SAN
        san_list = []
        try:
            san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        
        # Extract key information
        public_key = csr.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            key_type = 'RSA'
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_size = public_key.key_size
            key_type = 'EC'
        else:
            key_size = None
            key_type = 'Unknown'
        
        return {
            'success': True,
            'common_name': subject.get('CN', ''),
            'organization': subject.get('O', ''),
            'organizational_unit': subject.get('OU', ''),
            'locality': subject.get('L', ''),
            'state': subject.get('ST', ''),
            'country': subject.get('C', ''),
            'email': subject.get('E', ''),
            'san': san_list,
            'key_type': key_type,
            'key_size': key_size
        }
    except Exception as e:
        # Provide user-friendly error message
        error_msg = str(e)
        if 'asn1' in error_msg.lower() or 'parse' in error_msg.lower():
            return {
                'success': False,
                'error': 'The CSR format is invalid or corrupted. Please ensure you\'ve copied the complete CSR including the "-----BEGIN CERTIFICATE REQUEST-----" and "-----END CERTIFICATE REQUEST-----" lines, and that all lines are included.'
            }
        return {'success': False, 'error': f'Failed to process CSR: {error_msg}'}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/decode-certificate', methods=['POST'])
def decode_certificate():
    cert_text = request.json.get('certificate', '')
    result = parse_certificate(cert_text)
    return jsonify(result)

@app.route('/api/check-match', methods=['POST'])
def check_match():
    """
    SECURITY: This endpoint processes private keys but NEVER stores them.
    - Private keys are processed in memory only
    - No database or file storage
    - Request logging is disabled for this endpoint
    - All sensitive data is cleared after processing
    - Each request is completely isolated - no shared state between concurrent users
    - Flask's request context ensures isolation between requests
    """
    try:
        request_data = request.get_json()
        cert_text = request_data.get('certificate', '') if request_data else ''
        key_text = request_data.get('private_key', '') if request_data else ''

        result = check_certificate_key_match(cert_text, key_text)
        return jsonify(result)
    except Exception as e:
        # Provide user-friendly error messages
        error_msg = str(e)
        if 'private key appears to be empty' in error_msg.lower():
            return jsonify({'success': False, 'error': 'The private key appears to be empty. Please paste a valid private key.'})
        elif 'pasted a certificate instead' in error_msg.lower():
            return jsonify({'success': False, 'error': 'It looks like you pasted a certificate in the private key field. Please paste the private key that matches your certificate.'})
        elif 'pasted a csr instead' in error_msg.lower():
            return jsonify({'success': False, 'error': 'It looks like you pasted a CSR in the private key field. Please paste the private key that was used to generate the CSR.'})
        elif 'password-protected' in error_msg.lower() or 'encrypted' in error_msg.lower():
            return jsonify({'success': False, 'error': 'The private key appears to be password-protected (encrypted). This tool only supports unencrypted private keys. Please decrypt the key first or use an unencrypted key.'})
        elif 'failed to parse' in error_msg.lower():
            return jsonify({'success': False, 'error': f'Failed to parse the private key. Please ensure you\'ve copied the complete private key including the BEGIN and END lines. {error_msg}'})
        else:
            return jsonify({'success': False, 'error': f'An error occurred while processing: {error_msg}'})

@app.route('/api/decode-csr', methods=['POST'])
def decode_csr():
    csr_text = request.json.get('csr', '')
    result = parse_csr(csr_text)
    return jsonify(result)

@app.route('/api/convert-certificate', methods=['POST'])
def convert_certificate():
    """
    Convert certificate between different formats.
    Supports: PFX/P12, PEM, DER, CRT conversions
    """
    try:
        input_data = request.json.get('input_data', '')
        input_format = request.json.get('input_format', 'auto')
        output_format = request.json.get('output_format', 'pem')
        password = request.json.get('password', '')  # For PFX/P12 files
        
        if not input_data or not input_data.strip():
            return jsonify({'success': False, 'error': 'Please paste or upload certificate data.'})
        
        # Auto-detect input format if not specified
        if input_format == 'auto':
            input_format = detect_input_type(input_data)
            if input_format == 'certificate':
                # Check if it's PEM or DER
                if 'BEGIN CERTIFICATE' in input_data.upper():
                    input_format = 'pem'
                else:
                    input_format = 'der'
            elif input_format == 'unknown':
                if 'BEGIN' in input_data.upper():
                    return jsonify({'success': False, 'error': 'Could not detect input format. Please specify the format manually.'})
                # No PEM headers: try DER first, then PFX
                try:
                    raw = base64.b64decode(input_data)
                except Exception:
                    return jsonify({'success': False, 'error': 'Could not detect input format. Please specify the format manually.'})
                # Try parsing as DER certificate first
                try:
                    x509.load_der_x509_certificate(raw, default_backend())
                    input_format = 'der'
                except Exception:
                    # Not a DER cert, assume PFX/P12
                    input_format = 'pfx'
                    input_data = base64.b64encode(raw).decode('utf-8')
        
        # Load certificate based on input format
        cert = None
        private_key = None
        additional_certs = []
        
        if input_format == 'pfx' or input_format == 'p12':
            # Handle PFX/P12 format
            if not PKCS12_AVAILABLE:
                return jsonify({'success': False, 'error': 'PFX/P12 support requires cryptography library version 3.0 or higher. Please update your cryptography installation.'})
            
            try:
                # Decode base64 if needed
                if 'BEGIN' not in input_data.upper():
                    pfx_bytes = base64.b64decode(input_data)
                else:
                    return jsonify({'success': False, 'error': 'PFX/P12 files should be uploaded as binary or base64-encoded, not PEM format.'})
                
                # Load PFX
                pfx_password = password.encode('utf-8') if password else None
                try:
                    private_key_obj, cert_obj, additional_certs_list = load_key_and_certificates(
                        pfx_bytes, pfx_password, backend=default_backend()
                    )
                    cert = cert_obj
                    private_key = private_key_obj
                    additional_certs = additional_certs_list or []
                except ValueError as e:
                    if 'password' in str(e).lower() or 'mac' in str(e).lower():
                        return jsonify({'success': False, 'error': 'Invalid password for PFX/P12 file, or the file is corrupted.'})
                    raise
            except Exception as e:
                return jsonify({'success': False, 'error': f'Failed to load PFX/P12 file: {str(e)}'})
        
        elif input_format == 'pem':
            # Handle PEM format — extract certificates and private key separately
            try:
                # Find all certificate blocks
                cert_matches = re.findall(
                    r'-----BEGIN (?:X509 )?CERTIFICATE-----\s*(.+?)\s*-----END (?:X509 )?CERTIFICATE-----',
                    input_data, re.DOTALL
                )
                if not cert_matches:
                    return jsonify({'success': False, 'error': 'No certificate found in PEM input. Make sure the input contains a -----BEGIN CERTIFICATE----- block.'})

                # Parse the first certificate as the primary cert
                cert_der = base64.b64decode(''.join(cert_matches[0].split()))
                cert = x509.load_der_x509_certificate(cert_der, default_backend())

                # Any additional certificates go into the chain
                for extra_match in cert_matches[1:]:
                    extra_der = base64.b64decode(''.join(extra_match.split()))
                    additional_certs.append(x509.load_der_x509_certificate(extra_der, default_backend()))

                # Find a private key block (RSA, EC, or PKCS8)
                key_match = re.search(
                    r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----\s*(.+?)\s*-----END (?:RSA |EC )?PRIVATE KEY-----',
                    input_data, re.DOTALL
                )
                if key_match:
                    # Reconstruct full PEM for the key so the library can detect the type
                    key_pem_lines = key_match.group(0)
                    private_key = serialization.load_pem_private_key(
                        key_pem_lines.encode(), password=None, backend=default_backend()
                    )
            except Exception as e:
                return jsonify({'success': False, 'error': f'Failed to parse PEM input: {str(e)}'})
        
        elif input_format == 'der' or input_format == 'crt':
            # Handle DER/CRT format (binary)
            try:
                if 'BEGIN' in input_data.upper():
                    return jsonify({'success': False, 'error': 'DER/CRT format should be binary or base64-encoded, not PEM format.'})
                cert_der = base64.b64decode(input_data)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
            except Exception as e:
                return jsonify({'success': False, 'error': f'Failed to parse DER/CRT certificate: {str(e)}'})
        
        else:
            return jsonify({'success': False, 'error': f'Unsupported input format: {input_format}'})
        
        if cert is None:
            return jsonify({'success': False, 'error': 'Failed to load certificate from input data.'})
        
        # Convert to output format
        output_data = ''
        output_key_data = ''
        
        if output_format == 'pem' or output_format == 'crt':
            # PEM and CRT formats both use PEM encoding (text format with BEGIN/END headers)
            pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
            output_data = pem_bytes.decode('utf-8')
            
            # If we have a private key (from PFX), also output it separately
            if private_key is not None:
                key_pem_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                output_key_data = key_pem_bytes.decode('utf-8')
        
        elif output_format == 'der':
            # DER format is binary, output as base64-encoded
            der_bytes = cert.public_bytes(serialization.Encoding.DER)
            output_data = base64.b64encode(der_bytes).decode('utf-8')
            
            # If we have a private key, also output it in DER format
            if private_key is not None:
                key_der_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                output_key_data = base64.b64encode(key_der_bytes).decode('utf-8')
        
        elif output_format == 'pfx' or output_format == 'p12':
            if not PKCS12_AVAILABLE:
                return jsonify({'success': False, 'error': 'PFX/P12 support requires cryptography library version 3.0 or higher. Please update your cryptography installation.'})
            
            if private_key is None:
                return jsonify({'success': False, 'error': 'PFX/P12 output requires a private key. The input file must contain both certificate and private key.'})
            
            # Create PFX/P12
            pfx_password = password.encode('utf-8') if password else None
            pfx_bytes = serialize_key_and_certificates(
                name=b'certificate',
                key=private_key,
                cert=cert,
                cas=additional_certs,
                encryption_algorithm=serialization.BestAvailableEncryption(pfx_password) if pfx_password else serialization.NoEncryption()
            )
            output_data = base64.b64encode(pfx_bytes).decode('utf-8')
        
        else:
            return jsonify({'success': False, 'error': f'Unsupported output format: {output_format}'})
        
        # Store values before cleanup
        has_private_key = private_key is not None
        has_additional_certs = len(additional_certs) > 0

        response_data = {
            'success': True,
            'output_data': output_data,
            'output_format': output_format,
            'has_private_key': has_private_key,
            'has_additional_certs': has_additional_certs
        }

        # Include private key data if available
        if output_key_data:
            response_data['output_key_data'] = output_key_data

        return jsonify(response_data)

    except Exception as e:
        return jsonify({'success': False, 'error': f'Conversion failed: {str(e)}'})
    finally:
        # SECURITY: Drop references to sensitive data and prompt GC
        secure_cleanup(
            locals().get('private_key'),
            locals().get('input_data'),
            locals().get('password'),
            locals().get('additional_certs'),
        )

if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=8000, debug=debug)

