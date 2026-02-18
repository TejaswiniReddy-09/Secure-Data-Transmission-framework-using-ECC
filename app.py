import os
import sqlite3
import base64
import tempfile
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
import io
import numpy as np
import time
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import struct
import cv2
import binascii
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'ecc_steganography_secret_key_2024_secure'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['SENDER_UPLOAD_FOLDER'] = 'static/uploads/sender'
app.config['RECEIVER_UPLOAD_FOLDER'] = 'static/uploads/receiver'
app.config['ALLOWED_IMAGE_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'bmp'}
app.config['ALLOWED_VIDEO_EXTENSIONS'] = {'mp4', 'avi', 'mov', 'mkv'}
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Initialize database
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS operations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            operation_type TEXT,
            algorithm TEXT,
            file_type TEXT,
            file_size INTEGER,
            encryption_time REAL,
            decryption_time REAL,
            psnr_value REAL,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            algorithm TEXT,
            public_key TEXT,
            private_key TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

class ECCSteganography:
    def __init__(self, curve_type='curve25519'):
        self.curve_type = curve_type
        self.backend = default_backend()
    
    def generate_key_pair(self):
        """Generate ECC key pair"""
        try:
            if self.curve_type == 'curve25519':
                private_key = x25519.X25519PrivateKey.generate()
                public_key = private_key.public_key()
            else:
                private_key = ec.generate_private_key(ec.SECP256R1(), self.backend)
                public_key = private_key.public_key()
            return private_key, public_key
        except Exception as e:
            raise Exception(f"Key generation failed: {str(e)}")
    
    def serialize_public_key(self, public_key):
        """Serialize public key to bytes"""
        try:
            if self.curve_type == 'curve25519':
                return public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            else:
                return public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                )
        except Exception as e:
            raise Exception(f"Public key serialization failed: {str(e)}")
    
    def deserialize_public_key(self, key_bytes):
        """Deserialize public key from bytes"""
        try:
            if self.curve_type == 'curve25519':
                if len(key_bytes) != 32:
                    raise ValueError(f"X25519 public key must be 32 bytes, got {len(key_bytes)} bytes")
                return x25519.X25519PublicKey.from_public_bytes(key_bytes)
            else:
                if len(key_bytes) != 65:
                    raise ValueError(f"secp256r1 public key must be 65 bytes, got {len(key_bytes)} bytes")
                return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key_bytes)
        except Exception as e:
            raise Exception(f"Public key deserialization failed: {str(e)}")
    
    def serialize_private_key(self, private_key):
        """Serialize private key to bytes"""
        try:
            if self.curve_type == 'curve25519':
                return private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
            else:
                return private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
        except Exception as e:
            raise Exception(f"Private key serialization failed: {str(e)}")
    
    def deserialize_private_key(self, key_bytes):
        """Deserialize private key from bytes"""
        try:
            if self.curve_type == 'curve25519':
                if len(key_bytes) != 32:
                    raise ValueError(f"X25519 private key must be 32 bytes, got {len(key_bytes)} bytes")
                return x25519.X25519PrivateKey.from_private_bytes(key_bytes)
            else:
                return serialization.load_pem_private_key(key_bytes, password=None, backend=self.backend)
        except Exception as e:
            raise Exception(f"Private key deserialization failed: {str(e)}")
    
    def encrypt_data(self, public_key_bytes, data):
        """Encrypt data using ECC"""
        start_time = time.perf_counter()
        
        try:
            public_key = self.deserialize_public_key(public_key_bytes)
            
            if self.curve_type == 'curve25519':
                ephemeral_private = x25519.X25519PrivateKey.generate()
                ephemeral_public = ephemeral_private.public_key()
                shared_key = ephemeral_private.exchange(public_key)
            else:
                ephemeral_private = ec.generate_private_key(ec.SECP256R1(), self.backend)
                ephemeral_public = ephemeral_private.public_key()
                shared_key = ephemeral_private.exchange(ec.ECDH(), public_key)
            
            # Derive AES key
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'ecc_steganography',
                backend=self.backend
            ).derive(shared_key)
            
            # Encrypt data
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            
            # Add length prefix
            data_with_length = struct.pack('>I', len(data)) + data
            encrypted_data = encryptor.update(data_with_length) + encryptor.finalize()
            
            ephemeral_public_bytes = self.serialize_public_key(ephemeral_public)
            return ephemeral_public_bytes, iv + encrypted_data, time.perf_counter() - start_time
            
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_data(self, private_key, encrypted_data_with_public_key):
        """Decrypt data using ECC"""
        start_time = time.perf_counter()
        
        try:
            pub_key_len = 32 if self.curve_type == 'curve25519' else 65
            ephemeral_public_bytes = encrypted_data_with_public_key[:pub_key_len]
            encrypted_data = encrypted_data_with_public_key[pub_key_len:]
            
            ephemeral_public = self.deserialize_public_key(ephemeral_public_bytes)
            
            # Generate shared key
            if self.curve_type == 'curve25519':
                shared_key = private_key.exchange(ephemeral_public)
            else:
                shared_key = private_key.exchange(ec.ECDH(), ephemeral_public)
            
            # Derive AES key
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'ecc_steganography',
                backend=self.backend
            ).derive(shared_key)
            
            # Decrypt data
            iv = encrypted_data[:16]
            cipher_text = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()
            
            # Extract original data
            data_length = struct.unpack('>I', decrypted_data[:4])[0]
            original_data = decrypted_data[4:4+data_length]
            
            return original_data, time.perf_counter() - start_time
            
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

class TextSteganography(ECCSteganography):
    def hide_text_in_image(self, cover_image_path, text, public_key_bytes, output_path):
        """Hide encrypted text in image"""
        try:
            # Encrypt the text
            text_bytes = text.encode('utf-8')
            ephemeral_public_bytes, encrypted_data, enc_time = self.encrypt_data(public_key_bytes, text_bytes)
            
            # Combine public key and encrypted data
            combined_data = ephemeral_public_bytes + encrypted_data
            
            # Add end marker
            end_marker = b'ENDOFDATA'
            combined_data += end_marker
            
            # Convert to bits
            bits = ''.join(format(byte, '08b') for byte in combined_data)
            
            # Load cover image
            cover_img = Image.open(cover_image_path).convert('RGB')
            cover_pixels = np.array(cover_img)
            
            # Check capacity
            available_bits = cover_pixels.size
            required_bits = len(bits)
            
            if required_bits > available_bits:
                raise ValueError(f"Cover image too small. Needs {required_bits} bits but only {available_bits} available")
            
            # Embed in cover image using LSB
            flat = cover_pixels.flatten()
            for i in range(len(bits)):
                flat[i] = (flat[i] & 0xFE) | int(bits[i])
            
            # Save stego image
            stego_img = Image.fromarray(flat.reshape(cover_pixels.shape))
            stego_img.save(output_path)
            
            return enc_time
            
        except Exception as e:
            raise Exception(f"Text hiding failed: {str(e)}")
    
    def extract_text_from_image(self, stego_image_path, private_key):
        """Extract and decrypt text from image"""
        try:
            # Load stego image
            stego_img = Image.open(stego_image_path).convert('RGB')
            pixels = np.array(stego_img)
            flat = pixels.flatten()
            
            # Extract bits until we find the end marker
            extracted_bits = []
            end_marker_bits = ''.join(format(byte, '08b') for byte in b'ENDOFDATA')
            end_marker_len = len(end_marker_bits)
            
            for i, pixel in enumerate(flat):
                extracted_bits.append(str(pixel & 1))
                
                # Check for end marker
                if len(extracted_bits) >= end_marker_len:
                    recent_bits = ''.join(extracted_bits[-end_marker_len:])
                    if recent_bits == end_marker_bits:
                        extracted_bits = extracted_bits[:-end_marker_len]
                        break
            
            # Convert bits to bytes
            extracted_bytes = bytearray()
            for i in range(0, len(extracted_bits), 8):
                if i + 8 <= len(extracted_bits):
                    byte_bits = ''.join(extracted_bits[i:i+8])
                    extracted_bytes.append(int(byte_bits, 2))
            
            # Decrypt
            decrypted_data, dec_time = self.decrypt_data(private_key, bytes(extracted_bytes))
            
            # Convert to text
            text = decrypted_data.decode('utf-8')
            return text, dec_time
            
        except Exception as e:
            raise Exception(f"Text extraction failed: {str(e)}")

class ImageSteganography(ECCSteganography):
    def image_to_bytes(self, image):
        """Convert PIL Image to bytes"""
        img_byte_arr = io.BytesIO()
        image.save(img_byte_arr, format='PNG')
        return img_byte_arr.getvalue()
    
    def bytes_to_image(self, image_bytes):
        """Convert bytes to PIL Image"""
        try:
            img = Image.open(io.BytesIO(image_bytes))
            img.verify()
            img = Image.open(io.BytesIO(image_bytes))
            return img
        except Exception as e:
            raise ValueError(f"Invalid image data: {str(e)}")
    
    def hide_image_in_image(self, cover_image_path, secret_image_path, public_key_bytes, output_path):
        """Hide encrypted image in another image"""
        try:
            # Load and convert secret image to bytes
            secret_img = Image.open(secret_image_path).convert('RGB')
            secret_bytes = self.image_to_bytes(secret_img)
            
            # Encrypt the image data
            ephemeral_public_bytes, encrypted_data, enc_time = self.encrypt_data(public_key_bytes, secret_bytes)
            
            # Combine public key and encrypted data
            combined_data = ephemeral_public_bytes + encrypted_data
            
            # Add size prefix and end marker
            data_size = struct.pack('>I', len(combined_data))
            end_marker = b'IMGEND'
            full_data = data_size + combined_data + end_marker
            
            # Convert to bits
            bits = ''.join(format(byte, '08b') for byte in full_data)
            
            # Load cover image
            cover_img = Image.open(cover_image_path).convert('RGB')
            cover_pixels = np.array(cover_img)
            
            # Check capacity
            available_bits = cover_pixels.size
            required_bits = len(bits)
            
            if required_bits > available_bits:
                raise ValueError(f"Cover image too small. Needs {required_bits} bits but only {available_bits} available")
            
            # Embed in cover image
            flat = cover_pixels.flatten()
            for i in range(len(bits)):
                flat[i] = (flat[i] & 0xFE) | int(bits[i])
            
            # Save stego image
            stego_img = Image.fromarray(flat.reshape(cover_pixels.shape))
            stego_img.save(output_path)
            
            return enc_time
            
        except Exception as e:
            raise Exception(f"Image hiding failed: {str(e)}")
    
    def extract_image_from_image(self, stego_image_path, private_key):
        """Extract and decrypt image from stego image"""
        try:
            # Load stego image
            stego_img = Image.open(stego_image_path).convert('RGB')
            pixels = np.array(stego_img)
            flat = pixels.flatten()
            
            # Extract size information first
            size_bits = ''.join(str(pixel & 1) for pixel in flat[:32])
            if len(size_bits) != 32:
                raise ValueError("Could not extract size information")
                
            size_bytes = bytes(int(size_bits[i:i+8], 2) for i in range(0, 32, 8))
            data_size = struct.unpack('>I', size_bytes)[0]
            
            # Extract the actual data bits
            extracted_bits = []
            bits_extracted = 0
            target_bits = (data_size + len(b'IMGEND')) * 8
            
            for i in range(32, len(flat)):
                if bits_extracted >= target_bits:
                    break
                extracted_bits.append(str(flat[i] & 1))
                bits_extracted += 1
            
            if len(extracted_bits) < target_bits:
                raise ValueError(f"Not enough bits extracted. Got {len(extracted_bits)}, needed {target_bits}")
            
            # Convert bits to bytes
            extracted_bytes = bytearray()
            for i in range(0, len(extracted_bits), 8):
                if i + 8 <= len(extracted_bits):
                    byte_bits = ''.join(extracted_bits[i:i+8])
                    extracted_bytes.append(int(byte_bits, 2))
            
            # Find and remove end marker
            extracted_bytes = bytes(extracted_bytes)
            end_marker_index = extracted_bytes.find(b'IMGEND')
            if end_marker_index == -1:
                raise ValueError("End marker not found in extracted data")
            
            encrypted_data_with_key = extracted_bytes[:end_marker_index]
            
            # Decrypt
            decrypted_data, dec_time = self.decrypt_data(private_key, encrypted_data_with_key)
            
            # Convert back to image
            secret_img = self.bytes_to_image(decrypted_data)
            
            return secret_img, dec_time
            
        except Exception as e:
            raise Exception(f"Image extraction failed: {str(e)}")

class VideoSteganography(ECCSteganography):
    def hide_video_in_video(self, cover_video_path, secret_video_path, public_key_bytes, output_path):
        """Hide encrypted video in another video"""
        start_time = time.perf_counter()
        
        try:
            # Read secret video
            with open(secret_video_path, 'rb') as f:
                secret_video_data = f.read()
            
            # Encrypt the video data
            ephemeral_public_bytes, encrypted_data, enc_time = self.encrypt_data(public_key_bytes, secret_video_data)
            
            # Combine public key and encrypted data with size prefix
            combined_data = ephemeral_public_bytes + encrypted_data
            data_size = struct.pack('>Q', len(combined_data))
            end_marker = b'VIDEND'
            full_data = data_size + combined_data + end_marker
            
            # Convert to bits
            bits = ''.join(format(byte, '08b') for byte in full_data)
            total_bits = len(bits)
            
            # Open cover video
            cap = cv2.VideoCapture(cover_video_path)
            fps = cap.get(cv2.CAP_PROP_FPS)
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            
            # Setup video writer
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
            
            bit_index = 0
            frame_count = 0
            
            while bit_index < total_bits and cap.isOpened():
                ret, frame = cap.read()
                if not ret:
                    break
                
                # Embed bits in frame
                flat_frame = frame.flatten()
                frame_capacity = len(flat_frame)
                bits_to_embed = min(frame_capacity, total_bits - bit_index)
                
                for i in range(bits_to_embed):
                    flat_frame[i] = (flat_frame[i] & 0xFE) | int(bits[bit_index])
                    bit_index += 1
                
                # Reshape and write frame
                stego_frame = flat_frame.reshape(frame.shape)
                out.write(stego_frame)
                frame_count += 1
            
            # Write remaining frames without modification
            while cap.isOpened():
                ret, frame = cap.read()
                if not ret:
                    break
                out.write(frame)
                frame_count += 1
            
            cap.release()
            out.release()
            
            total_time = time.perf_counter() - start_time
            return total_time
            
        except Exception as e:
            raise Exception(f"Video hiding failed: {str(e)}")
    
    def extract_video_from_video(self, stego_video_path, private_key, output_path):
        """Extract and decrypt video from stego video"""
        start_time = time.perf_counter()
        
        try:
            # Open stego video
            cap = cv2.VideoCapture(stego_video_path)
            if not cap.isOpened():
                raise ValueError("Could not open stego video file")
            
            # Extract size first
            size_bits = []
            frames_processed = 0
            max_frames_for_size = 50
            
            while len(size_bits) < 64 and cap.isOpened() and frames_processed < max_frames_for_size:
                ret, frame = cap.read()
                if not ret:
                    break
                
                flat_frame = frame.flatten()
                for pixel in flat_frame:
                    size_bits.append(str(pixel & 1))
                    if len(size_bits) >= 64:
                        break
                frames_processed += 1
            
            if len(size_bits) < 64:
                raise ValueError(f"Could not extract complete size information. Got {len(size_bits)} bits, needed 64")
            
            # Convert size bits to bytes
            size_bytes = bytearray()
            for i in range(0, 64, 8):
                byte_bits = ''.join(size_bits[i:i+8])
                if byte_bits:
                    size_bytes.append(int(byte_bits, 2))
            
            # Get data size
            data_size = struct.unpack('>Q', bytes(size_bytes))[0]
            
            # Reset video capture to beginning
            cap.release()
            cap = cv2.VideoCapture(stego_video_path)
            
            # Skip frames used for size
            for _ in range(frames_processed):
                cap.read()
            
            # Extract remaining data
            extracted_bits = []
            end_marker = b'VIDEND'
            end_marker_bits = ''.join(format(byte, '08b') for byte in end_marker)
            total_bits_needed = (data_size + len(end_marker)) * 8
            
            frames_processed_data = 0
            max_data_frames = 1000
            
            while len(extracted_bits) < total_bits_needed and cap.isOpened() and frames_processed_data < max_data_frames:
                ret, frame = cap.read()
                if not ret:
                    break
                
                flat_frame = frame.flatten()
                for pixel in flat_frame:
                    extracted_bits.append(str(pixel & 1))
                    if len(extracted_bits) >= total_bits_needed:
                        break
                
                frames_processed_data += 1
            
            cap.release()
            
            if len(extracted_bits) < total_bits_needed:
                total_bits_needed = min(len(extracted_bits), total_bits_needed)
            
            # Convert bits to bytes
            extracted_bytes = bytearray()
            bit_index = 0
            
            while bit_index < total_bits_needed:
                if bit_index + 8 <= len(extracted_bits):
                    byte_bits = ''.join(extracted_bits[bit_index:bit_index+8])
                    if byte_bits:
                        extracted_bytes.append(int(byte_bits, 2))
                    bit_index += 8
                else:
                    break
            
            # Remove size prefix
            if len(extracted_bytes) >= 8:
                extracted_bytes = extracted_bytes[8:]
            else:
                raise ValueError("Not enough data extracted after removing size prefix")
            
            # Find and remove end marker
            extracted_bytes = bytes(extracted_bytes)
            end_marker_index = extracted_bytes.find(b'VIDEND')
            
            if end_marker_index == -1:
                encrypted_data_with_key = extracted_bytes
            else:
                encrypted_data_with_key = extracted_bytes[:end_marker_index]
            
            # Verify we have enough data
            if len(encrypted_data_with_key) < (32 if self.curve_type == 'curve25519' else 65):
                raise ValueError(f"Not enough data for decryption. Got {len(encrypted_data_with_key)} bytes")
            
            # Decrypt
            decrypted_data, dec_time = self.decrypt_data(private_key, encrypted_data_with_key)
            
            # Save decrypted video
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            total_time = time.perf_counter() - start_time
            return total_time
            
        except Exception as e:
            raise Exception(f"Video extraction failed: {str(e)}")

# Utility Functions
def allowed_file(filename, file_type='image'):
    if file_type == 'image':
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_IMAGE_EXTENSIONS']
    elif file_type == 'video':
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_VIDEO_EXTENSIONS']
    return False

def validate_base64(key_string):
    """Validate and clean Base64 key string"""
    try:
        cleaned_key = key_string.strip().replace(' ', '').replace('\n', '').replace('\r', '')
        
        # Add padding if needed
        padding = 4 - (len(cleaned_key) % 4)
        if padding != 4:
            cleaned_key += '=' * padding
            
        # Test decoding
        decoded = base64.b64decode(cleaned_key)
        return cleaned_key, decoded
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"Invalid Base64 key format: {str(e)}")

def save_operation(user_id, operation_type, algorithm, file_type, file_size, encryption_time, decryption_time, psnr_value, status):
    """Save operation details to database"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO operations (user_id, operation_type, algorithm, file_type, file_size, 
                              encryption_time, decryption_time, psnr_value, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, operation_type, algorithm, file_type, file_size, 
          encryption_time, decryption_time, psnr_value, status))
    conn.commit()
    conn.close()

def get_user_id(username):
    """Get user ID from username"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user[0] if user else None

# Routes
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['username'] = username
            session['user_id'] = user[0]
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                          (username, generate_password_hash(password), email))
            conn.commit()
            conn.close()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('Username or email already exists', 'danger')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    return render_template('dashboard.html')

# Sender Routes
@app.route('/sender/dashboard')
def sender_dashboard():
    if 'username' not in session:
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    return render_template('sender/sender_dashboard.html')

@app.route('/sender/text_image', methods=['GET', 'POST'])
def sender_text_image():
    if 'username' not in session:
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            if 'cover_image' not in request.files:
                flash('Cover image is required', 'danger')
                return redirect(request.url)
            
            cover_file = request.files['cover_image']
            text = request.form.get('secret_text', '')
            public_key_input = request.form.get('receiver_public_key', '')
            algorithm = request.form.get('algorithm', 'curve25519')
            
            if cover_file.filename == '':
                flash('No cover image selected', 'danger')
                return redirect(request.url)
            
            if not text.strip():
                flash('Secret text is required', 'danger')
                return redirect(request.url)
            
            if not public_key_input.strip():
                flash('Receiver public key is required', 'danger')
                return redirect(request.url)
            
            if not allowed_file(cover_file.filename, 'image'):
                flash('Invalid image file type', 'danger')
                return redirect(request.url)
            
            # Validate and process public key
            try:
                public_key_cleaned, public_key_bytes = validate_base64(public_key_input)
            except ValueError as e:
                flash(str(e), 'danger')
                return redirect(request.url)
            
            # Save cover image
            cover_filename = secure_filename(cover_file.filename)
            cover_path = os.path.join(app.config['SENDER_UPLOAD_FOLDER'], cover_filename)
            cover_file.save(cover_path)
            
            # Generate output filename
            output_filename = f"stego_text_{algorithm}_{int(time.time())}.png"
            output_path = os.path.join(app.config['SENDER_UPLOAD_FOLDER'], output_filename)
            
            # Hide text
            text_steg = TextSteganography(algorithm)
            enc_time = text_steg.hide_text_in_image(cover_path, text, public_key_bytes, output_path)
            
            # Save operation to database
            user_id = get_user_id(session['username'])
            save_operation(user_id, 'encrypt', algorithm, 'text_image', 
                          os.path.getsize(output_path), enc_time, 0, 0, 'success')
            
            flash('Text encrypted and hidden successfully!', 'success')
            return render_template('sender/text_image_sender.html', 
                                 cover_image=cover_filename,
                                 stego_image=output_filename,
                                 enc_time=enc_time,
                                 algorithm=algorithm)
            
        except Exception as e:
            flash(f'Error during encryption: {str(e)}', 'danger')
            return redirect(request.url)
    
    return render_template('sender/text_image_sender.html')

@app.route('/sender/image_image', methods=['GET', 'POST'])
def sender_image_image():
    if 'username' not in session:
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            if 'cover_image' not in request.files or 'secret_image' not in request.files:
                flash('Both cover and secret images are required', 'danger')
                return redirect(request.url)
            
            cover_file = request.files['cover_image']
            secret_file = request.files['secret_image']
            public_key_input = request.form.get('receiver_public_key', '')
            algorithm = request.form.get('algorithm', 'curve25519')
            
            if cover_file.filename == '' or secret_file.filename == '':
                flash('Both images must be selected', 'danger')
                return redirect(request.url)
            
            if not public_key_input.strip():
                flash('Receiver public key is required', 'danger')
                return redirect(request.url)
            
            if not (allowed_file(cover_file.filename, 'image') and allowed_file(secret_file.filename, 'image')):
                flash('Invalid image file type', 'danger')
                return redirect(request.url)
            
            # Validate and process public key
            try:
                public_key_cleaned, public_key_bytes = validate_base64(public_key_input)
            except ValueError as e:
                flash(str(e), 'danger')
                return redirect(request.url)
            
            # Save images
            cover_filename = secure_filename(cover_file.filename)
            secret_filename = secure_filename(secret_file.filename)
            cover_path = os.path.join(app.config['SENDER_UPLOAD_FOLDER'], cover_filename)
            secret_path = os.path.join(app.config['SENDER_UPLOAD_FOLDER'], secret_filename)
            
            cover_file.save(cover_path)
            secret_file.save(secret_path)
            
            # Generate output filename
            output_filename = f"stego_image_{algorithm}_{int(time.time())}.png"
            output_path = os.path.join(app.config['SENDER_UPLOAD_FOLDER'], output_filename)
            
            # Hide image
            image_steg = ImageSteganography(algorithm)
            enc_time = image_steg.hide_image_in_image(cover_path, secret_path, public_key_bytes, output_path)
            
            # Save operation to database
            user_id = get_user_id(session['username'])
            save_operation(user_id, 'encrypt', algorithm, 'image_image', 
                          os.path.getsize(output_path), enc_time, 0, 0, 'success')
            
            flash('Image encrypted and hidden successfully!', 'success')
            return render_template('sender/image_image_sender.html',
                                 cover_image=cover_filename,
                                 secret_image=secret_filename,
                                 stego_image=output_filename,
                                 enc_time=enc_time,
                                 algorithm=algorithm)
            
        except Exception as e:
            flash(f'Error during encryption: {str(e)}', 'danger')
            return redirect(request.url)
    
    return render_template('sender/image_image_sender.html')

@app.route('/sender/video', methods=['GET', 'POST'])
def sender_video():
    if 'username' not in session:
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            if 'cover_video' not in request.files or 'secret_video' not in request.files:
                flash('Both cover and secret videos are required', 'danger')
                return redirect(request.url)
            
            cover_file = request.files['cover_video']
            secret_file = request.files['secret_video']
            public_key_input = request.form.get('receiver_public_key', '')
            algorithm = request.form.get('algorithm', 'curve25519')
            
            if cover_file.filename == '' or secret_file.filename == '':
                flash('Both videos must be selected', 'danger')
                return redirect(request.url)
            
            if not public_key_input.strip():
                flash('Receiver public key is required', 'danger')
                return redirect(request.url)
            
            if not (allowed_file(cover_file.filename, 'video') and allowed_file(secret_file.filename, 'video')):
                flash('Invalid video file type', 'danger')
                return redirect(request.url)
            
            # Validate and process public key
            try:
                public_key_cleaned, public_key_bytes = validate_base64(public_key_input)
            except ValueError as e:
                flash(str(e), 'danger')
                return redirect(request.url)
            
            # Save videos
            cover_filename = secure_filename(cover_file.filename)
            secret_filename = secure_filename(secret_file.filename)
            cover_path = os.path.join(app.config['SENDER_UPLOAD_FOLDER'], cover_filename)
            secret_path = os.path.join(app.config['SENDER_UPLOAD_FOLDER'], secret_filename)
            
            cover_file.save(cover_path)
            secret_file.save(secret_path)
            
            # Generate output filename
            output_filename = f"stego_video_{algorithm}_{int(time.time())}.mp4"
            output_path = os.path.join(app.config['SENDER_UPLOAD_FOLDER'], output_filename)
            
            # Hide video
            video_steg = VideoSteganography(algorithm)
            enc_time = video_steg.hide_video_in_video(cover_path, secret_path, public_key_bytes, output_path)
            
            # Save operation to database
            user_id = get_user_id(session['username'])
            save_operation(user_id, 'encrypt', algorithm, 'video', 
                          os.path.getsize(output_path), enc_time, 0, 0, 'success')
            
            flash('Video encrypted and hidden successfully!', 'success')
            return render_template('sender/video_sender.html',
                                 cover_video=cover_filename,
                                 secret_video=secret_filename,
                                 stego_video=output_filename,
                                 enc_time=enc_time,
                                 algorithm=algorithm)
            
        except Exception as e:
            flash(f'Error during encryption: {str(e)}', 'danger')
            return redirect(request.url)
    
    return render_template('sender/video_sender.html')

# Receiver Routes
@app.route('/receiver/dashboard')
def receiver_dashboard():
    if 'username' not in session:
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    return render_template('receiver/receiver_dashboard.html')

@app.route('/receiver/text_image', methods=['GET', 'POST'])
def receiver_text_image():
    if 'username' not in session:
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            if 'stego_image' not in request.files:
                flash('Stego image is required', 'danger')
                return redirect(request.url)
            
            stego_file = request.files['stego_image']
            private_key_input = request.form.get('private_key', '')
            algorithm = request.form.get('algorithm', 'curve25519')
            
            if stego_file.filename == '':
                flash('No stego image selected', 'danger')
                return redirect(request.url)
            
            if not private_key_input.strip():
                flash('Private key is required', 'danger')
                return redirect(request.url)
            
            # Validate and process private key
            try:
                private_key_cleaned, private_key_bytes = validate_base64(private_key_input)
            except ValueError as e:
                flash(str(e), 'danger')
                return redirect(request.url)
            
            # Save stego image
            stego_filename = secure_filename(stego_file.filename)
            stego_path = os.path.join(app.config['RECEIVER_UPLOAD_FOLDER'], stego_filename)
            stego_file.save(stego_path)
            
            # Create steganography instance and deserialize private key
            text_steg = TextSteganography(algorithm)
            private_key = text_steg.deserialize_private_key(private_key_bytes)
            
            # Extract text
            extracted_text, dec_time = text_steg.extract_text_from_image(stego_path, private_key)
            
            # Save operation to database
            user_id = get_user_id(session['username'])
            save_operation(user_id, 'decrypt', algorithm, 'text_image', 
                          os.path.getsize(stego_path), 0, dec_time, 0, 'success')
            
            flash('Text decrypted successfully!', 'success')
            return render_template('receiver/text_image_receiver.html',
                                 stego_image=stego_filename,
                                 extracted_text=extracted_text,
                                 dec_time=dec_time,
                                 algorithm=algorithm)
            
        except Exception as e:
            flash(f'Error during decryption: {str(e)}', 'danger')
            return redirect(request.url)
    
    return render_template('receiver/text_image_receiver.html')

@app.route('/receiver/image_image', methods=['GET', 'POST'])
def receiver_image_image():
    if 'username' not in session:
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            if 'stego_image' not in request.files:
                flash('Stego image is required', 'danger')
                return redirect(request.url)
            
            stego_file = request.files['stego_image']
            private_key_input = request.form.get('private_key', '')
            algorithm = request.form.get('algorithm', 'curve25519')
            
            if stego_file.filename == '':
                flash('No stego image selected', 'danger')
                return redirect(request.url)
            
            if not private_key_input.strip():
                flash('Private key is required', 'danger')
                return redirect(request.url)
            
            # Validate and process private key
            try:
                private_key_cleaned, private_key_bytes = validate_base64(private_key_input)
            except ValueError as e:
                flash(str(e), 'danger')
                return redirect(request.url)
            
            # Save stego image
            stego_filename = secure_filename(stego_file.filename)
            stego_path = os.path.join(app.config['RECEIVER_UPLOAD_FOLDER'], stego_filename)
            stego_file.save(stego_path)
            
            # Create steganography instance and deserialize private key
            image_steg = ImageSteganography(algorithm)
            private_key = image_steg.deserialize_private_key(private_key_bytes)
            
            # Extract image
            extracted_image, dec_time = image_steg.extract_image_from_image(stego_path, private_key)
            
            # Save extracted image
            extracted_filename = f"extracted_{algorithm}_{int(time.time())}.png"
            extracted_path = os.path.join(app.config['RECEIVER_UPLOAD_FOLDER'], extracted_filename)
            extracted_image.save(extracted_path)
            
            # Save operation to database
            user_id = get_user_id(session['username'])
            save_operation(user_id, 'decrypt', algorithm, 'image_image', 
                          os.path.getsize(stego_path), 0, dec_time, 0, 'success')
            
            flash('Image decrypted successfully!', 'success')
            return render_template('receiver/image_image_receiver.html',
                                 stego_image=stego_filename,
                                 extracted_image=extracted_filename,
                                 dec_time=dec_time,
                                 algorithm=algorithm)
            
        except Exception as e:
            flash(f'Error during decryption: {str(e)}', 'danger')
            return redirect(request.url)
    
    return render_template('receiver/image_image_receiver.html')

@app.route('/receiver/video', methods=['GET', 'POST'])
def receiver_video():
    if 'username' not in session:
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            if 'stego_video' not in request.files:
                flash('Stego video is required', 'danger')
                return redirect(request.url)
            
            stego_file = request.files['stego_video']
            private_key_input = request.form.get('private_key', '')
            algorithm = request.form.get('algorithm', 'curve25519')
            
            if stego_file.filename == '':
                flash('No stego video selected', 'danger')
                return redirect(request.url)
            
            if not private_key_input.strip():
                flash('Private key is required', 'danger')
                return redirect(request.url)
            
            # Validate and process private key
            try:
                private_key_cleaned, private_key_bytes = validate_base64(private_key_input)
            except ValueError as e:
                flash(str(e), 'danger')
                return redirect(request.url)
            
            # Save stego video
            stego_filename = secure_filename(stego_file.filename)
            stego_path = os.path.join(app.config['RECEIVER_UPLOAD_FOLDER'], stego_filename)
            stego_file.save(stego_path)
            
            # Create steganography instance and deserialize private key
            video_steg = VideoSteganography(algorithm)
            private_key = video_steg.deserialize_private_key(private_key_bytes)
            
            # Generate output filename
            output_filename = f"extracted_video_{algorithm}_{int(time.time())}.mp4"
            output_path = os.path.join(app.config['RECEIVER_UPLOAD_FOLDER'], output_filename)
            
            # Extract video
            dec_time = video_steg.extract_video_from_video(stego_path, private_key, output_path)
            
            # Save operation to database
            user_id = get_user_id(session['username'])
            save_operation(user_id, 'decrypt', algorithm, 'video', 
                          os.path.getsize(stego_path), 0, dec_time, 0, 'success')
            
            flash('Video decrypted successfully!', 'success')
            return render_template('receiver/video_receiver.html',
                                 stego_video=stego_filename,
                                 extracted_video=output_filename,
                                 dec_time=dec_time,
                                 algorithm=algorithm)
            
        except Exception as e:
            flash(f'Error during decryption: {str(e)}', 'danger')
            return redirect(request.url)
    
    return render_template('receiver/video_receiver.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    """Generate ECC key pairs"""
    try:
        algorithm = request.json.get('algorithm', 'curve25519')
        
        steg = ECCSteganography(algorithm)
        private_key, public_key = steg.generate_key_pair()
        
        # Serialize keys
        private_key_bytes = steg.serialize_private_key(private_key)
        public_key_bytes = steg.serialize_public_key(public_key)
        
        # Encode to Base64
        private_key_b64 = base64.b64encode(private_key_bytes).decode('utf-8')
        public_key_b64 = base64.b64encode(public_key_bytes).decode('utf-8')
        
        # Save keys to database if user is logged in
        if 'username' in session:
            user_id = get_user_id(session['username'])
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO user_keys (user_id, algorithm, public_key, private_key)
                VALUES (?, ?, ?, ?)
            ''', (user_id, algorithm, public_key_b64, private_key_b64))
            conn.commit()
            conn.close()
        
        return jsonify({
            'private_key': private_key_b64,
            'public_key': public_key_b64,
            'algorithm': algorithm,
            'key_sizes': {
                'private_key_bytes': len(private_key_bytes),
                'public_key_bytes': len(public_key_bytes)
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_operations')
def get_operations():
    """Get user operations for charts"""
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user_id = get_user_id(session['username'])
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT algorithm, operation_type, AVG(encryption_time), AVG(decryption_time), COUNT(*)
        FROM operations 
        WHERE user_id = ? 
        GROUP BY algorithm, operation_type
    ''', (user_id,))
    operations = cursor.fetchall()
    conn.close()
    
    data = {
        'algorithms': [],
        'encryption_times': [],
        'decryption_times': [],
        'operation_counts': []
    }
    
    for op in operations:
        data['algorithms'].append(f"{op[0]}_{op[1]}")
        data['encryption_times'].append(op[2] or 0)
        data['decryption_times'].append(op[3] or 0)
        data['operation_counts'].append(op[4])
    
    return jsonify(data)

@app.route('/uploads/sender/<filename>')
def uploaded_sender_file(filename):
    return send_from_directory(app.config['SENDER_UPLOAD_FOLDER'], filename)

@app.route('/uploads/receiver/<filename>')
def uploaded_receiver_file(filename):
    return send_from_directory(app.config['RECEIVER_UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['SENDER_UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['RECEIVER_UPLOAD_FOLDER'], exist_ok=True)
    app.run()