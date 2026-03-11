from flask import Flask, render_template, request, send_file, redirect, url_for, after_this_request, flash
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import os
import sqlite3
from datetime import datetime
import requests
import concurrent.futures
import asyncio
import time
import shutil
import env
import re
import platform
import tempfile

# Temporary folder for cross-platform compatibility
tempfile.tempdir = r'D:\vscode\discord-cloud-storage-master\python_tmp'

app = Flask(__name__)
app.secret_key = os.urandom(16)

DATABASE_FILE = env.DATABASE_FILE
WEBHOOK_URL = env.WEBHOOK_URL
FILE_PATH_SEP = '\\' if platform.system() == 'Windows' else '/'

UPLOAD_DIR = 'temp_upload'
CHUNK_DIR = 'temp_chunks'
DOWNLOAD_DIR = 'temp_download'

for d in [UPLOAD_DIR, CHUNK_DIR, DOWNLOAD_DIR]:
    os.makedirs(d, exist_ok=True)


def safe_filename(filename):
    """Sanitize filename to prevent directory traversal."""
    filename = os.path.basename(filename)
    filename = filename.replace('\x00', '')  # Remove null bytes
    return filename


def create_path(*args):
    """Create a safe OS-specific file path."""
    return FILE_PATH_SEP.join(args)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files.get('file')
        if file and file.filename:
            filename = safe_filename(file.filename)
            file_path = os.path.join(UPLOAD_DIR, filename)
            file.save(file_path)
            asyncio.run(process_file(file_path))

            # Clean temp directories after processing
            shutil.rmtree(CHUNK_DIR, ignore_errors=True)
            shutil.rmtree(UPLOAD_DIR, ignore_errors=True)
            os.makedirs(CHUNK_DIR, exist_ok=True)
            os.makedirs(UPLOAD_DIR, exist_ok=True)

    files_info = asyncio.run(fetch_file_information())
    return render_template('index.html', files_info=files_info)


def convert_bytes(byte_size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if byte_size < 1024.0:
            break
        byte_size /= 1024.0
    return f"{byte_size:.2f} {unit}"


def numerical_sort_key(filename):
    numbers = re.findall(r'\d+', filename)
    return int(numbers[0]) if numbers else 0


def decrypt_and_reassemble(chunk_filenames, output_file, key_hex):
    key = bytes.fromhex(key_hex)
    chunks = []

    for chunk_filename in sorted(chunk_filenames, key=numerical_sort_key):
        # Ensure chunk is inside CHUNK_DIR
        chunk_filename = os.path.join(CHUNK_DIR, safe_filename(os.path.basename(chunk_filename)))
        with open(chunk_filename, 'rb') as chunk_file:
            nonce = chunk_file.read(16)
            tag = chunk_file.read(16)
            ciphertext = chunk_file.read()
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        try:
            chunks.append(cipher.decrypt_and_verify(ciphertext, tag))
        except ValueError as e:
            print(f"Error during decryption: {e}")

    output_file_path = os.path.join(DOWNLOAD_DIR, safe_filename(output_file))
    with open(output_file_path, 'wb') as out_file:
        for chunk in chunks:
            out_file.write(chunk)
    print(f'Successfully decrypted and reassembled {output_file_path}.')


@app.route('/download/<int:file_id>', methods=['GET'])
def download_and_decrypt(file_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT file_name, chunk_list, key_hex FROM files WHERE id=?", (file_id,))
    result = cursor.fetchone()
    conn.close()
    if not result:
        return "File not found", 404

    file_name, chunk_list, key_hex = result
    chunks_urls = chunk_list.split(', ')
    downloaded_chunks = []

    # Download all chunks
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_index = {executor.submit(download_chunk, (i, url)): i for i, url in enumerate(chunks_urls)}
        for future in concurrent.futures.as_completed(future_to_index):
            index = future_to_index[future]
            try:
                res = future.result()
                if res[1]:
                    downloaded_chunks.append(res)
            except Exception as exc:
                print(f'Chunk download error: {exc}')

    decrypt_and_reassemble([chunk for i, chunk in sorted(downloaded_chunks)], file_name, key_hex)

    decrypted_file_path = os.path.join(DOWNLOAD_DIR, safe_filename(file_name))

    @after_this_request
    def cleanup(response):
        shutil.rmtree(CHUNK_DIR, ignore_errors=True)
        shutil.rmtree(DOWNLOAD_DIR, ignore_errors=True)
        os.makedirs(CHUNK_DIR, exist_ok=True)
        os.makedirs(DOWNLOAD_DIR, exist_ok=True)
        return response

    return send_file(decrypted_file_path, as_attachment=True)


def download_chunk(chunk_data):
    i, chunk_url = chunk_data
    response = requests.get(chunk_url)
    if response.status_code == 200:
        filename = f'chunk_{i + 1}.enc'
        filepath = os.path.join(CHUNK_DIR, filename)
        with open(filepath, 'wb') as f:
            f.write(response.content)
        return (i, filepath)
    return (i, None)


async def fetch_file_information():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, file_name, file_size, chunk_list FROM files")
    results = cursor.fetchall()
    conn.close()
    files_info = []
    for file_id, file_name, file_size, chunk_list in results:
        files_info.append({
            'id': file_id,
            'file_name': safe_filename(file_name),
            'formatted_size': convert_bytes(file_size),
            'chunk_amount': len(chunk_list.split(', '))
        })
    return files_info


async def process_file(file_path):
    # Enforce file_path is inside UPLOAD_DIR
    file_path = os.path.abspath(file_path)
    if not file_path.startswith(os.path.abspath(UPLOAD_DIR)):
        raise Exception("Invalid file path")

    key = get_random_bytes(16)
    key_hex = key.hex()
    split_and_encrypt(file_path, CHUNK_DIR, key)
    chunks_urls = upload_to_discord(CHUNK_DIR)
    save_to_database(file_path, chunks_urls, key_hex)


def split_and_encrypt(input_file, output_directory, key):
    chunk_size = 23 * 1024 * 1024
    with open(input_file, 'rb') as f:
        data = f.read()
    num_chunks = (len(data) + chunk_size - 1) // chunk_size
    os.makedirs(output_directory, exist_ok=True)

    for i in range(num_chunks):
        chunk = data[i * chunk_size:(i + 1) * chunk_size]
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(chunk)
        with open(os.path.join(output_directory, f'chunk_{i + 1}.enc'), 'wb') as f:
            f.write(cipher.nonce)
            f.write(tag)
            f.write(ciphertext)
    print(f'Successfully encrypted {num_chunks} chunks.')


def upload_to_discord(output_directory):
    chunks_paths = sorted(
        [os.path.join(output_directory, f) for f in os.listdir(output_directory) if f.endswith('.enc')],
        key=numerical_sort_key
    )
    urls = []
    for path in chunks_paths:
        urls.append(upload_chunk(path))
    return urls


def upload_chunk(chunk_path, max_retries=5):
    retry_count = 0
    while retry_count < max_retries:
        try:
            with open(chunk_path, 'rb') as f:
                response = requests.post(WEBHOOK_URL, files={'file': ('chunk.enc', f.read())}, data={'content': 'File Upload'})
                if response.status_code == 200:
                    return response.json()['attachments'][0]['url']
        except Exception as e:
            print(f"Upload error: {e}, retrying...")
            retry_count += 1
            time.sleep(1)
    return None


def save_to_database(input_file, chunks_urls, key_hex):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS files 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                       file_name TEXT, chunk_list TEXT, key_hex TEXT, file_size INTEGER, upload_date TEXT)''')
    cursor.execute("INSERT INTO files (file_name, chunk_list, key_hex, file_size, upload_date) VALUES (?, ?, ?, ?, ?)",
                   (safe_filename(os.path.basename(input_file)), ', '.join(chunks_urls), key_hex,
                    os.path.getsize(input_file), datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
