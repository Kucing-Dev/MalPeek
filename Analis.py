import os
import hashlib
import re
import string

def calculate_hashes(file_path):
    hashes = {
        'MD5': hashlib.md5(),
        'SHA1': hashlib.sha1(),
        'SHA256': hashlib.sha256(),
    }

    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            for h in hashes.values():
                h.update(chunk)

    return {name: h.hexdigest() for name, h in hashes.items()}

def extract_ascii_strings(file_path, min_length=4):
    with open(file_path, 'rb') as f:
        data = f.read()

    result = []
    current = b''

    for byte in data:
        if chr(byte) in string.printable:
            current += bytes([byte])
        else:
            if len(current) >= min_length:
                result.append(current.decode('ascii', errors='ignore'))
            current = b''

    # Tangkap string terakhir jika valid
    if len(current) >= min_length:
        result.append(current.decode('ascii', errors='ignore'))

    return result

def extract_unicode_strings(file_path, min_length=4):
    with open(file_path, 'rb') as f:
        data = f.read()

    pattern = re.compile((b'(?:[%s]\x00){%d,}' % (bytes(string.printable, 'ascii'), min_length)))
    matches = pattern.findall(data)

    return [m.decode('utf-16le', errors='ignore') for m in matches]

def scan_suspicious_patterns(strings):
    suspicious_keywords = [
        'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
        'GetProcAddress', 'LoadLibrary', 'WinExec', 'ShellExecute',
        'RegSetValue', 'SetWindowsHook', 'GetAsyncKeyState',
        'InternetOpen', 'HttpSendRequest', 'Connect', 'Socket',
        'cmd.exe', 'powershell', 'user32.dll', 'kernel32.dll'
    ]

    flagged = [s for s in strings if any(keyword.lower() in s.lower() for keyword in suspicious_keywords)]
    return flagged

def main():
    file_path = input("Path ke file .exe: ").strip()

    if not os.path.exists(file_path):
        print("❌ File tidak ditemukan.")
        return

    print("\n🔒 Menghitung Hash...")
    hashes = calculate_hashes(file_path)
    for name, value in hashes.items():
        print(f"{name}: {value}")

    print("\n📄 Mengekstrak Strings...")
    ascii_strings = extract_ascii_strings(file_path)
    unicode_strings = extract_unicode_strings(file_path)
    all_strings = ascii_strings + unicode_strings
    print(f"Total strings ditemukan: {len(all_strings)}")

    print("\n🧪 Memindai pola mencurigakan...")
    flagged = scan_suspicious_patterns(all_strings)
    if flagged:
        print(f"Ditemukan {len(flagged)} string mencurigakan:")
        for s in flagged:
            print(f"  ⚠️  {s}")
    else:
        print("✅ Tidak ditemukan string mencurigakan yang umum.")

    print("\n✅ Analisis selesai.")

if __name__ == "__main__":
    main()
