"""Write the synthetic Preboot tree for make-preboot.sh into a mounted volume."""
import hashlib, os, sys

root = sys.argv[1]
GROUP = "A304C51B-D22F-4CDD-829D-3E30CB5BD87B"


def der(tag, value):
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    length = len(value).to_bytes(4, "big").lstrip(b"\0")
    return bytes([tag, 0x80 | len(length)]) + length + value


def im4p(kind, payload):
    return der(0x30, der(0x16, b"IM4P") + der(0x16, kind) + der(0x16, b"synthetic") + der(0x04, payload))


# A synthetic manifest: only its shape is real.
MANIFEST = der(0x30, der(0x16, b"IM4M") + der(0x02, b"\0") + der(0x31, b"") + der(0x04, b"\xaa" * 4) + der(0x30, b""))


def img4(kind, payload):
    return der(0x30, der(0x16, b"IMG4") + im4p(kind, payload) + der(0xa0, MANIFEST))


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


pattern = bytes((i * 7 + i // 251) & 0xFF for i in range(300000))
write(os.path.join(root, "pattern.bin"), pattern)
write(os.path.join(root, "empty"), b"")
boot_hash = hashlib.sha384(MANIFEST).hexdigest().upper()
boot = os.path.join(root, GROUP, "boot", boot_hash)
write(os.path.join(boot, "System/Library/Caches/com.apple.kernelcaches/kernelcache"), img4(b"krnl", pattern[:4096]))
firmware = os.path.join(boot, "usr/standalone/firmware")
write(os.path.join(firmware, "devicetree.img4"), img4(b"dtre", b"device tree bytes"))
write(os.path.join(firmware, "sptm.img4"), img4(b"sptm", b"sptm bytes"))
write(os.path.join(firmware, "txm.img4"), img4(b"trxm", b"txm bytes"))
write(os.path.join(firmware, "trustcache.img4"), img4(b"trst", b"trust cache bytes"))
write(os.path.join(firmware, "FUD/ans.img4"), img4(b"ansf", b"ans bytes"))
write(os.path.join(firmware, "notes.txt"), b"not an Image4 file, and long enough to be peeked at by the reader")
write(
    os.path.join(root, GROUP, "System/Library/CoreServices/SystemVersion.plist"),
    b'<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>'
    b"<key>ProductBuildVersion</key><string>FIXTURE</string>"
    b"<key>ProductVersion</key><string>27.0.fixture</string></dict></plist>\n",
)
os.symlink("boot/" + boot_hash, os.path.join(root, GROUP, "current"))
