#!/usr/bin/env python3
"""Run unchanged pinned Linux ccmp_pn2hdr over 262,144 PN/key-ID cases.

python3 crates/stela-drivers/tests/reference/wifi_tx_pn_oracle.py .stela/wifi-mac/tx-pn
No cipher/MIC or firmware counter behavior is claimed by this header oracle.
"""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from urllib.request import urlopen
from wifi_mac_oracle import function, PIN


def main():
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    donor = root / "wpa.c"
    if not donor.exists():
        donor.write_bytes(urlopen(f"https://raw.githubusercontent.com/torvalds/linux/{PIN}/net/mac80211/wpa.c").read())
    data = donor.read_bytes()
    expected = "07087347278d9f01307c98bad12554a611a8b70f703af4e7ca31747713d365b5"
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError("donor hash mismatch")
    unchanged = function(data.decode(), "ccmp_pn2hdr")
    harness = "#include <stdint.h>\n#include <stdio.h>\ntypedef uint8_t u8;\n" + unchanged + r"""
int main(void) {
    for (unsigned i=0;i<65536;++i) {
        u8 pn[6]={(u8)(i>>8),(u8)i,(u8)(i*13),(u8)(i>>3),(u8)(i*7),(u8)(i*5)};
        for (int key=0;key<4;++key) {
            u8 header[8];ccmp_pn2hdr(header,pn,key);
            if(fwrite(header,1,8,stdout)!=8) return 1;
        }
    }
    return fflush(stdout)!=0;
}
"""
    target = root / "pn.c"
    target.write_text(harness)
    command = ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g", "-fsanitize=address,undefined", str(target), "-o", str(root / "pn")]
    subprocess.run(command, check=True)
    output = subprocess.run([str(root / "pn")], check=True, capture_output=True).stdout
    if len(output) != 262144 * 8:
        raise RuntimeError("incomplete PN stream")
    (root / "pn.bin").write_bytes(output)
    receipt = {"pin":PIN,"donor":"net/mac80211/wpa.c","donor_sha256":expected,
        "donor_git_blob_sha1":hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest(),
        "unchanged_function_sha256":hashlib.sha256(unchanged.encode()).hexdigest(),
        "harness_sha256":hashlib.sha256(harness.encode()).hexdigest(),
        "output_sha256":hashlib.sha256(output).hexdigest(),"cases":262144,"command":command,
        "limits":"Header layout only; no cipher/MIC, hardware operation or firmware PN continuity proof"}
    (root / "receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    print(receipt["output_sha256"])


if __name__ == "__main__":
    main()
