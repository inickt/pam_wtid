# x86_64
orig_x86_64 = bytes.fromhex(
    "48 89 C7"        # mov rdi, rax  ;; arg 1
    "BE 01 00 00 00"  # mov esi, 0x1  ;; arg 2, the one we want
    "4C 89 E2"        # mov rdx, r12  ;; arg 3
)
# change 0x1 to 0x4
new_x86_64 = orig_x86_64.replace(bytes.fromhex("BE 01 00 00 00"), bytes.fromhex("BE 04 00 00 00"))

# aarch64
orig_arm64e = bytes.fromhex(
    "A3 83 01 D1" # sub x3, fp   ;; arg 4
    "21 00 80 52" # mov w1, 0x1  ;; arg 2, the one we want
    "E2 03 18 AA" # mov x2, x24  ;; arg 3
)
# change 0x1 to 0x4
new_arm64e = orig_arm64e.replace(bytes.fromhex("21 00 80 52"), bytes.fromhex("81 00 80 52"))

with open("/usr/lib/pam/pam_tid.so.2", "rb") as f:
    pam = f.read()

assert pam.count(orig_x86_64) == 1
assert pam.count(new_x86_64) == 0
pam = pam.replace(orig_x86_64, new_x86_64)
assert pam.count(orig_x86_64) == 0
assert pam.count(new_x86_64) == 1

assert pam.count(orig_arm64e) == 1
assert pam.count(new_arm64e) == 0
pam = pam.replace(orig_arm64e, new_arm64e)
assert pam.count(orig_arm64e) == 0
assert pam.count(new_arm64e) == 1

with open("pam_wtid.so", "wb") as f:
    f.write(pam)
