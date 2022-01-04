import argparse
import re
import subprocess

ARG_INSTR_X86_64 = bytes.fromhex("be 01 00 00 00")  # mov esi, 0x1
PATCH_ARG_INSTR_X86_64 = bytes.fromhex("be 04 00 00 00")  # mov esi, 0x4
ARG_INSTR_ARM64E = bytes.fromhex("21 00 80 52")  # mov w1, 0x1
PATCH_ARG_INSTR_ARM64E = bytes.fromhex("81 00 80 52")  # mov w1, 0x4

OBJDUMP_REGEX = r"^\s*(.+?)\s*{op}\s+_LAEvaluatePolicy$"
OBJDUMP_REGEX_X86_64 = OBJDUMP_REGEX.format(op="callq")
OBJDUMP_REGEX_ARM64E = OBJDUMP_REGEX.format(op="bl")


def patch_arg(
    bin: bytearray,
    arch: str,
    arg_instr: bytes,
    patch_arg_instr: bytes,
    call_instr: bytes,
):
    assert bin.count(call_instr) == 1
    call_loc = bin.find(call_instr)
    assert call_loc != -1
    arg_loc = bin.rfind(arg_instr, 0, call_loc)
    assert arg_loc != -1
    bin[arg_loc : arg_loc + len(arg_instr)] = patch_arg_instr
    print(f"Patched {arch}: {arg_instr.hex()} to {patch_arg_instr.hex()}")


def attempt_patch(
    bin: bytearray,
    dissassembly: str,
    arch: str,
    objdump_call_regex,
    arg_instr,
    patch_arg_instr,
):
    call_instr_match = re.search(objdump_call_regex, dissassembly, flags=re.MULTILINE)
    if call_instr_match:
        call_instr = bytes.fromhex(call_instr_match.groups()[0])
        print(f"Found {arch} call instruction: {call_instr.hex()}")
        patch_arg(bin, arch, arg_instr, patch_arg_instr, call_instr)
    else:
        print(f"Unable to find {arch} call instruction, skipping patch.")


def patch(input_file, output_file):
    print(f"Opening {input_file}")
    with open(input_file, "rb") as f:
        bin = f.read()

    objdump = subprocess.run(
        ["objdump", "-macho", "--no-leading-addr", "-d", input_file],
        capture_output=True,
        text=True,
    )
    dissassembly = objdump.stdout
    if not dissassembly:
        print("Error dissasembling binary:\n" + objdump.stderr)
        exit(1)

    patched_bin = bytearray(bin)
    attempt_patch(
        patched_bin,
        dissassembly,
        "x86_64",
        OBJDUMP_REGEX_X86_64,
        ARG_INSTR_X86_64,
        PATCH_ARG_INSTR_X86_64,
    )
    attempt_patch(
        patched_bin,
        dissassembly,
        "arm64e",
        OBJDUMP_REGEX_ARM64E,
        ARG_INSTR_ARM64E,
        PATCH_ARG_INSTR_ARM64E,
    )
    assert len(bin) == len(patched_bin)
    print(f"Writing patch to {output_file}")
    with open(output_file, "wb") as f:
        f.write(patched_bin)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("output")
    args = parser.parse_args()
    patch(args.input, args.output)
