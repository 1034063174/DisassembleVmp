import struct, json, sys, ctypes
from ctypes import wintypes

kernel32 = ctypes.windll.kernel32

GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

PIPE_NAME = rb'\\.\pipe\vmp_engine_ai'

def send_cmd(cmd, params=None):
    handle = kernel32.CreateFileA(
        PIPE_NAME, GENERIC_READ | GENERIC_WRITE,
        0, None, OPEN_EXISTING, 0, None)
    if handle == INVALID_HANDLE_VALUE:
        raise OSError(f"Cannot connect to pipe (err={kernel32.GetLastError()})")

    request = {"cmd": cmd}
    if params:
        request["params"] = params
    req_bytes = json.dumps(request).encode('utf-8')

    written = wintypes.DWORD()
    kernel32.WriteFile(handle, struct.pack('<I', len(req_bytes)), 4, ctypes.byref(written), None)
    kernel32.WriteFile(handle, req_bytes, len(req_bytes), ctypes.byref(written), None)

    read = wintypes.DWORD()
    resp_len_buf = ctypes.create_string_buffer(4)
    kernel32.ReadFile(handle, resp_len_buf, 4, ctypes.byref(read), None)
    resp_len = struct.unpack('<I', resp_len_buf.raw)[0]

    resp_buf = ctypes.create_string_buffer(resp_len)
    kernel32.ReadFile(handle, resp_buf, resp_len, ctypes.byref(read), None)

    kernel32.CloseHandle(handle)
    return json.loads(resp_buf.raw.decode('utf-8'))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: ai_client.py <cmd> [params_json]")
        sys.exit(1)
    cmd = sys.argv[1]
    params = json.loads(sys.argv[2]) if len(sys.argv) > 2 else None
    try:
        result = send_cmd(cmd, params)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"Error: {e}")
