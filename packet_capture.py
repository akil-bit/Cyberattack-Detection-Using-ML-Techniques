import subprocess
import random

def capture_packet(interface_index):
    try:
        cmd = [
            "tshark", "-i", str(interface_index), "-c", "1", "-T", "fields",
            "-e", "frame.time_relative",
            "-e", "ip.proto",
            "-e", "frame.len",
            "-e", "ip.len",
            "-e", "ip.ttl"
        ]

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.stderr:
            print("TShark error:", result.stderr)
            return None

        output = result.stdout.strip().split('\t')
        if len(output) < 5:
            return None

        duration = float(output[0]) if output[0] else 0
        protocol_type = int(output[1]) if output[1] else 0
        service = random.randint(0, 10)
        flag = random.randint(0, 5)
        src_bytes = int(output[2]) if output[2] else 0
        dst_bytes = int(output[3]) if output[3] else 0
        count = random.randint(0, 100)
        same_srv_rate = round(random.uniform(0, 1), 2)
        diff_srv_rate = round(random.uniform(0, 1), 2)
        dst_host_srv_count = int(output[4]) if output[4] else 0

        return [
            duration, protocol_type, service, flag, src_bytes,
            dst_bytes, count, same_srv_rate, diff_srv_rate, dst_host_srv_count
        ]
    except Exception as e:
        print("Capture Error:", e)
        return None
