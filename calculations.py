CIDR_conversion = {"1": "128.0.0.0", "2": "192.0.0.0", "3": "224.0.0.0", "4": "240.0.0.0", "5": "248.0.0.0",
                   "6": "252.0.0.0", "7": "254.0.0.0", "8": "255.0.0.0", "9": "255.128.0.0", "10": "255.192.0.0",
                   "11": "255.224.0.0", "12": "255.240.0.0", "13": "255.248.0.0", "14": "255.252.0.0",
                   "15": "255.254.0.0", "16": "255.255.0.0", "17": "255.255.128.0", "18": "255.255.192.0",
                   "19": "255.255.224.0", "20": "255.255.240.0", "21": "255.255.248.0", "22": "255.255.252.0",
                   "23": "255.255.254.0", "24": "255.255.255.0", "25": "255.255.255.128", "26": "255.255.255.192",
                   "27": "255.255.255.224", "28": "255.255.255.240", "29": "255.255.255.248", "30": "255.255.255.252",
                   "31": "255.255.255.254", "32": "255.255.255.255"}

reverse_CIDR_conversion = {"128.0.0.0": "1", "192.0.0.0": "2", "224.0.0.0": "3", "240.0.0.0": "4", "248.0.0.0": "5",
                           "252.0.0.0": "6", "254.0.0.0": "7", "255.0.0.0": "8", "255.128.0.0": "9",
                           "255.192.0.0": "10", "255.224.0.0": "11", "255.240.0.0": "12", "255.248.0.0": "13",
                           "255.252.0.0": "14", "255.254.0.0": "15", "255.255.0.0": "16", "255.255.128.0": "17",
                           "255.255.192.0": "18", "255.255.224.0": "19", "255.255.240.0": "20", "255.255.248.0": "21",
                           "255.255.252.0": "22", "255.255.254.0": "23", "255.255.255.0": "24", "255.255.255.128": "25",
                           "255.255.255.192": "26", "255.255.255.224": "27", "255.255.255.240": "28",
                           "255.255.255.248": "29", "255.255.255.252": "30", "255.255.255.254": "31",
                           "255.255.255.255": "32"}

decimal_bit_values = [128, 64, 32, 16, 8, 4, 2, 1]


def convert_mask_to_binary(mask):
    if len(mask) < 3:
        mask = CIDR_conversion[mask]
    parts = [int(x) for x in mask.split(".")]

    binary = []

    for part in parts:
        binary.append(bin(part))

    return binary


def convert_ip_to_binary(ip):
    parts = [int(x) for x in ip.split(".")]

    binary = []

    for part in parts:
        binary.append(bin(part))

    return binary


def calculate_broadcast_address(ip, mask):
    if len(mask) > 2:
        mask = reverse_CIDR_conversion[mask]

    host_bits = 32 - int(mask)

    ip_in_binary = convert_ip_to_binary(ip)
    binary_excluding_0b = []
    for i in ip_in_binary:
        binary_excluding_0b.append(i[2:])

    full_length_binary = [i.zfill(8) for i in binary_excluding_0b]
    binary_string = "".join(full_length_binary)
    binary = binary_string[:int(mask)] + host_bits * "1"

    binary_list = [("0b" + binary[:8]), ("0b" + binary[8:16]),
                   ("0b" + binary[16:24]), ("0b" + binary[24:32])]
    return convert_binary_to_ip(binary_list)


def calculate_network_address(ip, mask):
    if len(mask) > 2:
        mask = reverse_CIDR_conversion[mask]

    host_bits = 32 - int(mask)

    ip_in_binary = convert_ip_to_binary(ip)
    binary_excluding_0b = []
    for i in ip_in_binary:
        binary_excluding_0b.append(i[2:])

    full_length_binary = [i.zfill(8) for i in binary_excluding_0b]
    binary_string = "".join(full_length_binary)
    binary = binary_string[:int(mask)] + host_bits * "0"

    binary_list = [("0b" + binary[:8]), ("0b" + binary[8:16]),
                   ("0b" + binary[16:24]), ("0b" + binary[24:32])]
    return convert_binary_to_ip(binary_list)


def calculate_first_host_address(ip, mask):
    if len(mask) > 2:
        mask = reverse_CIDR_conversion[mask]

    host_bits = 32 - int(mask)

    ip_in_binary = convert_ip_to_binary(ip)
    binary_excluding_0b = []
    for i in ip_in_binary:
        binary_excluding_0b.append(i[2:])

    full_length_binary = [i.zfill(8) for i in binary_excluding_0b]
    binary_string = "".join(full_length_binary)
    binary = binary_string[:int(mask)] + (host_bits - 1) * "0" + "1"

    binary_list = [("0b" + binary[:8]), ("0b" + binary[8:16]),
                   ("0b" + binary[16:24]), ("0b" + binary[24:32])]
    return convert_binary_to_ip(binary_list)


def calculate_last_host_address(ip, mask):
    if len(mask) > 2:
        mask = reverse_CIDR_conversion[mask]

    host_bits = 32 - int(mask)

    ip_in_binary = convert_ip_to_binary(ip)
    binary_excluding_0b = []
    for i in ip_in_binary:
        binary_excluding_0b.append(i[2:])

    full_length_binary = [i.zfill(8) for i in binary_excluding_0b]
    binary_string = "".join(full_length_binary)
    binary = binary_string[:int(mask)] + (host_bits - 1) * "1" + "0"

    binary_list = [("0b" + binary[:8]), ("0b" + binary[8:16]),
                   ("0b" + binary[16:24]), ("0b" + binary[24:32])]
    return convert_binary_to_ip(binary_list)


def calculate_wildcard(mask):
    if len(mask) > 2:
        mask = reverse_CIDR_conversion[mask]
    wildcard_length = 32 - int(mask)
    wildcard_bits = wildcard_length * "1"
    binary = wildcard_bits.zfill(32)
    binary_list = [("0b" + binary[:8]), ("0b" + binary[8:16]),
                   ("0b" + binary[16:24]), ("0b" + binary[24:32])]

    return convert_binary_to_ip(binary_list)


def calculate_host_range(mask):
    if len(mask) > 2:
        mask = reverse_CIDR_conversion[mask]
    addresses_in_network = 2 ** (32 - int(mask))
    return str(addresses_in_network - 2)


def convert_binary_to_ip(binary):
    ip = []
    for part in binary:
        decimal = int(part, 2)
        ip.append(str(decimal))

    return ".".join(ip)
