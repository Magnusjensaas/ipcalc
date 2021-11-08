import calculations


def validate_ip(ip):
    parts = ip.split(".")

    if len(parts) != 4:
        raise ValueError

    for part in parts:
        if not isinstance(int(part), int):
            raise ValueError

        if int(part) < 0 or int(part) > 255:
            raise ValueError

    return True


def validate_mask(mask):
    if mask in calculations.CIDR_conversion or mask in calculations.reverse_CIDR_conversion:
        return True
    else:
        raise ValueError
