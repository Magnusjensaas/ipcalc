import calculations
import validation
# import calculations

print("IP CALCULATOR\n")
print("This calculator takes an IP address and a subnet mask or a netmask prefix\nand calculates the resulting "
      "broadcast, network, Cisco wildcard mask, and host range.\n")
print("Example of a valid IP Address: 192.168.0.1")
print("Example of a valid subnet mask: 255.255.255.0")
print("Example of a valid netmask prefix: 24\n")


def binary_list_to_string(binary_list):
    binary_excluding_0b = []
    for i in binary_list:
        binary_excluding_0b.append(i[2:])

    full_length_binary = [i.zfill(8) for i in binary_excluding_0b]
    return ".".join(full_length_binary)


def get_inputs():
    ipaddress = input("IP Address: ")
    mask = input("Subnet mask or netmask prefix: ")
    try:
        validation.validate_ip(ipaddress)
    except ValueError:
        print("Invalid IP address entered.")
    try:
        validation.validate_mask(mask)
    except ValueError:
        print("Invalid Mask entered.")

    address_binary = calculations.convert_ip_to_binary(ipaddress)
    address_binary_excluding_0b = []
    for i in address_binary:
        address_binary_excluding_0b.append(i[2:])

    print("Address: " + ipaddress + "    " + binary_list_to_string(calculations.convert_ip_to_binary(ipaddress)))
    print("Netmask: " + mask + "    " + binary_list_to_string(calculations.convert_mask_to_binary(mask)))
    print("Wildcard: " + calculations.calculate_wildcard(mask) + "    " +
          binary_list_to_string(calculations.convert_ip_to_binary(calculations.calculate_wildcard(mask))) + "\n")
    print("Network: " + calculations.calculate_network_address(ipaddress, mask) + "    " +
          binary_list_to_string(calculations.convert_ip_to_binary(calculations.calculate_network_address(ipaddress,
                                                                                                         mask))))
    print("Broadcast: " + calculations.calculate_broadcast_address(ipaddress, mask) + "    " +
          binary_list_to_string(calculations.convert_ip_to_binary(calculations.calculate_broadcast_address(ipaddress,
                                                                                                           mask))))
    print("First host address: " + calculations.calculate_first_host_address(ipaddress, mask))
    print("Last host address: " + calculations.calculate_last_host_address(ipaddress, mask))
    print("Available host addresses: " + calculations.calculate_host_range(mask))

    get_inputs()


if __name__ == "__main__":
    get_inputs()
