from typing import List

def split_history(text: str) -> List[int]:
    """Split a string containing at most one of the following letters: ShADadFf into a one hot encoding of the letters

    Args:
        text (str): The text to parse

    Returns:
        List[int]: A list containing 1s or 0s based on the presence of each of the letters in: ShADadFf
    """
    if type(text) != str:
        return [0, 0, 0, 0, 0, 0, 0, 0]
    out = {
        "S": 0,
        "h": 0,
        "A": 0,
        "D": 0,
        "a": 0,
        "d": 0,
        "F": 0,
        "f": 0
        }
    
    for letter in text:
        out[letter] = 1
    
    return list(out.values())

def check_IPv4(ip_address: str) -> bool:
    """ Check if an IP address is in the v4 format

    Args:
        ip_address (str): IP address to check in dotted decimal notation

    Returns:
        bool: True if IPv4
    """
    
    if ip_address.find(".") != -1:
        return True
    
    
    return False

    
def get_IPv4_split(ip_address: str) -> List[int]:
    """ Splits an IPv4 address into a list of each of the parts converted into ints

    Args:
        ip_address (str): The IPv4 address in dotted decimal notation

    Returns:
        List[int]: List of 4 ints containing the integer representation of each part
    """
    split_ip = ip_address.split(".")
    
    split_ip = list(map(int, split_ip))
    
    return split_ip

def get_IPv6_split(ip_address: str) -> List[int]:
    """ Splits an IPv6 address into a list of each of the parts converted into ints

    Args:
        ip_address (str): IPv6 address represented in hex codes seporated by colons

    Returns:
        List[int]: List of 8 ints containting the integer representations of each part
    """
    
    TARGET_LENGTH = 8
    
    split_ip = ip_address.split(":")
    
    # need to handle the case when :: is present in the address
    index_to_add = split_ip.index("")
    
    amount = split_ip.count("")
    
    # remove the extra blank items in the list created by splitting on : when there is :: present 
    for i in range(amount):
        split_ip.remove("")
    
    # add in missing zeros
    for i in range(TARGET_LENGTH - len(split_ip)):
        split_ip.insert(index_to_add, "0000")
        
    split_ip = list(map(lambda x: int(x, 16), split_ip))

    return split_ip  



def get_IP_columns(ip_address: str) -> List[int]:
    """ Gets a list containing data about the IP address regardless of its format

    Args:
        ip_address (_type_): The IP address to format (either IPv4 or IPv6)

    Returns:
        List[int]: A list of 12 values where the first 4 are if IPv4 and the second 8 are for IPv6
    """
    if check_IPv4(ip_address):
        ipv4 = get_IPv4_split(ip_address) 
        ipv6 = [-1]*8
        
    else:
        ipv4 = [-1]*4
        ipv6 = get_IPv6_split(ip_address)
        
    out = []
    out.extend(ipv4)
    out.extend(ipv6)
        
    return out