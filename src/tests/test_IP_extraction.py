from analysis_functions import check_IPv4, get_IPv4_split, get_IPv6_split, get_IP_columns, split_history

def test_check_IPv4():
    assert check_IPv4("10.10.10.10") == True
    
    assert check_IPv4("fe80::211:32ff:fe8d:ffe2") == False
    
def check_IPv4_split():
    assert get_IPv4_split("10.10.10.10") == [10, 10, 10, 10]
    
    assert get_IPv4_split("100.0.35.7") == [100, 0, 35, 7]
    
def check_IPv6_split():
    assert get_IPv6_split("fe80::5bcc:698e:39d5:cdf") == [65152, 0, 0, 0, 23500, 27022, 14805, 3295]
    
    assert get_IPv6_split("db3:de28:96ef:73b::") == [3507, 56872, 38639, 1851, 0, 0, 0, 0]
    
    assert get_IPv6_split("::") == [0, 0, 0, 0, 0, 0, 0, 0]
    
def check_get_IP_columns():
    assert get_IP_columns("10.10.10.10") == [10, 10, 10, 10, -1, -1, -1, -1, -1, -1, -1, -1]
    
    assert get_IP_columns("fe80::5bcc:698e:39d5:cdf") == [-1, -1, - 1, -1, 65152, 0, 0, 0, 23500, 27022, 14805, 3295]