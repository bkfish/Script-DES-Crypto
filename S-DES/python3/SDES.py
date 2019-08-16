import string

plaintext = "11101010"
K = "0111111101"
rounds = 2
alphabet = string.ascii_uppercase

def bin_to_ascii_4bit(bin_string):
    h1, h2 = split_half(bin_string)
    return alphabet[bin_to_int(h1)] + alphabet[bin_to_int(h2)]

def P10(data):
    box = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    return "".join(list(map(lambda x: data[x - 1], box)))

def P8(data):
    box = [6, 3, 7, 4, 8, 5, 10, 9]
    return "".join(list(map(lambda x: data[x - 1], box)))

def P4(data):
    box = [2, 4, 3, 1]
    return "".join(list(map(lambda x: data[x - 1], box)))

def S0(data):
    row = bin_to_int(data[0] + data[3])
    col = bin_to_int(data[1] + data[2])
    box = [ ["01", "00" ,"11", "10"],
            ["11", "10", "01", "00"],
            ["00", "10", "01", "11"],
            ["11", "01", "11", "10"]
            ]

    return box[row][col]

def S1(data):
    row = bin_to_int(data[0] + data[3])
    col = bin_to_int(data[1] + data[2])
    box = [ ["00", "01", "10", "11"],
            ["10", "00", "01", "11"],
            ["11", "00", "01", "00"],
            ["10", "01", "00", "11"]
            ]
            
    return box[row][col]

def IP(data):
    box = [2, 6, 3, 1, 4, 8, 5, 7]
    return "".join(list(map(lambda x: data[x - 1], box)))

def IP_1(data):
    box = [4, 1, 3, 5, 7, 2, 8, 6]
    return "".join(list(map(lambda x: data[x - 1], box)))

def E_P(data):
    box = [4, 1, 2, 3, 2, 3, 4, 1]
    return "".join(list(map(lambda x: data[x - 1], box)))

def XOR(data, key):
    return "".join(list(map(lambda x, y: str(int(x) ^ int(y)), data, key)))

def LS(data, amount):
    return data[amount:] + data[:amount]

def SW(data):
    data1, data2 = split_half(data)
    return data2 + data1
    
def split_half(data):
    return data[:int(len(data) / 2)], data[int(len(data) / 2):]

def int_to_bin(data):
    return "{0:b}".format(data)

def bin_to_int(data):
    return int(data, 2)

def generate_round_keys(key, rounds):
    round_keys = []
    k_h1, k_h2 = split_half(P10(key))

    s = 0
    for i in range(1, rounds + 1):
        s += i
        h1, h2 = LS(k_h1, s), LS(k_h2, s)
        round_keys.append(P8(h1 + h2))

    return round_keys

def encrypt(data, key):
    round_keys = generate_round_keys(key, rounds)
    ip1, ip2 = split_half(IP(data))
    print("IP: {}".format(ip1 + ip2))

    for i, r_key in enumerate(round_keys):
        data = E_P(ip2)
        data = XOR(data, r_key)
        d1, d2 = split_half(data)
        d1 = S0(d1)
        d2 = S1(d2)
        data = XOR(ip1, P4(d1 + d2)) + ip2
        if i == 0:
            print("First Fk: {}".format(data))
        elif i == 1:
            print("Second Fk: {}".format(data))

        if i != len(round_keys) - 1:
            ip1, ip2 = split_half(SW(data))
            print("SW: {}".format(ip1 + ip2))
        else:
            ciphertext = IP_1(data)
            print("IP-1: {}".format(ciphertext))

    return ciphertext

def decrypt(data, key, comments=False):
    round_keys = list(reversed(generate_round_keys(key, rounds)))
    ip1, ip2 = split_half(IP(data))
    if comments:
        print("IP: {}".format(ip1 + ip2))

    for i, r_key in enumerate(round_keys):
        data = E_P(ip2)
        data = XOR(data, r_key)
        d1, d2 = split_half(data)
        d1 = S0(d1)
        d2 = S1(d2)
        data = XOR(ip1, P4(d1 + d2)) + ip2
        if comments and i == 0:
            print("First Fk: {}".format(data))
        elif comments and i == 1:
            print("Second Fk: {}".format(data))

        if i != len(round_keys) - 1:
            ip1, ip2 = split_half(SW(data))
            if comments:
                print("SW: {}".format(ip1 + ip2))
        else:
            plaintext = IP_1(data)
            if comments:
                print("IP-1: {}".format(plaintext))


    return plaintext


if __name__ == "__main__":
    print("需要加密的明文为: {} ({})".format(plaintext, bin_to_ascii_4bit(plaintext)))
    print("Key: {}".format(K))

    print("\n以下是加密的过程\n-------------------\n")
    C= encrypt(plaintext,K)
    print("加密后的密文为:  {} ({})".format(C, bin_to_ascii_4bit(C)))

    print("\n以下是解密的过程\n-------------------\n")
    d = decrypt(C, K, comments=True)
    print("解密后的明文是: {} ({})".format(d, bin_to_ascii_4bit(d)))