import codecs

input_string = '1c0111001f010100061a024b53535009181c'
xor_string = '686974207468652062756c6c277320657965'
value1 = codecs.decode(input_string, 'hex')
value2 = codecs.decode(xor_string, 'hex')

result = bytes(a ^ b for a, b in zip(value1, value2))
hex_result = codecs.encode(result, 'hex')

assert hex_result.decode('utf-8') == '746865206b696420646f6e277420706c6179'
