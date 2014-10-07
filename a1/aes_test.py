from aes import *
# test key from AES-Spec Appendix B
NIST_test_key = '2b7e151628aed2a6abf7158809cf4f3c'

# plaintext test-value from AES-Spec Appendix B 
NIST_test_plaintext = '3243f6a8885a308d313198a2e0370734'

# input-to-round-1 value from AES-Spec Appendix B 
NIST_input_round_1 = '193de3bea0f4e22b9ac68d2ae9f84808'

# define NIST_test_plaintext_bv
NIST_test_plaintext_BV = key_bv(NIST_test_plaintext)

# perform ke scheduling
key_schedule = init_key_schedule(key_bv(NIST_test_key))
# create each round key for checking
round_key_array = []
round_key_array.append(NIST_test_key)
round_key_array.append('a0fafe1788542cb123a339392a6c7605')
round_key_array.append('f2c295f27a96b9435935807a7359f67f')
round_key_array.append('3d80477d4716fe3e1e237e446d7a883b')
round_key_array.append('ef44a541a8525b7fb671253bdb0bad00')
round_key_array.append('d4d1c6f87c839d87caf2b8bc11f915bc')
round_key_array.append('6d88a37a110b3efddbf98641ca0093fd')
round_key_array.append('4e54f70e5f5fc9f384a64fb24ea6dc4f')
round_key_array.append('ead27321b58dbad2312bf5607f8d292f')
round_key_array.append('ac7766f319fadc2128d12941575c006e')
round_key_array.append('d014f9a8c9ee2589e13f0cc8b6630ca6')


# convert NIST_test_plaintext to BitVector value NIST_test_plaintext_BV ...
state_array = init_state_array(NIST_test_plaintext_BV)


# perform initial add_round_key step before entering "round" process
state_array = add_round_key(state_array, key_schedule[0:4])


def test_key_schedule():
	for r in range(11):
		result = state_str(key_schedule[r * 4:r * 4 +4]) 
		assert result == round_key_array[r], \
			"Key Schedule is wrong, result = " + result + " and round " + str(r)

def test_input_round_1():
	assert state_str(state_array) == NIST_input_round_1,\
      "test first-round input value based on output of initial add-round-key"


def test_sbox_lookup():
	result = bv_hex_str(sbox_lookup(state_array[0][0])) 
	assert result == 'd4', \
	"function return " + result

def test_inv_sbox_lookup():
	result = bv_hex_str(inv_sbox_lookup(sbox_lookup(state_array[0][0])))
	assert result == '19', \
	"function return " + result

# Perform sub bytes
sub_bytes_array = sub_bytes(state_array)
def test_sub_bytes():
	assert(state_str(sub_bytes_array)) == 'd42711aee0bf98f1b8b45de51e415230',\
	"sub_bytes return " + result


def test_inv_sub_bytes():
	result = inv_sub_bytes(sub_bytes_array)
	assert state_str(result) == NIST_input_round_1, \
	"inv_sub_bytes wrong"

# Used for test shift bytes	
row = []
for i in range(1, 4):
	row.append(sub_bytes_array[0][i] + sub_bytes_array[1][i] + \
	sub_bytes_array[2][i] + sub_bytes_array[3][i])

def test_shift_bytes_left():
	assert bv_hex_str(shift_bytes_left(row[0], 1)) == 'bfb44127',\
	"shift bytes left wrong"
	assert bv_hex_str(shift_bytes_left(row[1], 2)) == '5d521198',\
	"shift bytes left wrong"
	assert bv_hex_str(shift_bytes_left(row[2], 3)) == '30aef1e5',\
	"shift bytes left wrong"

def test_shift_bytes_right():
	assert bv_hex_str(shift_bytes_right(shift_bytes_left(row[0], 1), 1)) == '27bfb441',\
	"shift bytes right wrong"
	assert bv_hex_str(shift_bytes_right(shift_bytes_left(row[1], 2), 2)) == '11985d52',\
	"shift bytes right wrong"
	assert bv_hex_str(shift_bytes_right(shift_bytes_left(row[2], 3), 3)) == 'aef1e530',\
	"shift bytes right wrong"

# Perform shift rows
shift_row_array = shift_rows(sub_bytes_array)
def test_shift_rows():
	assert state_str(shift_row_array) == 'd4bf5d30e0b452aeb84111f11e2798e5',\
	"shift rows return " + shift_row_array

def test_inv_shift_rows():
	result = inv_shift_rows(shift_row_array)
	assert state_str(result) == state_str(sub_bytes_array), \
	"inv shift row wrong"
	
def test_sub_key_bytes():
	key_word = key_schedule[3]
	temp = []
	temp = key_word[1:]
	temp.append(key_word[0])
	key_word = temp
	result = sub_key_bytes(key_word)
	result = bv_hex_str(result[0]) + bv_hex_str(result[1]) + \
	        bv_hex_str(result[2]) + bv_hex_str(result[3])
	assert result == '8a84eb01', \
	       "sub key butes return " + result

