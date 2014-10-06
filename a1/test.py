from aes_starter import *
# test key from AES-Spec Appendix B
NIST_test_key = '2b7e151628aed2a6abf7158809cf4f3c'

# plaintext test-value from AES-Spec Appendix B 
NIST_test_plaintext = '3243f6a8885a308d313198a2e0370734'

# input-to-round-1 value from AES-Spec Appendix B 
NIST_input_round_1 = '193de3bea0f4e22b9ac68d2ae9f84808'

# define NIST_test_plaintext_bv
NIST_test_plaintext_BV = key_bv(NIST_test_plaintext)

key_schedule = init_key_schedule(key_bv(NIST_test_key))

# convert NIST_test_plaintext to BitVector value NIST_test_plaintext_BV ...
init_state = state_array = init_state_array(NIST_test_plaintext_BV)


# perform initial add_round_key step before entering "round" process
state_array = add_round_key(state_array, key_schedule[0:4])


def test_key_schedule():
	result = state_str(key_schedule)
	assert result == NIST_test_key, \
	"Key Schedule is wrong, result = " + result 

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