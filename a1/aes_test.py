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

######################################################################
#Test Cases for init_key Schedule
def test_key_schedule():
	for r in range(11):
		result = state_str(key_schedule[r * 4:r * 4 +4]) 
		assert result == round_key_array[r], \
			"Key Schedule is wrong, result = " + result + " and round " + str(r)

# Key #2
key2 = '6920e299a5202a6d656e636869746f2a'

## Perform key schedule
key_schedule2 = init_key_schedule(key_bv(key2))

round_key_array2 = []
round_key_array2.append(key2)
round_key_array2.append('fa8807605fa82d0d3ac64e6553b2214f')
round_key_array2.append('cf75838d90ddae80aa1be0e5f9a9c1aa')
round_key_array2.append('180d2f1488d0819422cb6171db62a0db')
round_key_array2.append('baed96ad323d173910f67648cb94d693')
round_key_array2.append('881b4ab2ba265d8baad02bc36144fd50')
round_key_array2.append('b34f195d096944d6a3b96f15c2fd9245')
round_key_array2.append('a7007778ae6933ae0dd05cbbcf2dcefe')
round_key_array2.append('ff8bccf251e2ff5c5c32a3e7931f6d19')
round_key_array2.append('24b7182e7555e77229674495ba78298c')
round_key_array2.append('ae127cdadb479ba8f220df3d4858f6b1')

def test_key_schedule2():
	for r in range(11):
		result = state_str(key_schedule2[r * 4:r * 4 +4]) 
		assert result == round_key_array2[r], \
			"Key Schedule is wrong, result = " + result + " and round " + str(r)

#Key 3"
key3 = 'ffffffffffffffffffffffffffffffff'

# Perform key schedule
key_schedule3 = init_key_schedule(key_bv(key3))
round_key_array3 = []
round_key_array3.append('ffffffffffffffffffffffffffffffff')
round_key_array3.append('e8e9e9e917161616e8e9e9e917161616')
round_key_array3.append('adaeae19bab8b80f525151e6454747f0')
round_key_array3.append('090e2277b3b69a78e1e7cb9ea4a08c6e')
round_key_array3.append('e16abd3e52dc2746b33becd8179b60b6')
round_key_array3.append('e5baf3ceb766d488045d385013c658e6')
round_key_array3.append('71d07db3c6b6a93bc2eb916bd12dc98d')
round_key_array3.append('e90d208d2fbb89b6ed5018dd3c7dd150')
round_key_array3.append('96337366b988fad054d8e20d68a5335d')
round_key_array3.append('8bf03f233278c5f366a027fe0e0514a3')
round_key_array3.append('d60a3588e472f07b82d2d7858cd7c326')

def test_key_schedule3():
	for r in range(11):
		result = state_str(key_schedule3[r * 4:r * 4 +4]) 
		assert result == round_key_array3[r], \
			"Key Schedule is wrong, result = " + result + " and round " + str(r)
#################################################################################

##########################################################################
# Test cases for input_round_1					
def test_input_round_1():
	assert state_str(state_array) == NIST_input_round_1,\
      "test first-round input value based on output of initial add-round-key"
############################################################################

############################################################################
# Test cases for sbox lookup
# State array is the round 1 input
def test_sbox_lookup():
	result = bv_hex_str(sbox_lookup(state_array[0][0])) 
	assert result == 'd4', \
	"function return " + result
	
def test_sbox_lookup2():
	result = bv_hex_str(sbox_lookup(key_bv('cf')))
	assert result == '8a', \
	"function return " + result
	
def test_sbox_lookup3():
	result = bv_hex_str(sbox_lookup(key_bv('09'))) 
	assert result == '01', \
	"function return " + result	

##########################################################################
# Test cases for inv sbox lookup, state array is round 1 input
def test_inv_sbox_lookup():
	result = bv_hex_str(inv_sbox_lookup(sbox_lookup(state_array[0][0])))
	assert result == '19', \
	"function return " + result

def test_inv_sbox_lookup2():
	result = bv_hex_str(inv_sbox_lookup(key_bv('8a')))
	assert result == 'cf', \
	"function return " + result
	
def test_inv_sbox_lookup3():
	result = bv_hex_str(inv_sbox_lookup(key_bv('01')))
	assert result == '09', \
	"function return " + result
########################################################################
# Test cases for sub_bytes, state array is round 1 input
# Perform sub bytes
sub_bytes_array = sub_bytes(state_array)
def test_sub_bytes():
	assert(state_str(sub_bytes_array)) == 'd42711aee0bf98f1b8b45de51e415230',\
	"sub_bytes return " + state_str(sub_bytes_array)

# new state array for test_sub_bytes2 
state_array2_text = 'a49c7ff2689f352b6b5bea43026a5049'
state_array2 = init_state_array(key_bv(state_array2_text))
sub_bytes_array2 =  sub_bytes(state_array2)
def test_sub_bytes2():
	assert(state_str(sub_bytes_array2)) == '49ded28945db96f17f39871a7702533b',\
	"sub_bytes return " + state_str(sub_bytes_array2)
	
# new state array for test_sub_bytes3
state_array3_text = 'aa8f5f0361dde3ef82d24ad26832469a'
state_array3 = init_state_array(key_bv(state_array3_text))
sub_bytes_array3 =  sub_bytes(state_array3)
def test_sub_bytes3():
	assert(state_str(sub_bytes_array3)) == 'ac73cf7befc111df13b5d6b545235ab8',\
	"sub_bytes return " + state_str(sub_bytes_array3)
######################################################################

######################################################################
#Test cases for inv_sub_bytes	
def test_inv_sub_bytes():
	result = inv_sub_bytes(sub_bytes_array)
	assert state_str(result) == NIST_input_round_1, \
	"inv_sub_bytes wrong"

def test_inv_sub_bytes2():
	result = inv_sub_bytes(sub_bytes_array2)
	assert state_str(result) == state_array2_text, \
	"inv_sub_bytes_wrong"
	
def test_inv_sub_bytes3():
	result = inv_sub_bytes(sub_bytes_array3)
	assert state_str(result) == state_array3_text, \
	"inv_sub_bytes_wrong"

######################################################################
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

###############################################################################
# Tests for shift rows
# Perform shift rows
shift_row_array = shift_rows(sub_bytes_array)
def test_shift_rows():
	assert state_str(shift_row_array) == 'd4bf5d30e0b452aeb84111f11e2798e5',\
	"shift rows return " + state_str(shift_row_array)

shift_row_array2 = shift_rows(sub_bytes_array2)
def test_shift_rows_2():
	assert state_str(shift_row_array2) == '49db873b453953897f02d2f177de961a',\
	"shift row return " + state_str(shift_row_array2)

shift_row_array3 = shift_rows(sub_bytes_array3)
def test_shift_rows_3():
	assert state_str(shift_row_array3) == 'acc1d6b8efb55a7b1323cfdf457311b5', \
	"shift row return " + state_str(shift_row_array3)

####################################################################################	
# Test cases fpr inverse shift rows
def test_inv_shift_rows():
	result = inv_shift_rows(shift_row_array)
	assert state_str(result) == state_str(sub_bytes_array), \
	"inv shift return " + state_str(result)

def test_inv_shift_rows_2():
	result = inv_shift_rows(shift_row_array2)
	assert state_str(result) == state_str(sub_bytes_array2), \
	"inv shift return " + state_str(result)
	
def test_inv_shift_rows_3():
	result = inv_shift_rows(shift_row_array3)
	assert state_str(result) == state_str(sub_bytes_array3), \
	"inv shift return " + state_str(result)
######################################################################
	
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
	       "sub key bytes return " + result

def test_sub_key_bytes2():
	keyword = [key_bv('6c'), key_bv('76'), key_bv('05'), key_bv('2a')]
	result2 = sub_key_bytes(keyword)
	assert key_str(result2) == "50386be5",\
		"sub key bytes return " + key_str(result2)
		
def test_sub_key_bytes3():
	keyword = [key_bv('59'), key_bv('f6'), key_bv('7f'), key_bv('73')]
	result2 = sub_key_bytes(keyword)
	assert key_str(result2) == "cb42d28f",\
		"sub key bytes return " + key_str(result2)


############ Starting from this and below are the work of Pan Xu #################

# Tests for Xor() ####################################################
all_zero = BitVector.BitVector(intVal=0, size=8)
all_one = BitVector.BitVector(intVal=1, size=8)
def test_Xor_1():
	assert Xor(all_zero, all_one) == all_one, \
		"Xor test 4 error"

# Tests for gf_mult() ################################################
def test_gf_mult():
	test_bv = 191 #hex as "bf"
	factor = 2
	bv=BitVector.BitVector(intVal=test_bv, size=8)
	assert str(gf_mult(bv, factor)) == "01100101", \
	       "gf_mult test 1 error"

def test_gf_mult_2():
	test_bv = 93 #hex as "5d"
	factor = 3
	bv=BitVector.BitVector(intVal=test_bv, size=8)
	assert str(gf_mult(bv, factor)) == "11100111", \
	       "gf_mult test 2 error"

def test_gf_mult_3():
	test_bv = 48 #hex as "30"
	factor = 1
	bv=BitVector.BitVector(intVal=test_bv, size=8)
	assert str(gf_mult(bv, factor)) == "00110000", \
	       "gf_mult test 3 error"


# tests	for mix_columes() and invv_mix_columns()#####################
def test_mix_columns():
	sa = init_state_array(key_bv('876e46a6f24ce78c4d904ad897ecc395'))
	result = state_str(mix_columns(sa))
	assert result == "473794ed40d4e4a5a3703aa64c9f42bc", \
	       "mix_columns error"
	
def test_mix_columns_2():
	sa = init_state_array(key_bv('be3bd4fed4e1f2c80a642cc0da83864d'))
	result = state_str(mix_columns(sa))
	assert result == "00512fd1b1c889ff54766dcdfa1b99ea", \
	       "mix_columns error"

def test_inv_mix_columns():
	sa = init_state_array(key_bv('473794ed40d4e4a5a3703aa64c9f42bc'))
	result = state_str(inv_mix_columns(sa))
	assert result == "876e46a6f24ce78c4d904ad897ecc395", \
	       "inv_mix_columns 1 error"
	
def test_inv_mix_columns_2():
	sa = init_state_array(key_bv('00512fd1b1c889ff54766dcdfa1b99ea'))
	result = state_str(inv_mix_columns(sa))
	assert result == "be3bd4fed4e1f2c80a642cc0da83864d", \
	       "inv_mix_columns 2 error"

# Tests for encrypt() and decrypt() #################################
def test_encrypt():
	result = state_str(encrypt(NIST_test_key, NIST_test_plaintext))
	assert result == "3925841d02dc09fbdc118597196a0b32", \
	"encrypt() does not do as the animation does"
	
def test_encrypt_2():
	result = state_str(encrypt(NIST_test_key, NIST_test_plaintext))
	assert result == "3925841d02dc09fbdc118597196a0b32", \
	"encrypt() test 2 error"
	
def test_decrypt_1():
	result = state_str(decrypt(NIST_test_key, "3925841d02dc09fbdc118597196a0b32"))
	assert result == NIST_test_plaintext, \
	"decrypt() does not do as the animation does"

# Overall tests #######################################################
	
test_str1 = '00512fd1b1c889ff54766dcdfa1b99ea'
test_str2 = '473794ed40d4e4a5a3703aa64c9f42bc'
test_key = "be3bd4fed4e1f2c80a642cc0da83864d"

def test_overall_1():
	assert state_str(decrypt(test_key, \
	state_str(encrypt(test_key, test_str1)))) == test_str1, \
	"Overall test 1 fail"
	
def test_overall_2():
	assert state_str(decrypt(test_key, \
	state_str(encrypt(test_key, test_str2)))) == test_str2, \
	"Overall test 2 fail"

