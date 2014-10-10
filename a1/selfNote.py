from aes import *
from aes_test import *
import sys
import BitVector
import binascii
import copy



    
def Xor(bv1, bv2):
    '''does bv1 xor bv2. bv has to be 8-bits BitVectors'''
    temp = []
    new_temp = BitVector.BitVector(size=0)
    for i in range(0, 8):
        if (bv1[i] != bv2[i]):
            temp.append(BitVector.BitVector(intVal=1, size = 1))
        else:
            temp.append(BitVector.BitVector(intVal=0, size = 1))
    for i in range(0, 8):
        new_temp += temp[i] 
        
    return new_temp
        
    

def _gf_mult(bv, factor):
    def _shift(bv):
        '''shift the BV left by 1, with conditional xor with 00011011'''
        #bv = bv + BitVector.BitVector(intVal=0, size=1) #left shift
        if (bv[0] == 1):
            bv = ls_bv[1:] + BitVector.BitVector(intVal=0, size=1)
            bv = Xor(bv,BitVector.BitVector(intVal=27, size=8))
        else:
            bv = bv[1:]   
            bv = bv + BitVector.BitVector(intVal=0, size=1)
        return bv
    
    bv_factor = BitVector.BitVector(intVal=factor, size = 8)
    temp=[]
    ls_bv=copy.deepcopy(bv)
    for i in range(7): # shifting by the posision of the factor bits
        if (bv_factor[i]==1): # if the bit turns on
            ls_bv=copy.deepcopy(bv)
            for j in range((7-i)):  #left shift the number by j times
                ls_bv = _shift(ls_bv)
            temp.append(ls_bv)
    if (bv_factor[7]==1):
        temp.append(bv)
    final = BitVector.BitVector(intVal=0, size=8)
    for i in range(len(temp)):
        final = Xor(final, temp[i]) 
    return final
    
def _mix_columns(sa):
    state_array=copy.deepcopy(sa)
    new_sa = []
    matrix = [[2, 3, 1, 1], [1, 2, 3, 1], \
              [1, 1, 2, 3], [3, 1, 1, 2]]
    for i in range(4):
        col_collector = BitVector.BitVector(intVal=0, size=8)
        for j in range(4):
            after_mult = gf_mult(state_array[i][j], matrix[i][j])
            print after_mult
            col_collector = Xor(after_mult, col_collector)
        new_sa.append(col_collector)
    return new_sa
		
if __name__ == "__main__":
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
    #print state_str(state_array)
    
    # perform initial add_round_key step before entering "round" process
    state_array = add_round_key(state_array, key_schedule[0:4])  
    #print state_str(NIST_test_plaintext_BV)
    #print "key" + state_str(key_schedule)[32:64]
    #print state_str(state_array)
    
    
    ###########################################################
    """
    #print aes.bv_hex_str(10100100)
    test_bv = 93
    factor = 3
    bv=BitVector.BitVector(intVal=test_bv, size=8)
    print bv
    print bv[1:8] + BitVector.BitVector(intVal=0, size=1)
    for i in range(0, 0):
        print "haha"
    #print BitVector.BitVector(intVal=bv[1, 8], size=8)
    # aes.gf_mult(bv, factor)
    print gf_mult(bv, factor)
    print str(gf_mult(bv, factor)) == "11100111"
    """
    ###########################################################
    #print state_array
    matrix = [[2, 3, 1, 1], [1, 2, 3, 1], \
                  [1, 1, 2, 3], [3, 1, 1, 2]]    
    #print gf_mult(state_array[0][0], 3)
    #print bv_hex_str(state_array[1])
    #print state_str(mix_columns(state_array))
    ############################################################
    #sa = init_state_array(key_bv('473794ed40d4e4a5a3703aa64c9f42bc'))
    #result = state_str(inv_mix_columns(sa))    
    #print result
    
    ################################################################
    result = state_str(decrypt(NIST_test_key, '3925841d02dc09fbdc118597196a0b32'))
    print result
