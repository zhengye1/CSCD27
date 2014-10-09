from aes import *

if __name__ == "__main__":
    # test key from AES-Spec Appendix B
    NIST_test_key = '2b7e151628aed2a6abf7158809cf4f3c'

    # plaintext test-value from AES-Spec Appendix B 
    NIST_test_plaintext = '3243f6a8885a308d313198a2e0370734'

    # input-to-round-1 value from AES-Spec Appendix B 
    NIST_input_round_1 = '193de3bea0f4e22b9ac68d2ae9f84808'
    
    # define NIST_test_plaintext_bv
    NIST_test_plaintext_BV = key_bv(NIST_test_plaintext)
    #print NIST_test_plaintext_BV
    # perform ke scheduling
    key_schedule = init_key_schedule(key_bv(NIST_test_key))
    #print key_schedule
    # create each round key for checking
    # create each round key for checking
    round_key_array = []
    round_key_array.append(NIST_test_key)    
    # convert NIST_test_plaintext to BitVector value NIST_test_plaintext_BV ...
    state_array = init_state_array(NIST_test_plaintext_BV)
        
    # perform initial add_round_key step before entering "round" process
    state_array = add_round_key(state_array, key_schedule[0:4])    

    round_times = 10
    
    #print state_array[0][1]
############## Play with it for one round #######################
# sub byte
    sa_1 = sub_bytes(state_array)
    #print sa_1[0][1]
# sub byte end

# shift row
    sa_2 = shift_rows(sa_1)
    #print sa_2[2][2]
# shift row end

# Mix Columns
    sa_3 = mix_columns(sa_2)
    #print sa_3[3][3]
# Mix Columns end

#
############## end Play with it for one round #######################