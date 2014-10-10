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
    round_key_array = []
    #round_key_array.append(NIST_test_key)
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
    #print key_schedule
    # create each round key for checking
      
    # convert NIST_test_plaintext to BitVector value NIST_test_plaintext_BV ...
    state_array = init_state_array(NIST_test_plaintext_BV)
    print state_array[0][0]
    # perform initial add_round_key step before entering "round" process
    state_array = add_round_key(state_array, key_schedule[0:4])    
    print state_array[0][0]
    round_time = 10
    sa = state_array
    #print state_array[0][1]
    for i in range(round_time):
############## Play with it for one round #######################
        # sub byte
            sa = sub_bytes(sa)
            #print state_str(sa)
        # sub byte end
        
        # shift row
            sa = shift_rows(sa)
            #print state_str(sa)
        # shift row end
        
        # Mix Columns
            if i != 9:
                sa = mix_columns(sa)
                #print state_str(sa)
                #print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
        # Mix Columns end
        
        # Add round Key
            key_array = init_state_array(key_bv(round_key_array[i]))
            sa = add_round_key(sa, key_array)
            print state_str(sa)
        # Add round Key end
############## end Play with it for one round #######################