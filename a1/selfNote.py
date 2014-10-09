import aes
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
        
    

def gf_mult(bv, factor):
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
    print "here"
    for i in range(7): # shifting by the posision of the factor bits
        print "counting" + str(i)
        if (bv_factor[i]==1): # if the bit turns on
            ls_bv=copy.deepcopy(bv)
            print "The " +str(i) + "th" 
            for j in range((7-i)):  #left shift the number by j times
                print "haha"
                ls_bv = _shift(ls_bv)
                print ls_bv
            temp.append(ls_bv)
    if (bv_factor[7]==1):
       temp.append(bv)
    final = BitVector.BitVector(intVal=0, size=8)
    for i in range(len(temp)):
        final = Xor(final, temp[i]) 
    return final
    
		
if __name__ == "__main__":
    #print aes.bv_hex_str(10100100)
    bv=BitVector.BitVector(intVal=191, size=8)
    print bv
    print bv[1:8] + BitVector.BitVector(intVal=0, size=1)
    for i in range(0, 0):
        print "haha"
    #print BitVector.BitVector(intVal=bv[1, 8], size=8)
    # aes.gf_mult(bv, factor)
    factor = 3
    print gf_mult(bv, factor)