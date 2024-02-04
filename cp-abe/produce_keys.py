# this file i used to create the keys: SK, PK, MK, K
# the key produced are later used in the experiment

'''
logic:
produce PK, MK, SK, K
symenc K with data, produce iv & cipher
insert iv & cipher into node
cpabe encrypt PK, K & access policy, produce ctxt
cpabe decrypt PK, SK, ctxt
symdec dk, x , y
'''

from cpabe_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.engine.util import objectToBytes, bytesToObject
import pickle

def main():
	groupObj = PairingGroup('SS512')
	pairing_group = PairingGroup('SS512')

	cpabe = CPabe_BSW07(groupObj)
	# attrs = ['ONE', 'TWO', 'THREE']
	attrs = ['JUNIORDOCTOR', 'BILLINGPERSON', 'DOCTOR', 'STUDENT', 'SENIORDOCTOR', 'OBSTETRICS', 'GYNAECOLOGY', 'MEDICINE',
		 'MASTERS', 'GYNAECOLOGIST', 'BILLING', 'ORTHOPEDIC', 'COMPUTERS', 'GYNAECOLOGY', 'ORTHO', 'CSEE']
	# access_policy = '((four or three) and (three or one))'
	access_policy = '((SENIORDOCTOR and ORTHO)) and ((GYNAECOLOGY or BILLING))'
	# if debug:
	# 	print("Attributes =>", attrs);
	# 	print("Policy =>", access_policy)

	(pk, mk) = cpabe.setup()

	# print('Public Key:', pk)
	# print('Master Key:', msk)

	bytePK = objectToBytes(pk, pairing_group)
	byteMK = objectToBytes(mk, pairing_group)

	with open('PK.data', 'wb') as filehandle:
		pickle.dump(bytePK, filehandle)
		filehandle.close()

	with open('MK.data', 'wb') as filehandle:
		pickle.dump(byteMK, filehandle)
		filehandle.close()

	sk = cpabe.keygen(pk, mk, attrs)
	# print("sk :=>", sk)
	byteSK = objectToBytes(sk, pairing_group)

	with open('SK.data', 'wb') as filehandle:
		pickle.dump(byteSK, filehandle)
		filehandle.close()

	k = pairing_group.random(GT)
	byteK = objectToBytes(k, pairing_group)

	with open('k.data', 'wb') as filehandle:
		pickle.dump(byteK, filehandle)
		filehandle.close()

	# rand_msg = groupObj.random(GT)
	# if debug:
	# 	print("msg =>", rand_msg)
	# ct = cpabe.encrypt(pk, rand_msg, access_policy)
	# if debug:
	# 	print("\n\nCiphertext...\n")
	# groupObj.debug(ct)
	#
	# rec_msg = cpabe.decrypt(pk, sk, ct)
	# if debug:
	# 	print("\n\nDecrypt...\n")
	# if debug:
	# 	print("Rec msg =>", rec_msg)
	#
	# assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
	# if debug:
	# 	print("Successful Decryption!!!")


if __name__ == "__main__":
	debug = True
	main()

