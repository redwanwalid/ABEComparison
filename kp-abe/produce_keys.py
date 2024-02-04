# this file i used to create the keys: SK, PK, MK, K
# the key produced are later used in the experiment


'''
logic:
produce PK, MK, SK, K
symenc K with data, produce iv & cipher
insert iv & cipher into node
kpabe encrypt PK, K & attributes, produce ctxt
kpabe decrypt ctxt & sk
symdec dk, x , y
'''

from abenc_lsw08 import KPabe
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.engine.util import objectToBytes, bytesToObject
import pickle

def main():
	groupObj = PairingGroup('MNT224')
	pairing_group = PairingGroup('MNT224')
	kpabe = KPabe(groupObj)

	(pk, mk) = kpabe.setup()

	policy = '((SENIORDOCTOR and ORTHO)) and ((GYNAECOLOGY or BILLING))'

	attributes = ['JUNIORDOCTOR', 'BILLINGPERSON', 'DOCTOR', 'STUDENT', 'SENIORDOCTOR', 'OBSTETRICS', 'GYNAECOLOGY',
			 'MEDICINE', 'MASTERS', 'GYNAECOLOGIST', 'BILLING', 'ORTHOPEDIC', 'COMPUTERS', 'GYNAECOLOGY', 'ORTHO', 'CSEE']


	bytePK = objectToBytes(pk, pairing_group)
	byteMK = objectToBytes(mk, pairing_group)

	with open('PK.data', 'wb') as filehandle:
		pickle.dump(bytePK, filehandle)
		filehandle.close()

	with open('MK.data', 'wb') as filehandle:
		pickle.dump(byteMK, filehandle)
		filehandle.close()

	sk = kpabe.keygen(pk, mk, policy)
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

if __name__ == "__main__":
	debug = True
	main()