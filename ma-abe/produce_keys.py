

from maabeRW15 import merge_dicts, MaabeRW15
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.core.engine.util import objectToBytes, bytesToObject
import pickle

def main():
	group = PairingGroup('SS512')
	pairing_group = PairingGroup('SS512')
	maabe = MaabeRW15(group)
	public_parameters = maabe.setup()

	bytePMS = objectToBytes(public_parameters, pairing_group)

	with open('PMS.data', 'wb') as filehandle:
		pickle.dump(bytePMS, filehandle)
		filehandle.close()

	(public_key1, secret_key1) = maabe.authsetup(public_parameters, 'H1')
	(public_key2, secret_key2) = maabe.authsetup(public_parameters, 'H2')

	public_keys = {'H1': public_key1, 'H2': public_key2}

	bytePK1 = objectToBytes(public_key1, pairing_group)

	with open('PK1.data', 'wb') as filehandle:
		pickle.dump(bytePK1, filehandle)
		filehandle.close()

	bytePK2 = objectToBytes(public_key2, pairing_group)

	with open('PK2.data', 'wb') as filehandle:
		pickle.dump(bytePK2, filehandle)
		filehandle.close()

	byteSK1 = objectToBytes(secret_key1, pairing_group)

	with open('SK1.data', 'wb') as filehandle:
		pickle.dump(byteSK1, filehandle)
		filehandle.close()

	byteSK2 = objectToBytes(secret_key2, pairing_group)

	with open('SK2.data', 'wb') as filehandle:
		pickle.dump(byteSK2, filehandle)
		filehandle.close()

	bytePKS = objectToBytes(public_keys, pairing_group)

	with open('PKS.data', 'wb') as filehandle:
		pickle.dump(bytePKS, filehandle)
		filehandle.close()

	gid = "bob"
	user_attributes1 = ['SENIORDOCTOR@H1', 'GYNAECOLOGY@H1']
	user_attributes2 = ['SENIORDOCTOR@H2', 'ORTHO@H2']
	user_keys1 = maabe.multiple_attributes_keygen(public_parameters, secret_key1, gid, user_attributes1)
	user_keys2 = maabe.multiple_attributes_keygen(public_parameters, secret_key2, gid, user_attributes2)
	user_keys = {'GID': gid, 'keys': merge_dicts(user_keys1, user_keys2)}

	byteUK1 = objectToBytes(user_keys1, pairing_group)

	with open('UK1.data', 'wb') as filehandle:
		pickle.dump(byteUK1, filehandle)
		filehandle.close()

	byteUK2 = objectToBytes(user_keys2, pairing_group)

	with open('UK2.data', 'wb') as filehandle:
		pickle.dump(byteUK2, filehandle)
		filehandle.close()

	byteUKS = objectToBytes(user_keys, pairing_group)

	with open('UKS.data', 'wb') as filehandle:
		pickle.dump(byteUKS, filehandle)
		filehandle.close()

	access_policy = '(SENIORDOCTOR@H1 or SENIORDOCTOR@H2) and (GYNAECOLOGY@H1 or ORTHO@H2)'

	k = group.random(GT)

	byteK = objectToBytes(k, pairing_group)

	with open('k.data', 'wb') as filehandle:
		pickle.dump(byteK, filehandle)
		filehandle.close()

	# cipher_text = maabe.encrypt(public_parameters, public_keys, k, access_policy)

if __name__ == "__main__":
	debug = True
	main()