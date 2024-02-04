

from maabeRW15 import merge_dicts, MaabeRW15
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.engine.util import objectToBytes, bytesToObject
import pickle
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
import hashlib
from rdflib import Graph, URIRef
import base64
import os
from datetime import datetime

def byToOb(bytes):
	pairing_group = PairingGroup('SS512')
	return bytesToObject(bytes, pairing_group)

def symenc(k, m):
	# get aeskey from k
	h = hashlib.sha256()
	h.update(str(k).encode())
	aeskey = h.digest()
	# encrypt the data with aes
	iv = Random.new().read(AES.block_size)
	ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
	enc = AES.new(aeskey, AES.MODE_CTR, counter=ctr)
	cipher = enc.encrypt(m)
	return (iv, cipher)


def symdec(k, iv, cipher):
	h = hashlib.sha256()
	h.update(str(k).encode())
	aeskey = h.digest()
	# decrypt the cipher based on dk and iv
	ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
	dec = AES.new(aeskey, AES.MODE_CTR, counter=ctr)
	return dec.decrypt(cipher)

group = PairingGroup('SS512')
pairing_group = PairingGroup('SS512')
maabe = MaabeRW15(group)

g = Graph()
g.parse("EHROntology_100k.owl")

filenames = ['DoctorNotes']

for patient in range(0, 15, 1):

	start_time_1 = datetime.now()

	with open('PMS.data', 'rb') as filehandle:
		BytePMS = pickle.load(filehandle)
		filehandle.close()

	public_parameters = byToOb(BytePMS)

	with open('PK1.data', 'rb') as filehandle:
		BytePK1 = pickle.load(filehandle)
		filehandle.close()

	public_key1 = byToOb(BytePK1)

	with open('PK2.data', 'rb') as filehandle:
		BytePK2 = pickle.load(filehandle)
		filehandle.close()

	public_key2 = byToOb(BytePK2)

	public_keys = {'H1': public_key1, 'H2': public_key2}

	with open('k.data', 'rb') as filehandle:
		Bytek = pickle.load(filehandle)
		filehandle.close()

	k = byToOb(Bytek)

	access_policy = '(SENIORDOCTOR@H1 or SENIORDOCTOR@H2) and (GYNAECOLOGY@H1 or ORTHO@H2)'

	cipher_text = maabe.encrypt(public_parameters, public_keys, k, access_policy)

	sparql_1 = "SELECT ?object WHERE {<http://www.semanticweb.org/redwanwalid/ontologies/2023/3/untitled-ontology-294#" + str(
		patient) + "> <http://www.semanticweb.org/redwanwalid/ontologies/2023/3/untitled-ontology-294#" + str(
		filenames[0]) + "> ?object .}"

	qres_1 = g.query(sparql_1)
	# print(qres_1)
	for row in qres_1:
		data = row[0]
		# print('Data : ', data)

	y = data.split(" ", 1)
	# print(y)
	iv = y[0]
	# print(iv)
	x = base64.b64decode(iv)
	# print(x)
	cipher = y[1]
	# print(cipher)
	y = base64.b64decode(cipher)
	# print(y)

	with open('UK1.data', 'rb') as filehandle:
		ByteUK1 = pickle.load(filehandle)
		filehandle.close()

	user_keys1 = byToOb(ByteUK1)

	with open('UK2.data', 'rb') as filehandle:
		ByteUK2 = pickle.load(filehandle)
		filehandle.close()

	user_keys2 = byToOb(ByteUK2)

	gid = "bob"

	user_keys = {'GID': gid, 'keys': merge_dicts(user_keys1, user_keys2)}

	dk = maabe.decrypt(public_parameters, user_keys, cipher_text)
	# print(dk)
	m = symdec(dk, x, y)
	# m = m.decode('utf-8')
	# print(m)
	end_time_1 = datetime.now()
	print('Decrypt Duration: {}'.format(end_time_1 - start_time_1))