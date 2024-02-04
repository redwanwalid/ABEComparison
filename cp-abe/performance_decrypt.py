
from cpabe_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.engine.util import objectToBytes, bytesToObject
import pickle
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
import hashlib
from rdflib import Graph, URIRef
import base64
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

groupObj = PairingGroup('SS512')
pairing_group = PairingGroup('SS512')
cpabe = CPabe_BSW07(groupObj)

g = Graph()
g.parse("EHROntology_100k.owl")

filenames = ['DoctorNotes']


for patient in range(0, 15, 1):

	start_time_1 = datetime.now()

	with open('PK.data', 'rb') as filehandle:
		BytePK = pickle.load(filehandle)
		filehandle.close()

	pk = byToOb(BytePK)

	with open('k.data', 'rb') as filehandle:
		Bytek = pickle.load(filehandle)
		filehandle.close()

	k = byToOb(Bytek)

	access_policy = '((SENIORDOCTOR and ORTHO)) and ((GYNAECOLOGY or BILLING))'

	ctxt = cpabe.encrypt(pk, k, access_policy)

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

	with open('SK.data', 'rb') as filehandle:
		Bytek = pickle.load(filehandle)
		filehandle.close()

	sk = byToOb(Bytek)

	dk = cpabe.decrypt(pk, sk, ctxt)
	# print(dk)
	m = symdec(dk, x, y)
	# m = m.decode('utf-8')
	# print(m)

	end_time_1 = datetime.now()
	print('Decrypt Duration: {}'.format(end_time_1 - start_time_1))