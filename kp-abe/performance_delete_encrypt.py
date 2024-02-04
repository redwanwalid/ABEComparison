from abenc_lsw08 import KPabe
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.core.engine.util import objectToBytes, bytesToObject
import pickle
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
import hashlib
from rdflib import Graph, URIRef
import base64
import os
from pandas import *
from datetime import datetime

def byToOb(bytes):
	pairing_group = PairingGroup('MNT224')
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

groupObj = PairingGroup('MNT224')
pairing_group = PairingGroup('MNT224')
kpabe = KPabe(groupObj)


# LabResults = ["The patient was tested for, Beta-human chorionic gonadotropin, Serial hCG monitoring, False positive hCG results, Early pregnancy factor", "The patient was tested for tendinitis. A CT scan was conducted. The results show positive for tendinitis. The cross sectional images of both the knees show severe bone damage.", "Lab Results show severe damage to bones due to ageing.", "No tests needed."]

# Medication = ["The patient is advised to follow exercises as shown during the visit and follow the prescribed medicines regularly.", "The patient is advised to take over-the-counter Calcium tablets. Along with this, the patient is advised to massage the painful area everyday before going to bed with sessame oil. Avoid sleeping on your side. Use pillows positioned on either side of your body to prevent you from rolling onto your side. When lying on your side, keep a pillow between your knees.", "The patient is advised to follow as written below, Ultimate Bone Support talbets 2 times a day", "No medication.", "The patient has been prescribed the following medication,Emetre, Monistat or Terazol", "The patient is prescribed with, Bone Strength Take Care™ Slim Tablets, Ultimate Bone Support talbets", "The patient does not need any medication. The patient's bone health is good. Regular exercise to be continued."]

# Allergies = ["The patient is allergic to Ibuprofen", "No allergies recorded."]

DoctorNotes = ["The patient is in her first trimester of pregnancy. Extra care is advised.", "Warm up before exercise. Stretch your quadriceps and hamstrings before and after exercise. Try low-impact exercises. Instead of tennis or running, give swimming or bicycling a shot. Or mix low-impact exercises with high-impact exercises to give your knees a break. Lose weight. Walk down hills. Running puts extra force on your knee. Instead of running down an incline, walk. Stick to paved surfaces. Rough roads or pocked walkways may be hazardous to your knee’s health. Stick to smooth, paved surfaces like a track or walking arena. Get support. Shoe inserts can help treat foot or gait problems that may be contributing to knee pain. Replace your running shoes frequently to ensure they still have proper support and cushioning.", "The patient is advised to follow the prescribed medicines strictly. The patient should try to reduce weight. Also, carrying a support stick is advised.", "Keep up the good exercise routine."]

# Immunization = ["The patient is being currently administered with, Flu (influenza) shot, Tetanus toxoid, reduced diphtheria toxoid and acellular pertussis (Tdap) vaccine", "The patient was administered with B12 as of November 12, 1995 The patient does not need any specific immunization as of now for tendinitis.", "The patient's immunization schedule is, Synvisc-One® (hylan G-F 20) once every month for a period of 4 months", "No immunization required."]

# BillingDetails = ["The patient has been billed as follows, Doctor Visit : $400, Sonography : $1290, Lab Tests : $2200, Medical Insurance Coverage : $2500, Total expense to be paid : $1390", "The following amount has been generated for CT Scan for Tendinitis in both Knees : $2,334, Medical Insurance Coverage : -$1500, Total amount to be paid : $834. The following amount has been generated for Doctor Visit Doctor Visit and Check-up : $400, Insurance Coverage : $400, Total amount to be paid : $0.", "The patient has been billed as follows, Synvisc-One® (hylan G-F 20), Injection Charges : $1200, Insurance Coverage : $600 , Total expense to be paid : $600. The patient has been billed as follows, Doctor Visit, Doctor's examination charges : $400, Medical Insurance Claimed : $200, Total expenses to be paid : $200"]

# data = read_csv("D_ICD_DIAGNOSES.csv")

# Diagnosis = data['long_title'].tolist()

# absolute_path = '/Users/redwanwalid/Documents/UMBC Studies/KNACC/Experiments/Journal_2_2023/'
# os.chdir(absolute_path)

g = Graph()
g.parse("EHROntology_100k.owl")

Dia = ["Diagnosis"]
l = 0

for patient in range(0, 15, 1):

	# delete
	start_time_1 = datetime.now()

	sparql_2 = "DELETE {<http://www.semanticweb.org/redwanwalid/ontologies/2023/3/untitled-ontology-294#" + str(patient) + "> <http://www.semanticweb.org/redwanwalid/ontologies/2023/3/untitled-ontology-294#" + str(Dia[0]) + "> ?object} WHERE {<http://www.semanticweb.org/redwanwalid/ontologies/2023/3/untitled-ontology-294#" + str(patient) + "> <http://www.semanticweb.org/redwanwalid/ontologies/2023/3/untitled-ontology-294#" + str(Dia[0]) + "> ?object .}"
	qres_2 = g.update(sparql_2)

	end_time_1 = datetime.now()
	print('Delete Duration: {}'.format(end_time_1 - start_time_1))

	# encryption

	if l == len(DoctorNotes):
		l = 0

	start_time_2 = datetime.now()

	with open('PK.data', 'rb') as filehandle:
		BytePK = pickle.load(filehandle)
		filehandle.close()

	pk = byToOb(BytePK)

	with open('k.data', 'rb') as filehandle:
		Bytek = pickle.load(filehandle)
		filehandle.close()

	k = byToOb(Bytek)

	attributes = ['JUNIORDOCTOR', 'BILLINGPERSON', 'DOCTOR', 'STUDENT', 'SENIORDOCTOR', 'OBSTETRICS', 'GYNAECOLOGY',
	              'MEDICINE', 'MASTERS', 'GYNAECOLOGIST', 'BILLING', 'ORTHOPEDIC', 'COMPUTERS', 'GYNAECOLOGY', 'ORTHO',
	              'CSEE']

	ctxt = kpabe.encrypt(pk, k, attributes)

	(iv, cipher) = symenc(k, DoctorNotes[l])

	l += 1

	iv_str = str(base64.b64encode(iv), 'utf-8')
	cipher_str = str(base64.b64encode(cipher), 'utf-8')
	final_data = iv_str + " " + cipher_str

	sparql_3 = "INSERT {<http://www.semanticweb.org/redwanwalid/ontologies/2023/3/untitled-ontology-294#" + str(patient) + "> <http://www.semanticweb.org/redwanwalid/ontologies/2023/3/untitled-ontology-294#" + str(Dia[0]) + "> " + repr(final_data) + "} WHERE {<http://www.semanticweb.org/redwanwalid/ontologies/2023/3/untitled-ontology-294#" + str(patient) + "> ?predicate ?object .}"

	qres_3 = g.update(sparql_3)

	end_time_2 = datetime.now()
	print('Encrypt Duration: {}'.format(end_time_2 - start_time_2))

g.serialize(destination="EHROntology_100k.owl", format='application/rdf+xml')

