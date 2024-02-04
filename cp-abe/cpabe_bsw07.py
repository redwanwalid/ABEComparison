'''
John Bethencourt, Brent Waters (Pairing-based)

| From: "Ciphertext-Policy Attribute-Based Encryption".
| Published in: 2007
| Available from:
| Notes:
| Security Assumption:
|
| type:           ciphertext-policy attribute-based encryption (public key)
| setting:        Pairing

:Authors:    J Ayo Akinyele
:Date:            04/2011
'''
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output


class CPabe_BSW07(ABEnc):

	def __init__(self, groupObj):
		ABEnc.__init__(self)
		global util, group
		util = SecretUtil(groupObj, verbose=False)
		group = groupObj

	# @Output(pk_t, mk_t)
	def setup(self):
		g, gp = group.random(G1), group.random(G2)
		alpha, beta = group.random(ZR), group.random(ZR)
		# initialize pre-processing for generators
		g.initPP();
		gp.initPP()

		h = g ** beta;
		f = g ** ~beta
		e_gg_alpha = pair(g, gp ** alpha)

		pk = {'g': g, 'g2': gp, 'h': h, 'f': f, 'e_gg_alpha': e_gg_alpha}
		mk = {'beta': beta, 'g2_alpha': gp ** alpha}
		return (pk, mk)

	# @Input(pk_t, mk_t, [str])
	# @Output(sk_t)
	def keygen(self, pk, mk, S):
		r = group.random()
		g_r = (pk['g2'] ** r)
		D = (mk['g2_alpha'] * g_r) ** (1 / mk['beta'])
		D_j, D_j_pr = {}, {}
		for j in S:
			r_j = group.random()
			D_j[j] = g_r * (group.hash(j, G2) ** r_j)
			D_j_pr[j] = pk['g'] ** r_j
		return {'D': D, 'Dj': D_j, 'Djp': D_j_pr, 'S': S}

	# @Input(pk_t, GT, str)
	# @Output(ct_t)
	def encrypt(self, pk, M, policy_str):
		policy = util.createPolicy(policy_str)
		a_list = util.getAttributeList(policy)
		s = group.random(ZR)
		shares = util.calculateSharesDict(s, policy)

		C = pk['h'] ** s
		C_y, C_y_pr = {}, {}
		for i in shares.keys():
			j = util.strip_index(i)
			C_y[i] = pk['g'] ** shares[i]
			C_y_pr[i] = group.hash(j, G2) ** shares[i]

		return {'C_tilde': (pk['e_gg_alpha'] ** s) * M,
		        'C': C, 'Cy': C_y, 'Cyp': C_y_pr, 'policy': policy_str, 'attributes': a_list}

	# @Input(pk_t, sk_t, ct_t)
	# @Output(GT)
	def decrypt(self, pk, sk, ct):
		policy = util.createPolicy(ct['policy'])
		pruned_list = util.prune(policy, sk['S'])
		if pruned_list == False:
			return False
		z = util.getCoefficients(policy)
		A = 1
		for i in pruned_list:
			j = i.getAttributeAndIndex();
			k = i.getAttribute()
			A *= (pair(ct['Cy'][j], sk['Dj'][k]) / pair(sk['Djp'][k], ct['Cyp'][j])) ** z[j]

		return ct['C_tilde'] / (pair(ct['C'], sk['D']) / A)