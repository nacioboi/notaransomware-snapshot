from typing import Generator
from functools import cache
from math import gcd as math_X_gcd
from os import cpu_count
from numba import njit
from random import choice as random_X_choice
from sympy import nextprime as sympy_X_nextprime
from concurrent.futures import ThreadPoolExecutor

N_CPUS = cpu_count()
if N_CPUS is None:
	N_CPUS = 1







#TODO: THE BELOW IS 19KB, saving it as a compressed file would be better...
_BUNDLED_PRIMES = """
115792089237316195423570985008687907853269984665640564039457584007913138139947
115792089237316195423570985008687907853269984665640564039457584007913138139993
115792089237316195423570985008687907853269984665640564039457584007913138140277
115792089237316195423570985008687907853269984665640564039457584007913138140299
115792089237316195423570985008687907853269984665640564039457584007913138140491
115792089237316195423570985008687907853269984665640564039457584007913138140511
115792089237316195423570985008687907853269984665640564039457584007913138140563
115792089237316195423570985008687907853269984665640564039457584007913138141949
115792089237316195423570985008687907853269984665640564039457584007913138142237
115792089237316195423570985008687907853269984665640564039457584007913138144193
115792089237316195423570985008687907853269984665640564039457584007913138144543
115792089237316195423570985008687907853269984665640564039457584007913138144597
115792089237316195423570985008687907853269984665640564039457584007913138144853
115792089237316195423570985008687907853269984665640564039457584007913138144879
115792089237316195423570985008687907853269984665640564039457584007913138146233
115792089237316195423570985008687907853269984665640564039457584007913138146443
115792089237316195423570985008687907853269984665640564039457584007913138146451
115792089237316195423570985008687907853269984665640564039457584007913138146493
115792089237316195423570985008687907853269984665640564039457584007913138146499
115792089237316195423570985008687907853269984665640564039457584007913138148183
115792089237316195423570985008687907853269984665640564039457584007913138148681
115792089237316195423570985008687907853269984665640564039457584007913138150003
115792089237316195423570985008687907853269984665640564039457584007913138150193
115792089237316195423570985008687907853269984665640564039457584007913138150223
115792089237316195423570985008687907853269984665640564039457584007913138150369
115792089237316195423570985008687907853269984665640564039457584007913138150447
115792089237316195423570985008687907853269984665640564039457584007913138150831
115792089237316195423570985008687907853269984665640564039457584007913138152049
115792089237316195423570985008687907853269984665640564039457584007913138152217
115792089237316195423570985008687907853269984665640564039457584007913138152253
115792089237316195423570985008687907853269984665640564039457584007913138152283
115792089237316195423570985008687907853269984665640564039457584007913138152499
115792089237316195423570985008687907853269984665640564039457584007913138152589
115792089237316195423570985008687907853269984665640564039457584007913138152659
115792089237316195423570985008687907853269984665640564039457584007913138152863
115792089237316195423570985008687907853269984665640564039457584007913138153939
115792089237316195423570985008687907853269984665640564039457584007913138154287
115792089237316195423570985008687907853269984665640564039457584007913138154431
115792089237316195423570985008687907853269984665640564039457584007913138154443
115792089237316195423570985008687907853269984665640564039457584007913138154483
115792089237316195423570985008687907853269984665640564039457584007913138154563
115792089237316195423570985008687907853269984665640564039457584007913138154831
115792089237316195423570985008687907853269984665640564039457584007913138156139
115792089237316195423570985008687907853269984665640564039457584007913138156163
115792089237316195423570985008687907853269984665640564039457584007913138156241
115792089237316195423570985008687907853269984665640564039457584007913138156411
115792089237316195423570985008687907853269984665640564039457584007913138156859
115792089237316195423570985008687907853269984665640564039457584007913138156871
115792089237316195423570985008687907853269984665640564039457584007913138157971
115792089237316195423570985008687907853269984665640564039457584007913138158127
115792089237316195423570985008687907853269984665640564039457584007913138158229
115792089237316195423570985008687907853269984665640564039457584007913138158377
115792089237316195423570985008687907853269984665640564039457584007913138158389
115792089237316195423570985008687907853269984665640564039457584007913138158419
115792089237316195423570985008687907853269984665640564039457584007913138158473
115792089237316195423570985008687907853269984665640564039457584007913138158887
115792089237316195423570985008687907853269984665640564039457584007913138160051
115792089237316195423570985008687907853269984665640564039457584007913138160167
115792089237316195423570985008687907853269984665640564039457584007913138160581
115792089237316195423570985008687907853269984665640564039457584007913138160617
115792089237316195423570985008687907853269984665640564039457584007913138160801
115792089237316195423570985008687907853269984665640564039457584007913138160849
115792089237316195423570985008687907853269984665640564039457584007913138161941
115792089237316195423570985008687907853269984665640564039457584007913138162073
115792089237316195423570985008687907853269984665640564039457584007913138162337
115792089237316195423570985008687907853269984665640564039457584007913138162429
115792089237316195423570985008687907853269984665640564039457584007913138162813
115792089237316195423570985008687907853269984665640564039457584007913138162913
115792089237316195423570985008687907853269984665640564039457584007913138164167
115792089237316195423570985008687907853269984665640564039457584007913138164263
115792089237316195423570985008687907853269984665640564039457584007913138164677
115792089237316195423570985008687907853269984665640564039457584007913138164913
115792089237316195423570985008687907853269984665640564039457584007913138165967
115792089237316195423570985008687907853269984665640564039457584007913138165987
115792089237316195423570985008687907853269984665640564039457584007913138166077
115792089237316195423570985008687907853269984665640564039457584007913138166173
115792089237316195423570985008687907853269984665640564039457584007913138166323
115792089237316195423570985008687907853269984665640564039457584007913138166441
115792089237316195423570985008687907853269984665640564039457584007913138166443
115792089237316195423570985008687907853269984665640564039457584007913138166869
115792089237316195423570985008687907853269984665640564039457584007913138168049
115792089237316195423570985008687907853269984665640564039457584007913138168079
115792089237316195423570985008687907853269984665640564039457584007913138168163
115792089237316195423570985008687907853269984665640564039457584007913138168243
115792089237316195423570985008687907853269984665640564039457584007913138168273
115792089237316195423570985008687907853269984665640564039457584007913138168619
115792089237316195423570985008687907853269984665640564039457584007913138170461
115792089237316195423570985008687907853269984665640564039457584007913138170653
115792089237316195423570985008687907853269984665640564039457584007913138170817
115792089237316195423570985008687907853269984665640564039457584007913138170839
115792089237316195423570985008687907853269984665640564039457584007913138170907
115792089237316195423570985008687907853269984665640564039457584007913138172053
115792089237316195423570985008687907853269984665640564039457584007913138172081
115792089237316195423570985008687907853269984665640564039457584007913138172257
115792089237316195423570985008687907853269984665640564039457584007913138172299
115792089237316195423570985008687907853269984665640564039457584007913138172567
115792089237316195423570985008687907853269984665640564039457584007913138172579
115792089237316195423570985008687907853269984665640564039457584007913138173973
115792089237316195423570985008687907853269984665640564039457584007913138174157
115792089237316195423570985008687907853269984665640564039457584007913138174567
115792089237316195423570985008687907853269984665640564039457584007913138176067
115792089237316195423570985008687907853269984665640564039457584007913138176167
115792089237316195423570985008687907853269984665640564039457584007913138176211
115792089237316195423570985008687907853269984665640564039457584007913138176239
115792089237316195423570985008687907853269984665640564039457584007913138176251
115792089237316195423570985008687907853269984665640564039457584007913138176269
115792089237316195423570985008687907853269984665640564039457584007913138176313
115792089237316195423570985008687907853269984665640564039457584007913138176589
115792089237316195423570985008687907853269984665640564039457584007913138176767
115792089237316195423570985008687907853269984665640564039457584007913138176887
115792089237316195423570985008687907853269984665640564039457584007913138178323
115792089237316195423570985008687907853269984665640564039457584007913138178509
115792089237316195423570985008687907853269984665640564039457584007913138178579
115792089237316195423570985008687907853269984665640564039457584007913138178819
115792089237316195423570985008687907853269984665640564039457584007913138178893
115792089237316195423570985008687907853269984665640564039457584007913138180141
115792089237316195423570985008687907853269984665640564039457584007913138180241
115792089237316195423570985008687907853269984665640564039457584007913138180339
115792089237316195423570985008687907853269984665640564039457584007913138182253
115792089237316195423570985008687907853269984665640564039457584007913138182403
115792089237316195423570985008687907853269984665640564039457584007913138182767
115792089237316195423570985008687907853269984665640564039457584007913138184119
115792089237316195423570985008687907853269984665640564039457584007913138184821
115792089237316195423570985008687907853269984665640564039457584007913138185991
115792089237316195423570985008687907853269984665640564039457584007913138186121
115792089237316195423570985008687907853269984665640564039457584007913138186181
115792089237316195423570985008687907853269984665640564039457584007913138186363
115792089237316195423570985008687907853269984665640564039457584007913138186387
115792089237316195423570985008687907853269984665640564039457584007913138186453
115792089237316195423570985008687907853269984665640564039457584007913138186459
115792089237316195423570985008687907853269984665640564039457584007913138186489
115792089237316195423570985008687907853269984665640564039457584007913138186681
115792089237316195423570985008687907853269984665640564039457584007913138186723
115792089237316195423570985008687907853269984665640564039457584007913138186849
115792089237316195423570985008687907853269984665640564039457584007913138186909
115792089237316195423570985008687907853269984665640564039457584007913138188143
115792089237316195423570985008687907853269984665640564039457584007913138188193
115792089237316195423570985008687907853269984665640564039457584007913138188559
115792089237316195423570985008687907853269984665640564039457584007913138188779
115792089237316195423570985008687907853269984665640564039457584007913138189943
115792089237316195423570985008687907853269984665640564039457584007913138190233
115792089237316195423570985008687907853269984665640564039457584007913138190317
115792089237316195423570985008687907853269984665640564039457584007913138190597
115792089237316195423570985008687907853269984665640564039457584007913138190677
115792089237316195423570985008687907853269984665640564039457584007913138190899
115792089237316195423570985008687907853269984665640564039457584007913138191941
115792089237316195423570985008687907853269984665640564039457584007913138192021
115792089237316195423570985008687907853269984665640564039457584007913138192277
115792089237316195423570985008687907853269984665640564039457584007913138192301
115792089237316195423570985008687907853269984665640564039457584007913138192441
115792089237316195423570985008687907853269984665640564039457584007913138192463
115792089237316195423570985008687907853269984665640564039457584007913138192733
115792089237316195423570985008687907853269984665640564039457584007913138192883
115792089237316195423570985008687907853269984665640564039457584007913138194293
115792089237316195423570985008687907853269984665640564039457584007913138194307
115792089237316195423570985008687907853269984665640564039457584007913138194523
115792089237316195423570985008687907853269984665640564039457584007913138194541
115792089237316195423570985008687907853269984665640564039457584007913138194829
115792089237316195423570985008687907853269984665640564039457584007913138196063
115792089237316195423570985008687907853269984665640564039457584007913138196329
115792089237316195423570985008687907853269984665640564039457584007913138196557
115792089237316195423570985008687907853269984665640564039457584007913138196599
115792089237316195423570985008687907853269984665640564039457584007913138196929
115792089237316195423570985008687907853269984665640564039457584007913138198097
115792089237316195423570985008687907853269984665640564039457584007913138198129
115792089237316195423570985008687907853269984665640564039457584007913138198229
115792089237316195423570985008687907853269984665640564039457584007913138198243
115792089237316195423570985008687907853269984665640564039457584007913138198247
115792089237316195423570985008687907853269984665640564039457584007913138198319
115792089237316195423570985008687907853269984665640564039457584007913138198459
115792089237316195423570985008687907853269984665640564039457584007913138198699
115792089237316195423570985008687907853269984665640564039457584007913138198811
115792089237316195423570985008687907853269984665640564039457584007913138198901
115792089237316195423570985008687907853269984665640564039457584007913138200079
115792089237316195423570985008687907853269984665640564039457584007913138200187
115792089237316195423570985008687907853269984665640564039457584007913138200587
115792089237316195423570985008687907853269984665640564039457584007913138200607
115792089237316195423570985008687907853269984665640564039457584007913138200851
115792089237316195423570985008687907853269984665640564039457584007913138202143
115792089237316195423570985008687907853269984665640564039457584007913138202183
115792089237316195423570985008687907853269984665640564039457584007913138202233
115792089237316195423570985008687907853269984665640564039457584007913138202353
115792089237316195423570985008687907853269984665640564039457584007913138202533
115792089237316195423570985008687907853269984665640564039457584007913138202611
115792089237316195423570985008687907853269984665640564039457584007913138202627
115792089237316195423570985008687907853269984665640564039457584007913138202681
115792089237316195423570985008687907853269984665640564039457584007913138203989
115792089237316195423570985008687907853269984665640564039457584007913138204079
115792089237316195423570985008687907853269984665640564039457584007913138204271
115792089237316195423570985008687907853269984665640564039457584007913138204453
115792089237316195423570985008687907853269984665640564039457584007913138204871
115792089237316195423570985008687907853269984665640564039457584007913138206019
115792089237316195423570985008687907853269984665640564039457584007913138206137
115792089237316195423570985008687907853269984665640564039457584007913138206193
115792089237316195423570985008687907853269984665640564039457584007913138206311
115792089237316195423570985008687907853269984665640564039457584007913138206589
115792089237316195423570985008687907853269984665640564039457584007913138206649
115792089237316195423570985008687907853269984665640564039457584007913138206923
115792089237316195423570985008687907853269984665640564039457584007913138208219
115792089237316195423570985008687907853269984665640564039457584007913138208681
115792089237316195423570985008687907853269984665640564039457584007913138208849
115792089237316195423570985008687907853269984665640564039457584007913138210067
115792089237316195423570985008687907853269984665640564039457584007913138210129
115792089237316195423570985008687907853269984665640564039457584007913138210199
115792089237316195423570985008687907853269984665640564039457584007913138210561
115792089237316195423570985008687907853269984665640564039457584007913138210693
115792089237316195423570985008687907853269984665640564039457584007913138210697
115792089237316195423570985008687907853269984665640564039457584007913138210829
115792089237316195423570985008687907853269984665640564039457584007913138210889
115792089237316195423570985008687907853269984665640564039457584007913138212119
115792089237316195423570985008687907853269984665640564039457584007913138212259
115792089237316195423570985008687907853269984665640564039457584007913138212353
115792089237316195423570985008687907853269984665640564039457584007913138212401
115792089237316195423570985008687907853269984665640564039457584007913138212481
115792089237316195423570985008687907853269984665640564039457584007913138212599
115792089237316195423570985008687907853269984665640564039457584007913138213957
115792089237316195423570985008687907853269984665640564039457584007913138214609
115792089237316195423570985008687907853269984665640564039457584007913138216127
115792089237316195423570985008687907853269984665640564039457584007913138216529
115792089237316195423570985008687907853269984665640564039457584007913138216841
115792089237316195423570985008687907853269984665640564039457584007913138216897
115792089237316195423570985008687907853269984665640564039457584007913138218239
115792089237316195423570985008687907853269984665640564039457584007913138218263
115792089237316195423570985008687907853269984665640564039457584007913138218599
115792089237316195423570985008687907853269984665640564039457584007913138218793
115792089237316195423570985008687907853269984665640564039457584007913138219979
115792089237316195423570985008687907853269984665640564039457584007913138220017
115792089237316195423570985008687907853269984665640564039457584007913138220383
115792089237316195423570985008687907853269984665640564039457584007913138220563
115792089237316195423570985008687907853269984665640564039457584007913138220683
115792089237316195423570985008687907853269984665640564039457584007913138220717
115792089237316195423570985008687907853269984665640564039457584007913138222111
115792089237316195423570985008687907853269984665640564039457584007913138222213
115792089237316195423570985008687907853269984665640564039457584007913138222339
115792089237316195423570985008687907853269984665640564039457584007913138222681
115792089237316195423570985008687907853269984665640564039457584007913138222717
115792089237316195423570985008687907853269984665640564039457584007913138222843
115792089237316195423570985008687907853269984665640564039457584007913138222889
115792089237316195423570985008687907853269984665640564039457584007913138224247
115792089237316195423570985008687907853269984665640564039457584007913138224359
115792089237316195423570985008687907853269984665640564039457584007913138224511
115792089237316195423570985008687907853269984665640564039457584007913138224533
115792089237316195423570985008687907853269984665640564039457584007913138225949
115792089237316195423570985008687907853269984665640564039457584007913138225997
115792089237316195423570985008687907853269984665640564039457584007913138226041
115792089237316195423570985008687907853269984665640564039457584007913138226231
115792089237316195423570985008687907853269984665640564039457584007913138226249
115792089237316195423570985008687907853269984665640564039457584007913138226707
115792089237316195423570985008687907853269984665640564039457584007913138226803
115792089237316195423570985008687907853269984665640564039457584007913138226887
115792089237316195423570985008687907853269984665640564039457584007913138227937
""".strip()







def modular_inverse(e:"int", phi:"int"):
	# Extended Euclidean Algorithm
	a, m = e, phi
	m0, y, x = m, 0, 1
	if m == 1:
		return 0
	while a > 1:
		# q is quotient
		q = a // m
		t = m
		# m is remainder now, process same as Euclid's algo
		m = a % m
		a = t
		t = y
		# Update x and y
		y = x - q * y
		x = t
	# Make x positive
	if x < 0:
		x += m0
	return x

def find_large_prime_pair(start:"int", min_difference:"int") -> "tuple[int,int]":
    first_prime = sympy_X_nextprime(start)
    current = first_prime + min_difference #type:ignore
    second_prime = sympy_X_nextprime(current)
    
    while second_prime - first_prime < min_difference: #type:ignore
        second_prime = sympy_X_nextprime(second_prime + 1) #type:ignore
    
    return first_prime, second_prime #type:ignore







@njit(cache=True, fastmath=True, nogil=True)
def _inner_decrypt_convert_to_str(segment:"list[int]") -> "str":
	ret_str = "" 
	for x in segment:
		ret_str += chr(x)
	return ret_str







class RSA:



	@property
	def public_key(self):
		return self.e, self.n
	


	@property
	def private_key(self):
		return self.d, self.n
	


	@property
	def key_size(self):
		assert isinstance(self.n, int)
		return self.n.bit_length()
	


	def __load_primes(self, compressed_primes_file:"str", nprocs:"int"):
		if compressed_primes_file is None:
			self._decoded = _BUNDLED_PRIMES
		else:
			raise NotImplementedError("Loading primes from a file is not yet implemented.")
			


	def __find_e(self, phi):
		e = 65537
		while math_X_gcd(e, phi) != 1:
			e += 2
		return e



	def __init__(self, compressed_primes_file=None):
		self.e:int|None = None
		self.d:int|None = None
		self.phi:int|None = None
		self.p:int|None = None
		self.q:int|None = None

		self._decoded:str|None = None
		self._primes_list:list[int] = []

		nprocs = N_CPUS
		if nprocs > 1 and nprocs % 2 != 0:
			nprocs -= 1
		self._nprocs = nprocs

		self.MIN_PRIMES_DIFF = 100_000_000

		self._already_computed_encrypts = {}
		self._already_computed_decrypts = {}

		self._initialize(compressed_primes_file)
	


	def _initialize(self, compressed_primes_file):
		self.__load_primes(compressed_primes_file, self._nprocs)

		lines = self._decoded.split("\n") #type:ignore

		initial_p = int(random_X_choice(lines))
		initial_q = int(random_X_choice(lines))
		while initial_p == initial_q:
			initial_q = int(random_X_choice(lines))

		self.p, self.q = find_large_prime_pair(initial_p, self.MIN_PRIMES_DIFF)
		
		self.n = self.p * self.q
		self.phi = (self.p - 1) * (self.q - 1)

		self.recompute_keys()



	def recompute_keys(self):
		assert isinstance(self.phi, int)

		self.e = self.__find_e(self.phi)
		self.d = modular_inverse(self.e, self.phi)



	@cache
	def _encrypt(self, x:"str") -> "int":
		if x in self._already_computed_encrypts:
			return self._already_computed_encrypts[x]
		n = pow(ord(x), self.e, self.n) #type:ignore
		self._already_computed_encrypts[x] = n
		return n



	def encrypt(self, message: str) -> Generator[int,None,None]:
		return (self._encrypt(char) for char in message)

	

	@cache
	def _inner_decrypt_compute(self, x) -> "int":
		if x in self._already_computed_decrypts:
			return self._already_computed_decrypts[x]
		n = pow(x, self.d, self.n)
		self._already_computed_decrypts[x] = n
		return n



	def __decrypt(self, encrypted_nums: Generator[int,None,None]) -> Generator[int,None,None]:
		for x in encrypted_nums:
			yield self._inner_decrypt_compute(x)



	def _decrypt(self, encrypted_nums: Generator[int,None,None], chunk_size:"int") -> "Generator[str,None,None]":
		
		def process_chunk(chunk) -> "str":
			with ThreadPoolExecutor(max_workers=N_CPUS) as executor:
				return "".join(executor.map(_inner_decrypt_convert_to_str, chunk))

		chunk = []
		for res in self.__decrypt(encrypted_nums):
			chunk.append(res)
			if len(chunk) == chunk_size * N_CPUS:
				yield process_chunk(
					[chunk[chunk_size*(i):chunk_size*(i+1)] for i in range(N_CPUS)]
				)
				chunk.clear()

		if chunk:
			yield process_chunk([chunk])



	def decrypt(self, encrypted_nums: Generator[int,None,None]) -> "Generator[str,None,None]":
		for num in self.__decrypt(encrypted_nums):
			yield _inner_decrypt_convert_to_str([num])



	def full_decrypt(self, encrypted_nums: Generator[int,None,None], chunk_size=51200) -> "str":
		ret_str = ""
		for chunk in self._decrypt(encrypted_nums, chunk_size):
			ret_str += chunk
		return ret_str
	


	def set_private_key(self, d:"int", n:"int"):
		self.d, self.n = d, n



	def set_public_key(self, e:"int", n:"int"):
		self.e, self.n = e, n



	@staticmethod
	def from_public_key(e:"int", n:"int", compressed_primes_file:str|None=None):
		rsa = RSA(compressed_primes_file)
		rsa.e, rsa.n = e, n
		return rsa
	


