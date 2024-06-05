# DO NOT MODIFY THIS, OR, LINES BELOW, UNTIL INSTRUCTED.
if True:
	# If not running in `cx_Freeze`, then the following code will run:
	import sys, os ; sys.path.append(os.path.dirname(os.path.abspath(__file__)))
	from rsa import RSA
else:
	# Otherwise, we are using `cx_Freeze`:
	from .rsa import RSA
# MODIFICATIONS BEYOND THIS POINT IS PERMITTED.

from json import loads, dumps
from typing import Callable
from refvars import Reference, new, disable_runtime_usage_checks
disable_runtime_usage_checks()
from socket import timeout as socket_X_timeout
from socket import SHUT_RDWR as socket_X_SHUT_RDWR
from socket import socket as socket_X_socket
from zlib import compress, decompress







SPLITTER = "||-_-||"  # Nice little face :D







class RSA_Crypto_ZLIB_Net_Controller:



	def __init__(self,
			sock:"socket_X_socket",
			addr:"tuple[str,int]",
			on_connection_reset_cb:"Callable[[RSA_Crypto_ZLIB_Net_Controller,Exception|None],None]"
	):
		self.__sock = sock
		self.__on_connection_reset_cb = on_connection_reset_cb

		self.endpoint_address = addr

		# Generally, since python is an extremely slow language, a large buffer size is recommended.
		# Also, my code is bad, so recursion is used in the recv method, which is why a large buffer size is better.
		self.BUFFER_SIZE = 40960

		self.__rsa_sender_instance:"RSA|None" = None
		self.__rsa_receiver_instance:"RSA|None" = None

		self.handshake_complete = False



	def __flush_socket_buffer(self, timeout=3):
		from time import time

		self.__sock.setblocking(False)
		end_time = time() + timeout
		
		while True:
			try:
				data = self.__sock.recv(4096)
				if not data:
					break  # No more data
			except BlockingIOError:
				break
			except ConnectionResetError as e:
				self.__on_connection_reset_cb(self, e)
				break
			if time() >= end_time:
				break
		
		self.__sock.setblocking(True)



	def conduct_handshake(self):
		prev_timeout = self.__sock.gettimeout()
		self.__sock.settimeout(999)
		try:
			self.__rsa_receiver_instance = RSA()
			try:
				self.__sock.sendall(dumps({
					"private_key": self.__rsa_receiver_instance.private_key,
					"public_key": self.__rsa_receiver_instance.public_key
				}).encode('utf-8'))
				msg = self._forced_ll_recv(10240)
				if msg:
					endpoints_msg = msg.decode()
					endpoints_public_key = loads(endpoints_msg)['public_key']
					self.__rsa_sender_instance = RSA.from_public_key(endpoints_public_key[0], endpoints_public_key[1])
				print("Handshake complete")
			except ConnectionResetError as e:
				self.__on_connection_reset_cb(self, e)
		except socket_X_timeout:
			if self.__not_a_bad_timeout_flag:
				self.__not_a_bad_timeout_flag = False
			else:
				raise Exception("Handshake timed out")
		finally:
			self.__sock.settimeout(prev_timeout)
		while self.__rsa_receiver_instance is None:
			self.__flush_socket_buffer()
			self.conduct_handshake()
		while self.__rsa_sender_instance is None:
			self.__flush_socket_buffer()
			self.conduct_handshake()
		self.handshake_complete = True



	def _forced_ll_recv(self, size:"int") -> "bytes|None":
		prev_timeout = self.__sock.gettimeout()
		self.__sock.settimeout(999_999)
		try:
			data = self.__sock.recv(size)
		except socket_X_timeout:
			raise Exception("Waited 277.78 hours, still no response.")
		finally:
			self.__sock.settimeout(prev_timeout)
		return data



	def __send(self, msg:"str"):
		compressed = compress(msg.encode())
		data = str(len(compressed)).encode() + chr(0).encode() + compressed
		self.__sock.sendall(data)

	def send(self, msg:"str"):
		try:
			assert self.__rsa_sender_instance is not None
			assert self.__rsa_receiver_instance is not None
			if SPLITTER in msg:
				from base64 import b64encode
				msg = b64encode(msg.encode()).decode()
			if self.handshake_complete:
				if msg == "":
					return
				encrypted = self.__rsa_sender_instance.encrypt(msg)
				dumped = [str(x) for x in encrypted]
				if SPLITTER in dumped:
					raise Exception("Cannot send data with the splitter in it.")
				data = SPLITTER.join(dumped)
				if SPLITTER in msg:
					data = "B" + data
				else:
					data = "A" + data
				self.__send(data)
			else:
				raise Exception("Handshake not complete")
		except ConnectionResetError as e:
			self.__on_connection_reset_cb(self, e)
			return



	def __deep_inner_recv(self, amount:"int") -> "str|None":
		buff = bytearray()
		rec_size = amount
		while len(buff) < amount:
			try:
				new = self.__sock.recv(rec_size)
			except ConnectionResetError as e:
				self.__on_connection_reset_cb(self, e)
				return None
			rec_size -= len(new)
			buff.extend(new)
		return decompress(buff).decode()

	def __inner_recv(self, cancel_flag_p:"Reference|None"=None, time_between=3) -> "str|None":
		assert self.__rsa_sender_instance is not None
		assert self.__rsa_receiver_instance is not None

		cancel_flag_p = cancel_flag_p or new[bool](False).get_ref()

		prev_timeout = self.__sock.gettimeout()
		while cancel_flag_p.get() == False:
			try:
				self.__sock.settimeout(time_between)
				self.__sock.setblocking(False)
				try:
					init_received = b""
					while not init_received.endswith(b"\x00"):
						init_received += self.__sock.recv(1)
						if init_received == b"":
							return None
				except BlockingIOError:
					continue
				finally:
					self.__sock.setblocking(True)
				self.__sock.settimeout(prev_timeout)
				data = self.__deep_inner_recv(int(init_received.strip(b"\x00")))
				if not data:
					return None
				if data.startswith("B"):
					from base64 import b64decode
					data = b64decode(data[1:]).decode()
				else:
					data = data[1:]
				encrypted = data.split(SPLITTER)
				decrypted = self.__rsa_receiver_instance.full_decrypt(int(s) for s in encrypted)
				return decrypted
			except socket_X_timeout:
				pass
			finally:
				self.__sock.settimeout(prev_timeout)
	
	def recv(self, cancel_flag_p:"Reference|None"=None, time_between=3) -> "str|None":
		try:
			msg = self.__inner_recv(cancel_flag_p, time_between)
			if msg is None:
				return None
			if msg.startswith("ERROR"):
				from pickle import loads
				from base64 import b64decode
				self.__on_connection_reset_cb(self, loads(b64decode(msg[5:].encode())))
			else:
				return msg
		except ConnectionResetError as e:
			self.__on_connection_reset_cb(self, e)
			return None
		return ""



	def shutdown(self, e:"Exception|None"):
		from pickle import dumps
		from base64 import b64encode
		if e is not None:
			self.send("ERROR"+b64encode(dumps(e)).decode())
		self.__sock.shutdown(socket_X_SHUT_RDWR)
		self.__sock.close()
		self.reset_state()



	def reset_state(self):
		self.handshake_complete = False
		self.__rsa_sender_instance = None
		self.__rsa_receiver_instance = None
		self.__extra = b""




