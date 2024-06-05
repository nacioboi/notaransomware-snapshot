import os, sys
sys.path.append(os.path.abspath(
	os.path.join(os.path.dirname(__file__), "src", "helpers")
))
from src.helpers.rsa import RSA

from base64 import b64decode
import json

RSA_PRIV_KEY_B = None
RSA_PRIV_KEY_A = None
RSA_PUBL_KEY_B = None
RSA_PUBL_KEY_A = None



def decrypt_from_report(report_file_path):
	if not os.path.isabs(report_file_path):
		report_file_path = os.path.abspath(report_file_path)
	with open(report_file_path, "r") as report_file:
		report = report_file.read()
	data = json.loads(report)
	assert isinstance(RSA_PUBL_KEY_A, int)
	assert isinstance(RSA_PUBL_KEY_B, int)
	assert isinstance(RSA_PRIV_KEY_A, int)
	assert isinstance(RSA_PRIV_KEY_B, int)
	public_key = [RSA_PUBL_KEY_A, RSA_PUBL_KEY_B]
	private_key = [RSA_PRIV_KEY_A, RSA_PRIV_KEY_B]
	my_rsa = RSA()
	my_rsa.set_private_key(int(private_key[0]), int(private_key[1]))
	my_rsa.set_public_key(int(public_key[0]), int(public_key[1]))
	files = data["files"]
	decrypted_files:"dict[str,list[str]]" = {}
	for file_name, file_content in files.items():
		if not decrypted_files.get(file_name):
			decrypted_files[file_name] = []
		res = "".join(my_rsa.decrypt(int(x) for x in file_content.split(",")))
		decrypted_files[file_name].append(b64decode(res.encode()).decode())
	return decrypted_files



if __name__ == "__main__":
	usage_msg = f"Usage: python {sys.argv[0]} "
	usage_msg += "<<<report file path>>> "
	usage_msg += "<<<rsa priv key b>>> "
	usage_msg += "<<<rsa priv key a>>> "
	usage_msg += "<<<rsa publ key b>>> "
	usage_msg += "[-o: do output ->decoded.json]"
	if not (len(sys.argv) == 5 or len(sys.argv) == 6):
		print(usage_msg)
		exit(1)
	if not (len(sys.argv) == 6 and sys.argv[5] == "-o"):
		print(usage_msg)
		exit(1)
	DO_OUTPUT = len(sys.argv) == 6
	if DO_OUTPUT:
		abs_path = os.path.abspath("decoded.json")
		if os.path.exists(abs_path):
			print(f"The [{abs_path}] file/dir already exists!")
			exit(1)
	REPORT_PATH = sys.argv[1]
	RSA_PRIV_KEY_B = int(sys.argv[2])
	RSA_PRIV_KEY_A = int(sys.argv[3])
	RSA_PUBL_KEY_B = int(sys.argv[4])
	RSA_PUBL_KEY_A = 65537
	decrypted_files = decrypt_from_report(REPORT_PATH)
	if DO_OUTPUT:
		abs_path = os.path.abspath("decoded.json")
		with open(abs_path, "w") as f:
			json.dump(decrypted_files, f)
	else:
		for file_name, file_content in decrypted_files.items():
			print(f"File: {file_name}")
			for line in file_content:
				print(line, end="")
