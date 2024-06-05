import os, sys
sys.path.append(os.path.abspath(
	os.path.join(os.path.dirname(__file__), "src", "helpers")
))
from src.helpers.rsa import RSA

from base64 import b64decode
import json

def decrypt_from_report(report_file_path):
	if not os.path.isabs(report_file_path):
		report_file_path = os.path.abspath(report_file_path)
	with open(report_file_path, "r") as report_file:
		report = report_file.read()
	data = json.loads(report)
	public_key = data["public_key"]
	private_key = data["private_key"]
	my_rsa = RSA()
	my_rsa.set_private_key(int(private_key[0]), int(private_key[1]))
	my_rsa.set_public_key(int(public_key[0]), int(public_key[1]))
	files = data["files"]
	decrypted_files:"dict[str,list[str]]" = {}
	for file_name, file_content in files.items():
		for line in file_content:
			if not decrypted_files.get(file_name):
				decrypted_files[file_name] = []
			decrypted_files[file_name].append(b64decode(
				my_rsa.full_decrypt(int(x) for x in line.split(",")).encode()
			).decode())
	return decrypted_files


if __name__ == "__main__":
	import argparse
	parser = argparse.ArgumentParser(description="If you do not know what this is, turn away and dont look back.")
	parser.add_argument("report_file_path", help="Path to the report file.")
	parser.add_argument("-o", "--output", help="Output directory for the decrypted files.")
	args = parser.parse_args()
	decrypted_files = decrypt_from_report(args.report_file_path)
	if args.output:
		if not os.path.isabs(args.output):
			args.output = os.path.abspath(args.output)
		for file_name, file_content in decrypted_files.items():
			with open(os.path.join(args.output, file_name), "w") as file:
				file.write("\n".join(file_content))
	else:
		for file_name, file_content in decrypted_files.items():
			print(f"File: {file_name}")
			for line in file_content:
				print(line, end="")
