from ._Logger import Logger

from os.path import exists as os_path_X_exists
from os import remove as os_X_remove
from os.path import dirname as os_path_X_dirname
from os.path import join as os_path_X_join
from os import mkdir as os_X_mkdir
from os import walk as os_X_walk
from pickle import loads as pickle_X_loads
from pickle import dumps as pickle_X_dumps
from tempfile import mkdtemp as tempfile_X_mkdtemp
from hashlib import sha256 as hashlib_X_sha256
from random import randint as random_X_randint



def _get_temp_dir() -> str:
	parent_dir = tempfile_X_mkdtemp()
	parent_dir = os_path_X_dirname(parent_dir)

	temp_dir = None

	for root, dirs, _ in os_X_walk(parent_dir):
		for dir in dirs:
			path = os_path_X_join(root, dir)
			if path.endswith("_PY_plsp_SHAREDLOGGER_"):
				temp_dir = path
				break

	if not temp_dir:
		random_seq = "".join([str(random_X_randint(0, 9)) for _ in range(10)])
		temp_dir = os_path_X_join(parent_dir, f"{random_seq}_PY_plsp_SHAREDLOGGER_")
		os_X_mkdir(temp_dir)

	return temp_dir



def save(logger_inst:"Logger", inst_name:"str"):
	hashed = hashlib_X_sha256()
	hashed.update(inst_name.encode("utf-8"))
	inst_name = f"{hashed.hexdigest()}_PY_plsp_SHAREDLOGGER_.pkl"
	temp_dir = _get_temp_dir()
	if os_path_X_exists(os_path_X_join(temp_dir, inst_name)):
		os_X_remove(os_path_X_join(temp_dir, inst_name))
	with open(os_path_X_join(temp_dir, inst_name), "wb") as file:
		file.write(pickle_X_dumps(
			Logger._pickle_dump(logger_inst)
		))
	
	

def load(inst_name:str) -> "Logger":
	temp_dir = _get_temp_dir()
	hashed = hashlib_X_sha256()
	hashed.update(inst_name.encode("utf-8"))
	inst_name = f"{hashed.hexdigest()}_PY_plsp_SHAREDLOGGER_.pkl"
	found_file = None
	for _, _, files in os_X_walk(temp_dir):
		for file in files:
			if file == inst_name:
				found_file = file
				break
	if not found_file:
		raise Exception("Could not find the specified file.")

	with open(os_path_X_join(temp_dir, found_file), "rb") as file:
		return Logger._pickle_load(
			pickle_X_loads(file.read())
		)
				





