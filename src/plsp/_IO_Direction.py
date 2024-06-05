import dataclasses



@dataclasses.dataclass
class IO_Direction:
	do_encode: bool
	file_handle: int|None
	file_path: str|None
	do_flush: bool = False
	do_serialize: bool = False

	def validate(self):
		if self.file_handle and self.file_path:
			raise ValueError("Cannot have both file handle and file path set.")
		

