import dataclasses







@dataclasses.dataclass
class Debug_Mode:



	name: str
	level: int
	overridden_instructions: "list[str]|None"



	def override_is_active(self, is_active: bool) -> None:
		if self.overridden_instructions is None:
			self.overridden_instructions = []
		self.overridden_instructions.append(
			f"is_active={str(is_active)}"
		)
	


	def override_write_to_handle(self, file_handle: "int|None") -> None:
		if self.overridden_instructions is None:
			self.overridden_instructions = []
		self.overridden_instructions.append(
			f"write_to_handle={'None' if file_handle is None else str(file_handle)}"
		)


	
	def override_write_to_file(self, file_name: "str|None") -> None:
		if self.overridden_instructions is None:
			self.overridden_instructions = []
		self.overridden_instructions.append(
			f"write_to_file={'None' if file_name is None else file_name}"
		)







