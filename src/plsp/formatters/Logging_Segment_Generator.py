from abc import ABC as __abc_X_ABC
from abc import abstractmethod as _abc_X_abstractmethod

import base64 as _base64
from typing import Any
from dataclasses import dataclass as _dataclass
from .._Color_Configuration import Color_Configuration







@_dataclass
class Logging_Segment_Piece:
	color_config: Color_Configuration|None = None
	value: str|None = None







class I_Logging_Segment_Generator (__abc_X_ABC):



	def get_id(self) -> str:
		name = self.__class__.__name__
		b64_name = _base64.b64encode(name.encode("utf-8")).decode("utf-8")
		return f"|`FORMATTER_POSTFIX`{b64_name}|"



	@staticmethod
	def _handle(inst) -> str:
		I_Logging_Segment_Generator.validate_pieces(inst)
		inst.impl_handle()
		addition = ""
		pieces:"list[Logging_Segment_Piece]" = inst.impl_combine_pieces()
		for p in pieces:
			assert p.value is not None
			if p.color_config:
				addition += str(p.color_config)
				addition += p.value
				addition += "\033[0m"
			else:
				addition += p.value
		return f"{addition}{inst.get_id()}"



	@staticmethod
	def validate_pieces(inst) -> None:
		pieces = inst.impl_pieces()
		if len(pieces) == 0:
			raise Exception("The formatter did not return any pieces.")
		for piece in pieces:
			if not isinstance(piece, str):
				raise Exception("The formatter returned a piece that is not a string.")
			if piece == "":
				raise Exception("The formatter returned an empty piece.")
		insts_pieces = []
		for key in inst.__dir__():
			if type(getattr(inst,key)) == Logging_Segment_Piece:
				insts_pieces.append(key)
		for piece in pieces:
			if not piece in insts_pieces:
				raise Exception(f"Piece, [{piece}], was not found as a property.")



	@_abc_X_abstractmethod
	def impl_handle(self) -> None:
		pass



	@_abc_X_abstractmethod
	def impl_pieces(self) -> "list[str]":
		pass



	@_abc_X_abstractmethod
	def impl_combine_pieces(self) -> list[Logging_Segment_Piece]:
		pass







class Logging_Segment:
	def __init__(self, id:"str", s:"str") -> None:
		self.id = id
		self.s = s
		






def _new_segment_from_str_and_head(s:"str", head:"int") -> tuple:
	s = s[head:]
	head = head + len(s)
	splitted = s.split("|`FORMATTER_POSTFIX`")
	return head, Logging_Segment(_base64.b64decode(splitted[1].encode()).decode(), splitted[0])

	