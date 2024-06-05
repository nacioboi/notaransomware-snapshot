from ._Debug_Context import Debug_Context
from ._Debug_Mode import Debug_Mode

import inspect
from pickle import dumps as pickle_X_dumps
from pickle import loads as pickle_X_loads
from typing import Any, Literal, Generic, Type, TypeVar
from enum import Enum

Logger_X_set__ACCEPTED_LITS_T = Literal["global_context"]







SINGLE_DYNAMIC_PIE = {}
DVC_DM_T = TypeVar("DVC_DM_T", bound=Enum)
DVC_DC_T = TypeVar("DVC_DC_T", bound=Enum)
class DynamicVariableContainer (Generic[DVC_DM_T, DVC_DC_T]):



	def __init__(self, modes_t: "Type[DVC_DM_T]", contexts_t: "Type[DVC_DC_T]"):
		global SINGLE_DYNAMIC_PIE

		self.name = "LOGGER_HELPER"

		for item in modes_t:
			setattr(self, item.name.lower(), property(lambda self, item=item: item))

		SINGLE_DYNAMIC_PIE[self.name] = {}
		DynamicVariableContainer._post_setup(self.name)
	


	@staticmethod
	def _post_setup(__name:str):
		global SINGLE_DYNAMIC_PIE

		def __wrapper_for_set(*args, **kwargs):
			DynamicVariableContainer._set(__name, *args, **kwargs)

		def __wrapper_for_del(*args, **kwargs):
			DynamicVariableContainer._del(__name, *args, **kwargs)

		def __wrapper_for_get_children(*args, **kwargs):
			return DynamicVariableContainer._get_children(__name, *args, **kwargs)

		def __wrapper_for_get_name(*args, **kwargs):
			return DynamicVariableContainer._get_name(__name, *args, **kwargs)

		SINGLE_DYNAMIC_PIE[__name]["set"] = __wrapper_for_set
		SINGLE_DYNAMIC_PIE[__name]["del"] = __wrapper_for_del
		SINGLE_DYNAMIC_PIE[__name]["get_children"] = __wrapper_for_get_children
		SINGLE_DYNAMIC_PIE[__name]["get_name"] = __wrapper_for_get_name
	


	@staticmethod
	def _set(__name_of_self:str, name: str, value) -> None:
		global SINGLE_DYNAMIC_PIE

		name_of_self = __name_of_self
		piece_of_pie = SINGLE_DYNAMIC_PIE[name_of_self]

		piece_of_pie[name] = value



	@staticmethod
	def _del(__name_of_self:str, name: str) -> None:
		global SINGLE_DYNAMIC_PIE

		name_of_self = __name_of_self
		piece_of_pie = SINGLE_DYNAMIC_PIE[name_of_self]

		del piece_of_pie[name]



	@staticmethod
	def _get_children(__name_of_self:str) -> dict:
		global SINGLE_DYNAMIC_PIE

		name_of_self = __name_of_self
		piece_of_pie = SINGLE_DYNAMIC_PIE[name_of_self]

		return piece_of_pie
	


	@staticmethod
	def _get_name(__name_of_self:str) -> str:
		return __name_of_self



	def __getattribute__(self, __name: str):
		global SINGLE_DYNAMIC_PIE

		name_of_self = super().__getattribute__("name")
		piece_of_pie = SINGLE_DYNAMIC_PIE[name_of_self]

		if __name in piece_of_pie:
			return piece_of_pie[__name]
		
		err_str = f"'{name_of_self}' object has no attribute '{__name}'"
		raise AttributeError(err_str)






DM_T = TypeVar("DM_T", bound=Enum)
DC_T = TypeVar("DC_T", bound=Enum)
class Experimental_Logger (Generic[DM_T, DC_T]):



	def __init__(self, modes_t:"Type[DM_T]", contexts_t:"Type[DC_T]") -> None:
		self._configuration_vars = {}
		self.debug_modes:"dict[str,Debug_Mode]" = {}
		self.contexts:"dict[str,Debug_Context]" = {}

		self._LOGGER_HELPER = DynamicVariableContainer(modes_t,contexts_t)

		self.__inner__add_debug_mode("disabled", 0)
		self.debug_modes["disabled"].override_is_active(False)

		modes_names = [item.name for item in modes_t]
		contexts_names = [item.name for item in contexts_t]

		for name in modes_names:
			is_separate = True if name.startswith("SEPARATED_") else False
			name = name.lstrip("SEPARATED_")
			self.__add_debug_mode(name, is_separate)
		
		for name in contexts_names:
			self.__add_debug_context(name)

		self.active_debug_mode:"Debug_Mode" = self.debug_modes["disabled"]


	
	def __call__(self, *args: Any, **kwds: Any) -> DynamicVariableContainer[DM_T,DC_T]:
		return self._LOGGER_HELPER



	def show(self, mode:"DM_T") -> None:
		self.active_debug_mode = self.debug_modes[mode.name]



	def __inner__add_debug_mode(self, name:"str", level:"int"):
		# Check that the name isn't already in use.
		if name in self.debug_modes:
			raise Exception(f"Debug mode {name} already exists.")

		# Construct the debug mode.
		self.debug_modes[name] = Debug_Mode(name, level, None)

		self.__update_state_after_adding_debug_mode(name)

	

	def __update_state_after_adding_debug_mode(self, name_of_debug_mode):
		# The below wrapper is what actually gets called when you do `plsp().<insert name of debug mode>(...)`
		# NOTE: Remember, this is only for the global context.
		# NOTE: E.g., if we do `plsp().our_debug_mode(...)`, this would invoke the global context since we did not do
		# NOTE:   `plsp().our_context.our_debug_mode(...)`.
		def wrapper_for_global_handler(*args, **kwargs):
			context = self.contexts[self._configuration_vars["global_context"]]
			mode = self.debug_modes[name_of_debug_mode]
			context._handle(mode, self.active_debug_mode, *args, **kwargs)

		# And here is the wrapper for when we specify a context.
		# E.g., `plsp().our_context.our_debug_mode(...)`...
		# This wrapper is the `our_debug_mode` part.
		# NOTE: The actual `our_context` is created in the `add_debug_context` method. It is a
		# NOTE:   `DynamicVariableContainer` instance that serves as a child of the `LOGGER_HELPER` instance,
		# NOTE:   which itself, is an instance of `DynamicVariableContainer`.
		def wrapper_for_context_specified_handler(context, *args, **kwargs):
			mode = self.debug_modes[name_of_debug_mode]
			context._handle(mode, self.active_debug_mode, *args, **kwargs)

		# We only want to use the `wrapper_for_global_handler` if the global context is set.
		if self._configuration_vars.get("global_context") is not None:
			self._LOGGER_HELPER.set(name_of_debug_mode, wrapper_for_global_handler)

		# Now to update the context-specific wrappers.
		keys_no_globals = [k for k in self._LOGGER_HELPER.get_children().keys() if k not in self.debug_modes.keys()]
		keys_no_globals = [k for k in keys_no_globals if k not in ["set", "del", "get_children", "get_name"]]
		for child_key in keys_no_globals:
			container = self._LOGGER_HELPER.get_children()[child_key]
			def _wrapper_for_the_wrapper(*args, **kwargs):
				nonlocal container
				# Get the key of `DYNAMIC_PIE` that corresponds to the context.
				# Remember that the context is itself, a `DynamicVariableContainer` instance.
				context = self.contexts[container.get_name()]
				wrapper_for_context_specified_handler(context, *args, **kwargs)
			container.set(name_of_debug_mode, _wrapper_for_the_wrapper)



	def __add_debug_mode(self, name:"str", separate=False):
		if separate:
			level = -1
		else:
			level = len(self.debug_modes)+1

		self.__inner__add_debug_mode(name, level)



	def __add_debug_context(self, name:"str"):
		if name in self.contexts:
			raise Exception(f"Debug context {name} already exists.")
		self.contexts[name] = Debug_Context(name)
		self._LOGGER_HELPER.set(name, DynamicVariableContainer(name))



	def set(self, name:"Logger_X_set__ACCEPTED_LITS_T", value) -> None:
		accepted_vars = ["global_context"]

		if name not in accepted_vars:
			raise Exception(f"Variable {name} not accepted.")

		constant_vars = ["global_context"]
		if name in constant_vars:
			if name in self._configuration_vars:
				raise Exception(f"Variable {name} already set.")

		self._configuration_vars[name] = value

		





