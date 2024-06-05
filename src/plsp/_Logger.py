from ._Debug_Context import Debug_Context

from pickle import dumps as pickle_X_dumps
from pickle import loads as pickle_X_loads
from typing import Any, Callable, Literal
from threading import Thread
from inspect import getsource as inspect_X_getsource

Logger_X_set__ACCEPTED_LITS_T = Literal["global_context"]







DYNAMIC_PIE = {}
class DynamicVariableContainer:



	"""
	Represents a container for dynamically managing variables.

	This class allows you to dynamically set and retrieve variables without explicitly defining them in the class definition.

	Usage:
	```python
	# Create a DynamicVariableContainer instance
	container = DynamicVariableContainer("container1")

	# Dynamically set a variable in the container
	container.set("variable1", 10)

	# Dynamically get the value of a variable from the container
	value = container.variable1
	print(value)  # Output: 10

	# Dynamically get all the variables in the container
	variables = container.get_children()

	# Dynamically delete a variable from the container
	container.del("variable1")
	```

	Attributes:
		name (str): The name of the container.

	Notes on the hackiness of this class:
	- This class uses a global dictionary to store the variables.
	- This class uses a static method to set and delete the variables, among other things.

	Because of this, please DO NOT EVER call the static methods directly.
	Instead, use the `set`, `del`, and `get_children` methods of the instance of this class.
	Beware that you will not get good intellisense support but it WILL work, trust me bro. ^_^
	"""



	def __init__(self, name):
		global DYNAMIC_PIE

		self.name = name

		DYNAMIC_PIE[name] = {}
		DynamicVariableContainer._post_setup(name)
	


	@staticmethod
	def _post_setup(__name:str):
		global DYNAMIC_PIE

		def __wrapper_for_set(*args, **kwargs):
			DynamicVariableContainer._set(__name, *args, **kwargs)

		def __wrapper_for_del(*args, **kwargs):
			DynamicVariableContainer._del(__name, *args, **kwargs)

		def __wrapper_for_get_children(*args, **kwargs):
			return DynamicVariableContainer._get_children(__name, *args, **kwargs)

		def __wrapper_for_get_name(*args, **kwargs):
			return DynamicVariableContainer._get_name(__name, *args, **kwargs)

		DYNAMIC_PIE[__name]["set"] = __wrapper_for_set
		DYNAMIC_PIE[__name]["del"] = __wrapper_for_del
		DYNAMIC_PIE[__name]["get_children"] = __wrapper_for_get_children
		DYNAMIC_PIE[__name]["get_name"] = __wrapper_for_get_name
	


	@staticmethod
	def _set(__name_of_self:str, name: str, value) -> None:
		global DYNAMIC_PIE

		name_of_self = __name_of_self
		piece_of_pie = DYNAMIC_PIE[name_of_self]

		piece_of_pie[name] = value



	@staticmethod
	def _del(__name_of_self:str, name: str) -> None:
		global DYNAMIC_PIE

		name_of_self = __name_of_self
		piece_of_pie = DYNAMIC_PIE[name_of_self]

		del piece_of_pie[name]



	@staticmethod
	def _get_children(__name_of_self:str) -> dict:
		global DYNAMIC_PIE

		name_of_self = __name_of_self
		piece_of_pie = DYNAMIC_PIE[name_of_self]

		return piece_of_pie
	


	@staticmethod
	def _get_name(__name_of_self:str) -> str:
		return __name_of_self



	def __getattribute__(self, __name: str) -> Callable:
		global DYNAMIC_PIE

		name_of_self = super().__getattribute__("name")
		piece_of_pie = DYNAMIC_PIE[name_of_self]

		if __name in piece_of_pie:
			return piece_of_pie[__name]
		
		def on_call_do_nothing(*args, **kwargs):
			pass

		return on_call_do_nothing







class Logger:



	"""
	The actual meat and potatoes of the logging system.
	"""


	@staticmethod
	def __pickle_dump_debug_contexts(inst:"Logger") -> "bytes":
		ret_dict = {}
		for key in inst.contexts:
			if not ret_dict.get(key):
				ret_dict[key] = {}
			ret_dict[key]["name"] = inst.contexts[key].name
			ret_dict[key]["LSGs"] = inst.contexts[key].LSGs
			# TODO: The below may cause some problems. For e.g., referencing any non builtin classes will fail.
			# NOTE: The e.g. will fail because we are only capturing the source code of the class and 
			# NOTE:   this does not include the imports.
			source_code = inspect_X_getsource(inst.contexts[key].final_formatter.__class__)
			ret_dict[key]["final_formatter::source_code"] = source_code
			ret_dict[key]["is_active"] = inst.contexts[key].is_active
			ret_dict[key]["directions"] = inst.contexts[key].directions

		return pickle_X_dumps(ret_dict)



	@staticmethod
	def _pickle_dump(inst:"Logger") -> "dict":	
		attrs = {}
		attrs["configuration_vars"] = pickle_X_dumps(inst._configuration_vars)
		attrs["active_debug_mode"] = pickle_X_dumps(inst.active_debug_mode.name)
		attrs["debug_contexts"] = Logger.__pickle_dump_debug_contexts(inst)
		attrs["debug_modes"] = pickle_X_dumps(inst.debug_modes)
		return attrs



	@staticmethod
	def _pickle_load(data:"dict") -> "Logger":
		x = {}
		for d in data:
			x[d] = pickle_X_loads(data[d])
		data = x
		pickled_contexts = data["debug_contexts"]
		data["debug_contexts"] = {}
		from .formatters.I_Final_Formatter import I_Final_Formatter
		from .formatters.Logging_Segment_Generator import Logging_Segment
		globals()["I_Final_Formatter"] = I_Final_Formatter
		globals()["Logging_Segment"] = Logging_Segment
		for ctx_v in pickled_contexts.values():
			new_ctx = Debug_Context(ctx_v["name"])
			new_ctx.LSGs = ctx_v["LSGs"]
			new_ctx.is_active = ctx_v["is_active"]
			new_ctx.directions = ctx_v["directions"]
			exec(ctx_v["final_formatter::source_code"], globals(), locals())
			# TODO: This is hardcoded class name `my_final_formatter`.
			new_ctx.final_formatter = locals()["my_final_formatter"]
			data["debug_contexts"][ctx_v["name"]] = new_ctx
		inst = Logger()
		inst._configuration_vars = data["configuration_vars"]
		inst.debug_modes = data["debug_modes"]
		inst.active_debug_mode = inst.debug_modes[data["active_debug_mode"]]
		inst.contexts = data["debug_contexts"]
		for name in inst.contexts:
			inst._LOGGER_HELPER.set(name, DynamicVariableContainer(name))
		for name in inst.debug_modes:
			# TODO: CALLBACKS ARE NOT SUPPORTED WHEN PICKLING LOGGER.
			inst.__update_state_after_adding_debug_mode(name, None)
		return inst



	def __init__(self) -> None:
		self._configuration_vars = {}
		self._callbacks:"dict[str,tuple[Callable,bool]]" = {}

		self.debug_modes:"dict" = {}
		self.contexts:"dict[str,Debug_Context]" = {}

		self._LOGGER_HELPER = DynamicVariableContainer("LOGGER_HELPER")

		self.__add_debug_mode("disabled", 0, None)
		self.debug_modes["disabled"].override_is_active(False)

		self.active_debug_mode = self.debug_modes["disabled"]


	
	def __call__(self, *args: Any, **kwds: Any) -> Any:
		return self._LOGGER_HELPER



	def show(self, name:"str") -> None:
		self.active_debug_mode = self.debug_modes[name]



	def __add_debug_mode(self, name:"str", level:"int", callback:"str|None"):
		from ._Debug_Mode import Debug_Mode
		# Check that the name isn't already in use.
		if name in self.debug_modes:
			raise Exception(f"Debug mode {name} already exists.")

		# Construct the debug mode.
		self.debug_modes[name] = Debug_Mode(name, level, None)

		self.__update_state_after_adding_debug_mode(name, callback)

	

	def __update_state_after_adding_debug_mode(self, name_of_debug_mode, callback:"str|None"):
		# The below wrapper is what actually gets called when you do `plsp().<insert name of debug mode>(...)`
		# NOTE: Remember, this is only for the global context.
		# NOTE: E.g., if we do `plsp().our_debug_mode(...)`, this would invoke the global context since we did not do
		# NOTE:   `plsp().our_context.our_debug_mode(...)`.
		def wrapper_for_global_handler(*args, **kwargs):
			context = self.contexts[self._configuration_vars["global_context"]]
			mode = self.debug_modes[name_of_debug_mode]
			if callback is not None:
				def _cb_():
					self._callbacks[callback][0]({ #type:ignore
						"colored_text": context._inner_handle(
							mode, self.active_debug_mode, *args, **kwargs
						)
					})
				do_start_sep_thread = self._callbacks[callback][1] 
				if do_start_sep_thread:
					Thread(target=_cb_, daemon=True).start()
				else:
					_cb_()
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



	def add_debug_mode(self, name:"str", separate=False, callback:"str|None"=None):
		if separate:
			level = -1
		else:
			level = len(self.debug_modes)+1

		self.__add_debug_mode(name, level, callback)



	def add_debug_context(self, name:"str"):
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

		

	def define_callback(self, id:"str", multi_threaded:bool):
		def wrapper(func):
			self._callbacks[id] = (func, multi_threaded)
		return wrapper



