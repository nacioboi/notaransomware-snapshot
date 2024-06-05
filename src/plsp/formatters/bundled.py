from .Logging_Segment_Generator import I_Logging_Segment_Generator as __I_Logging_Segment_Generator
from .Logging_Segment_Generator import Logging_Segment_Piece as _Logging_Segment_Piece

from typing import Callable as __typing_X_Callable
from datetime import datetime as _datetime_X_datetime



class Time_Segment_Generator (__I_Logging_Segment_Generator):



	def impl_pieces(self) -> list[str]:
		return [
			"day",
			"month",
			"year",
			"hour",
			"minute",
			"second",
			"microsecond",
			"separator",
			"date_separator",
			"time_separator",
			"second_microsecond_separator"
		]
	


	@property
	def day(self) -> _Logging_Segment_Piece:
		return self._day
	
	@property
	def month(self) -> _Logging_Segment_Piece:
		return self._month
	
	@property
	def year(self) -> _Logging_Segment_Piece:
		return self._year
	
	@property
	def hour(self) -> _Logging_Segment_Piece:
		return self._hour
	
	@property
	def minute(self) -> _Logging_Segment_Piece:
		return self._minute
	
	@property
	def second(self) -> _Logging_Segment_Piece:
		return self._second
	
	@property
	def microsecond(self) -> _Logging_Segment_Piece:
		return self._microsecond
	
	@property
	def separator(self) -> _Logging_Segment_Piece:
		return self._separator
	
	@property
	def date_separator(self) -> _Logging_Segment_Piece:
		return self._date_separator
	
	@property
	def time_separator(self) -> _Logging_Segment_Piece:
		return self._time_separator
	
	@property
	def second_microsecond_separator(self) -> _Logging_Segment_Piece:
		return self._second_microsecond_separator
	


	def __default_further_parse_data(self, string:str) -> str:
		rd_or_st_or_th = None
		day_part = string.split("/")[0]
		rest_part = "/".join(string.split("/")[1:])
		if day_part.endswith("1"):
			rd_or_st_or_th = "st"
		elif day_part.endswith("2"):
			rd_or_st_or_th = "nd"
		elif day_part.endswith("3"):
			rd_or_st_or_th = "rd"
		else:
			rd_or_st_or_th = "th"
		return f"{day_part}{rd_or_st_or_th}/{rest_part}"



	def __init__(self, format_string:"str|None"=None, further_parse_data:"__typing_X_Callable[[str],str]|None"=None):
		super().__init__()

		self._day = _Logging_Segment_Piece()
		self._month = _Logging_Segment_Piece()
		self._year = _Logging_Segment_Piece()
		self._hour = _Logging_Segment_Piece()
		self._minute = _Logging_Segment_Piece()
		self._second = _Logging_Segment_Piece()
		self._microsecond = _Logging_Segment_Piece()
		self._separator = _Logging_Segment_Piece()
		self._date_separator = _Logging_Segment_Piece()
		self._time_separator = _Logging_Segment_Piece()
		self._second_microsecond_separator = _Logging_Segment_Piece()

		self.time_format_string = "%d/%m/%y@%H:%M:%S" if not format_string else format_string
		self._further_parse_data_callback = further_parse_data



	def impl_handle(self) -> None:
		s = _datetime_X_datetime.now().strftime(self.time_format_string)
		if self._further_parse_data_callback is None:
			s = self.__default_further_parse_data(s)
		else:
			s = self._further_parse_data_callback(s)
		from time import perf_counter_ns
		nanoseconds = perf_counter_ns() % 1_000_000_000
		s = s + "." + str(nanoseconds)[:-2]  # Last two digits are always `00`.
		date = s.split("@")[0]
		time = s.split("@")[1]
		self.day.value = date.split("/")[0]
		self.month.value = date.split("/")[1]
		self.year.value = date.split("/")[2]
		self.hour.value = time.split(":")[0]
		self.minute.value = time.split(":")[1]
		self.second.value = time.split(":")[2].split(".")[0]
		self.microsecond.value = time.split(":")[2].split(".")[1]
		self.separator.value = "@"
		self.date_separator.value = "/"
		self.time_separator.value = ":"
		self.second_microsecond_separator.value = "."

	

	def impl_combine_pieces(self) -> list[_Logging_Segment_Piece]:
		return [
			self.day,
			self.date_separator,
			self.month,
			self.date_separator,
			self.year,
			self.separator,
			self.hour,
			self.time_separator,
			self.minute,
			self.time_separator,
			self.second,
			self.second_microsecond_separator,
			self.microsecond,
		]
	


