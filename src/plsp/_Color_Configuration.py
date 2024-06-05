from dataclasses import dataclass
from enum import Enum



class A_Foreground_Color (Enum):
	DEFAULT = "\033[39m"

	BASIC_BLACK = "\033[30m"
	BASIC_RED = "\033[31m"
	BASIC_GREEN = "\033[32m"
	BASIC_YELLOW = "\033[33m"
	BASIC_BLUE = "\033[34m"
	BASIC_MAGENTA = "\033[35m"
	BASIC_CYAN = "\033[36m"
	BASIC_WHITE = "\033[37m"

	BASIC_BRIGHT_BLACK = "\033[90m"
	BASIC_BRIGHT_RED = "\033[91m"
	BASIC_BRIGHT_GREEN = "\033[92m"
	BASIC_BRIGHT_YELLOW = "\033[93m"
	BASIC_BRIGHT_BLUE = "\033[94m"
	BASIC_BRIGHT_MAGENTA = "\033[95m"
	BASIC_BRIGHT_CYAN = "\033[96m"
	BASIC_BRIGHT_WHITE = "\033[97m"



class A_Background_Color (Enum):
	DEFAULT = "\033[49m"

	BASIC_BLACK = "\033[40m"
	BASIC_RED = "\033[41m"
	BASIC_GREEN = "\033[42m"
	BASIC_YELLOW = "\033[43m"
	BASIC_BLUE = "\033[44m"
	BASIC_MAGENTA = "\033[45m"
	BASIC_CYAN = "\033[46m"
	BASIC_WHITE = "\033[47m"

	BASIC_BRIGHT_BLACK = "\033[100m"
	BASIC_BRIGHT_RED = "\033[101m"
	BASIC_BRIGHT_GREEN = "\033[102m"
	BASIC_BRIGHT_YELLOW = "\033[103m"
	BASIC_BRIGHT_BLUE = "\033[104m"
	BASIC_BRIGHT_MAGENTA = "\033[105m"
	BASIC_BRIGHT_CYAN = "\033[106m"
	BASIC_BRIGHT_WHITE = "\033[107m"



class A_Special_Option (Enum):
	BOLD = "\033[1m"
	UNDERLINE = "\033[4m"
	BLINK = "\033[5m"
	REVERSE = "\033[7m"
	HIDDEN = "\033[8m"



@dataclass
class Color_Configuration:
	foreground_color: A_Foreground_Color
	background_color: A_Background_Color
	other_options: str = ""

	def __str__(self):
		return f"{self.foreground_color.value}{self.background_color.value}{self.other_options}"

	def add_option(self, option: A_Special_Option):
		self.other_options += option.value


