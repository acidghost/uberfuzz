ifndef PIN_ROOT

$(error PIN_ROOT not set!)

else

CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config
include $(TOOLS_ROOT)/Config/makefile.default.rules

ifdef DEBUG_TOOLS
TOOL_CXXFLAGS += -DDEBUG
endif

include Makefile.rules

endif
