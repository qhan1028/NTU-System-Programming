TARGET=file_merger
INCLUDE=-I../include
BIN=../bin
FLAG=-g
GCC=g++
FILE_MERGER_OBJS=file_merger_main.o
LIB=-lm
.PHONY: clean
all: $(TARGET)

%.o: %.cpp
	@echo "making: " $@
	@$(GCC) $< -c $(FLAG) $(INCLUDE)
%.o: %.c
	@echo "making: " $@
	@$(GCC) $< -c $(FLAG) $(INCLUDE)
clean:
	rm -rf *.o
	@for bin in $(TARGET); do \
		echo "rm -rf $(BIN)/$$bin"; \
		rm -rf $(BIN)/$$bin; \
	done
file_merger: $(FILE_MERGER_OBJS)
	@echo "making: " $@
	@$(GCC) -o $(BIN)/$@ $(FLAG) $(INCLUDE) $(FILE_MERGER_OBJS)