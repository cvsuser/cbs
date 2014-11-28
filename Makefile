###########################################
#Makefile for simple programs
###########################################

export TUNER_NUM = 1
export USE_SFCS = 0

PWD=$(shell pwd)
INC= -I$(PWD)/..
#INC= -I/home/haoqing/Dropbox/MXL603/

LIB := -lpthread -lm
ifeq ($(USE_SFCS),1)
    LIB += -lsfcslink -LSFCSLink/SFCSLink
endif

#CC=g++
CC=arm-none-linux-gnueabi-g++

CC_FLAG :=-Wall -fpermissive -static

ifeq ($(TUNER_NUM),1)
    CC_FLAG += -DSINGEL_TUNER
endif

PRG=factory_test
OBJ=factory_test.o kfifo.o

$(PRG):$(OBJ)
    $(CC) -o $@ $(OBJ) $(INC) $(LIB)

.SUFFIXES: .c .o .cpp
.cpp.o:
    $(CC) $(CC_FLAG) $(INC) -c $*.cpp -o $*.o

.PRONY:clean
clean:
    @echo "Removing linked and compiled files......"
    rm -f $(OBJ) $(PRG)
