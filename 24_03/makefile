CC			=  g++
CFLAGS	    = -Wall
LIBS        = -lcrypto 
RM        	= rm 

.SUFFIXES: .cpp .h

%: %.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<

%.o: %.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

all: encryptor decryptor

encryptor: encryptor.o aes_cbc.o
	$(CC) $(CCFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)

decryptor: decryptor.o aes_cbc.o
	$(CC) $(CCFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)

clean: 
	$(RM) -f *.o encryptor decryptor file.txt.*

test:
	./encryptor && ./decryptor

valgrind_test:
	valgrind ./encryptor && valgrind ./decryptor