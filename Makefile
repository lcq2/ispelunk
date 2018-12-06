GCC_BIN=`xcrun --sdk iphoneos --find gcc`
GCC=$(GCC_BASE) -arch arm64
SDK=`xcrun --sdk iphoneos --show-sdk-path`

CFLAGS = 
GCC_BASE = $(GCC_BIN) -Os $(CFLAGS) -Wimplicit -isysroot $(SDK) -F$(SDK)/System/Library/Frameworks -F$(SDK)/System/Library/PrivateFrameworks

all: ispelunk_server

ispelunk_server: main.c
	$(GCC) -o $@ $^
	ldid -Sent.xml $@
	ssh -p 2222 -l root localhost rm -f /electra/$@
	scp -P 2222 $@ root@localhost:/electra/$@

clean:
	rm -f *.o ispelunk_server
