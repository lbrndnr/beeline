obj-m += beeline.o

# Enable BTF generation
KBUILD_CFLAGS += -g -O2
TARGET_DIR=$(PWD)/../target/release/build
TARGET=$(TARGET_DIR)/beeline.ko

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	mkdir -p $(TARGET_DIR)
	cp beeline.ko $(TARGET_DIR)

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
