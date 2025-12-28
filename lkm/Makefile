obj-m := beeline.o

# Enable BTF generation
KBUILD_CFLAGS += -g -O2
TARGET_DIR=$(PWD)/../target/release/build
TARGET=$(TARGET_DIR)/beeline.ko

all:
	mkdir -p $(TARGET_DIR)
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) MO=$(TARGET_DIR) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
