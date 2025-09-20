RK3588_GITHUB_URL = https://github.com/arceos-hypervisor/platform_tools/releases/download/latest/rk3588.zip
RK3588_MKIMAGE = ./tools/rk3588/mkimage

OUT_IMG := $(OUT_DIR)/$(APP_NAME)_$(PLAT_NAME).img

.PHONY: build_image

TFTP_SERVER ?= 127.0.0.1
TFTP_CLIENT ?= 127.0.0.1
TARGET_IMG := axvisor-board1

build_image: build
ifeq ($(wildcard $(RK3588_MKIMAGE)),)
		@echo "file not found, downloading from $(RK3588_GITHUB_URL)...";
		wget $(RK3588_GITHUB_URL);
		unzip -o rk3588.zip -d tools;
		rm rk3588.zip;
endif
	$(RK3588_MKIMAGE) -n axvisor -A arm64 -O linux -T kernel -C none -a 0x00480000 -e 0x00480000 -d $(OUT_BIN) $(OUT_IMG)
	@echo 'Built the uboot image ${OUT_IMG} successfully!'

define upload_image
	@echo "Uploading image to RK3588..."
	cp $(OUT_IMG) /srv/tftp/${USER}/$(TARGET_IMG)
	@echo "Image uploaded to /srv/tftp/${USER}/$(TARGET_IMG)"
	@echo "You can now boot the image using the RK3588 board."
	@echo "Coping this command to uboot console:"
	@echo ""
	@echo 'setenv serverip $(TFTP_SERVER);setenv ipaddr $(TFTP_CLIENT);tftp 0x00480000 $(TFTP_SERVER):${USER}/$(TARGET_IMG);tftp 0x10000000 $(TFTP_SERVER):${USER}/rk3588_dtb.bin;bootm 0x00480000 - 0x10000000;'	@echo ""
endef