python bl_build.py
sudo lm4flash ../bootloader/bin/bootloader.bin
python fw_protect.py --infile ../firmware/bin/firmware.bin --outfile firmware_protected.bin --version 2 --message "Firmware V2"
echo "press RESET..."
sleep 2
sudo python fw_update.py --firmware ./firmware_protected.bin

