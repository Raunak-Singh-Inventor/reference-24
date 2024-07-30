# An extra tool to conveniently debug
#!/bin/bash

if [ "$1" == "dev" ]; then
    echo "Development mode is enabled"
    # run in background
    openocd -f /usr/share/openocd/scripts/interface/ti-icdi.cfg -f /usr/share/openocd/scripts/board/ti_ek-tm4c123gxl.cfg > /dev/null 2>&1 &
    gdb-multiarch -ex "target extended-remote localhost:3333" bootloader/bin/bootloader.axf
else
    echo "Development mode is not changed"
    echo "If no info is shown, try using RESET"
    picocom /dev/ttyACM0 -b 115200 --imap lfcrlf
fi

