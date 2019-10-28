# BLE Utilities for AmbiqMicro Apollo Family
Here're the BLE Utilities developed for AmbiqMicro Apollo Product Family. Please let me know If you find any bugs and have any other requirements or suggestions. Thank you.

## prodtest_cmd.py
This is a Python3 script which works with Ambiqmicro Apollo3Blue running the BLE direct test mode (DTM).
* The script communicates with Apollo3Blue through serial port. Thus the Python module pyserail needs to be installed beforehand.
* The DTM firmware running on Apollo3Blue is avaliable in Ambiqmicro SDKs which can be downlaoded from [Ambiqmicro offical website](https://ambiqmicro.com/mcu/). The pre-built DTM firmware is located in **<sdk_root>/boards/apollo3_evb/examples/uart_ble_bridge**.
* **prodtest_cmd.py -h** to see the usage.
