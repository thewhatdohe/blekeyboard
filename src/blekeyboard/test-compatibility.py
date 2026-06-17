import asyncio
from winsdk.windows.devices.bluetooth import BluetoothAdapter

async def check_support():
    adapter = await BluetoothAdapter.get_default_async()
    if adapter:
        print("--- HARDWARE CAPABILITY REPORT ---")
        print(f"Is Low Energy (BLE) Supported?    {adapter.is_low_energy_supported}")
        print(f"Is Central Role Supported?        {adapter.is_central_role_supported}")
        print(f"Is Peripheral Role Supported?     {adapter.is_peripheral_role_supported}")
        print("----------------------------------")
    else:
        print("[ERROR] No Bluetooth adapter detected by Windows.")

if __name__ == "__main__":
    asyncio.run(check_support())