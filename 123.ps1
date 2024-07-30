# Load necessary assemblies
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class MouseClicker
{
    [DllImport("user32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
    public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint cButtons, uint dwExtraInfo);

    private const int MOUSEEVENTF_LEFTDOWN = 0x02;
    private const int MOUSEEVENTF_LEFTUP = 0x04;

    public static void ClickMouse(uint x, uint y)
    {
        mouse_event(MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP, x, y, 0, 0);
    }
}
"@

# Function to perform mouse click at current cursor position
function Click-Mouse {
    [MouseClicker]::ClickMouse(0, 0)
}

# Set the interval in seconds
$interval = 5
# Set the number of repetitions
$repetitions = 10

for ($i = 0; $i -lt $repetitions; $i++) {
    Start-Sleep -Seconds $interval
    Click-Mouse
}
