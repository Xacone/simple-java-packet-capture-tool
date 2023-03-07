import java.awt.*;
import java.io.File;
import java.io.IOException;

public class sys1 {

    public static int geth()
    {
        Dimension screensize = Toolkit.getDefaultToolkit().getScreenSize();
        int h = (int) screensize.getHeight();
        return h;
    }

    public static int getw()
    {
        Dimension screensize = Toolkit.getDefaultToolkit().getScreenSize();
        int w = (int) screensize.getWidth();
        return w;
    }

    public static long getCurrentPid() {
        ProcessHandle processHandle = ProcessHandle.current();
        return processHandle.pid();
    }

    public static void WLAN_SSID_1()
    {
        try {
            Process GET_SSID = Runtime.getRuntime().exec("exec_modules/getssid");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
