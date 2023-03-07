import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;

public class textarea extends JTextArea {
    String r = "\n";
    Font consolas = new Font("Consolas", Font.PLAIN, 14);

    public textarea()
    {

        Border border = BorderFactory.createLineBorder(Color.DARK_GRAY);

                //this.setBounds(1,1,10,0);
                //this.setSize(new Dimension(100,10));

        // this.setBorder(border);
        this.setLineWrap(true);
        this.setWrapStyleWord(true);
        this.setEditable(false);
        //this.setColumns((int) (sys1.geth() / 9));
        //this.setRows(39);
        this.setColumns((sys1.getw() / 17) + 1);
        this.setRows(sys1.geth() / 19);
        this.setFont(consolas);

        this.append("");

        this.append("\n" +
                "   _____                 _        _                    \n" +
                "  / ____|               | |      | |                   \n" +
                " | (___  _ __  _ __ ___ | |_ ___ | |_ _   _ _ __   ___ \n" +
                "  \\___ \\| '_ \\| '__/ _ \\| __/ _ \\| __| | | | '_ \\ / _ \\\n" +
                "  ____) | |_) | | | (_) | || (_) | |_| |_| | |_) |  __/\n" +
                " |_____/| .__/|_|  \\___/ \\__\\___/ \\__|\\__, | .__/ \\___|\n" +
                "        | |                            __/ | |         \n" +
                "        |_|                           |___/|_|         \n" +
                "" +
                " \n V 0.1 - 2020 | https://www.xacone.net | Yazid \n__________________________________________________________\n\n" +
                "");

        append(r + "Lancé le: " + date.date() + r + r);






    }



}
