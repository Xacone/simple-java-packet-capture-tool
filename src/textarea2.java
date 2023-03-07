import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;

public class textarea2 extends JTextArea {
    String r = "\n";
    Font consolas = new Font("Consolas", Font.PLAIN, 14);

    public textarea2()
    {

        Border border = BorderFactory.createLineBorder(Color.DARK_GRAY);

        //this.setBounds(1,1,10,0);
        //this.setSize(new Dimension(100,10));

        // this.setBorder(border);
        this.setLineWrap(true);
        this.setWrapStyleWord(true);
        this.setEditable(false);
        this.setColumns((sys1.getw() / 17)+1);
        this.setRows(sys1.geth() / 19); // 19
        //this.setColumns((sys1.geth() / 10));
        //this.setRows(39);

        this.setFont(consolas);

        this.append(""); // Texte au début

    }



}
