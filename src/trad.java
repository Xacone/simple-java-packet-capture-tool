public class trad {
    public static String vrai_faux(boolean bool)
    {
        String res = null;
        if (bool) { res = "Oui"; }
        else { if (!bool) { res =  "Non"; } }
        return res;
    }

    public static String valide(boolean bool)
    {
        String res = null;
        if(bool) { res = "Valide"; }
        else { if (!bool) { res = "Non valide"; } }
        return res;
    }
}
