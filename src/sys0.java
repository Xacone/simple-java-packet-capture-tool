import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;

public class sys0 {

    public static class GENERAL_DIRECTORY
    {
        public static void CREATE_GENERAL_DIRECTORY()
        {

            File SPROTO_MAIN_FOLDER_EXIST = new File("C://SPROTOTYPE_FILE");
            boolean MAIN_EXIST = SPROTO_MAIN_FOLDER_EXIST.exists();

            if (!MAIN_EXIST)
            {
                try {
                    Process FOLDER_CREATING = Runtime.getRuntime().exec("exec_modules/main_file");
                } catch (IOException e) {
                    e.printStackTrace();
                }


                }


            File SPROTO_HISTORY_FOLDER = new File("C://SPROTOTYPE_FILE/Historique");
            boolean HISTORY_FILE_EXIST = SPROTO_HISTORY_FOLDER.exists();

            if (!HISTORY_FILE_EXIST)
            {
                try {
                    Process HISTORY_FOLDER_CREATING = Runtime.getRuntime().exec("exec_modules/main_history_file");

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

        }

        public static void HISTORY_FILE() {

            try {
                String file_pathname = "C://SPROTOTYPE_FILE/Historique/Historique du " + date.FileDate() + ".txt";
                File obj = new File(file_pathname);

                if (!obj.exists())
                {
                    if (obj.createNewFile())
                    {
                        System.out.println("Fichier crée !!!! - " + obj.getName() + " -- " + obj.getAbsolutePath());
                    } else {
                        System.out.println("Fichier existe deja");
                    }
                }



            } catch (IOException e)
            {
                e.printStackTrace();
                System.out.println("Errrrrrrrroor BITCH");
            }


        }





    }


}
