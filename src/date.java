import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class date {

    public static String date()
    {
        LocalDateTime dateTime = LocalDateTime.now();
        DateTimeFormatter dateTimeFormat = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss.SSS");
        String Time = dateTime.format(dateTimeFormat);
        String DATE_LOG = "[" + Time + "] ";
        return DATE_LOG;
    }

    public static String FileDate()
    {
        LocalDateTime dateTime = LocalDateTime.now();
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("dd-MM-yyyy");
        String Time = dateTime.format(dateTimeFormatter);
        return Time;
    }

}
