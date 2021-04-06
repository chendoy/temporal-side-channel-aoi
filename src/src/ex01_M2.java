public class ex01_M2 {
    public static void main(String[] args) {
        final String username = "205644941";
        try {

//            long startTime = System.nanoTime();
            String password = TimingAttack.findPassword(username);
            System.out.println(username + " " + password);
//            long elapsed = System.nanoTime() - startTime;
//            System.out.println(TimingAttack.nanoToMilli(elapsed));
        }
        catch (Exception e) {
            System.out.println("We have a problem");
            e.printStackTrace();
        }
    }
}
