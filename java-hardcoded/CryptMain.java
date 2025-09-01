import org.mindrot.jbcrypt.BCrypt;

public class CryptMain {
	public static void main(String[] args) {
		//복호화가 불가능한 암호화
		//64 자리나 128자리 정도
		String encryptString = 
				BCrypt.hashpw("123456789012345", BCrypt.gensalt());
		System.out.println(encryptString);
		
		//비교
		System.out.println(BCrypt.checkpw("123456789012345", 
				encryptString));
	}
}
