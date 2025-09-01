package iuh.fit.util;

import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;

import iuh.fit.entity.ChiTietDichVu;
import iuh.fit.entity.ChiTietPhieuDatPhong;
import iuh.fit.entity.ChucVu;
import iuh.fit.entity.HangHoa;
import iuh.fit.entity.KhachHang;
import iuh.fit.entity.LoaiHangHoa;
import iuh.fit.entity.LoaiPhong;
import iuh.fit.entity.NhanVien;
import iuh.fit.entity.PhieuDatPhong;
import iuh.fit.entity.Phong;

/**
 * @author Trần Nguyên Vũ, Trần Ngọc Phát, Mai Nhật Hào, Lê Phước Nguyên
 * @version 1.0
 * @created 10-Oct-2023 13:36:00
 */
public class HibernateUtil {
	private static SessionFactory mySessionFactory = null;

	public static void provideSessionFactory() {
		// Load configuration from hibernate.cfg.xml
		Configuration config = new Configuration();
		config.configure("hibernate.cfg.xml");

		// Get env vars
		// Dotenv dotenv = Dotenv.configure().directory(".").load();
		// String url = dotenv.get("DB_URL");
		// String username = dotenv.get("DB_USERNAME");
		// String password = dotenv.get("DB_PASSWORD");

		String url = "jdbc:sqlserver://localhost:1433;databaseName=quanlykaraoke;encrypt=false;trustServerCertificates=true";
		String username = "sa";
		String password = "!Nguyenvu123";

		// Override properties
		config.setProperty("hibernate.connection.url", url);
		config.setProperty("hibernate.connection.username", username);
		config.setProperty("hibernate.connection.password", password);

		// Eager loading
		config.setProperty("hibernate.enable_lazy_load_no_trans", "false");

		// Add annotated classes
		config.addAnnotatedClass(ChiTietPhieuDatPhong.class);
		config.addAnnotatedClass(ChiTietDichVu.class);
		config.addAnnotatedClass(ChucVu.class);
		config.addAnnotatedClass(HangHoa.class);
		config.addAnnotatedClass(KhachHang.class);
		config.addAnnotatedClass(LoaiHangHoa.class);
		config.addAnnotatedClass(LoaiPhong.class);
		config.addAnnotatedClass(NhanVien.class);
		config.addAnnotatedClass(PhieuDatPhong.class);
		config.addAnnotatedClass(Phong.class);

		// Build session factory
		mySessionFactory = config.buildSessionFactory();
	}

	public static SessionFactory getMySessionFactory() {
		return mySessionFactory;
	}
}
