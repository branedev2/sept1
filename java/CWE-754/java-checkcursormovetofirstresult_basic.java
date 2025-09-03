import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.net.Uri;

public class CursorChecksExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=missing-check-on-method-output@v1.0 defects=1}
    public void bad_case_1(SQLiteDatabase db) {
        Cursor cursor = db.query("users", new String[]{"name", "email"}, null, null, null, null, null);
        // ruleid: java-checkcursormovetofirstresult
        cursor.moveToFirst();
        String name = cursor.getString(0);
        cursor.close();
    }

    public void bad_case_2(SQLiteDatabase db) {
        String[] projection = {"id", "title", "content"};
        Cursor cursor = db.query("notes", projection, "id = ?", new String[]{"1"}, null, null, null);
        // ruleid: java-checkcursormovetofirstresult
        cursor.moveToFirst();
        int id = cursor.getInt(0);
        String title = cursor.getString(1);
        cursor.close();
    }

    public void bad_case_3(ContentResolver resolver, Uri uri) {
        Cursor cursor = resolver.query(uri, null, null, null, null);
        // ruleid: java-checkcursormovetofirstresult
        cursor.moveToFirst();
        String result = cursor.getString(cursor.getColumnIndex("data"));
        cursor.close();
    }

    public void bad_case_4(SQLiteDatabase db) {
        Cursor cursor = db.rawQuery("SELECT * FROM products WHERE price < ?", new String[]{"100"});
        // ruleid: java-checkcursormovetofirstresult
        cursor.moveToFirst();
        while (!cursor.isAfterLast()) {
            String productName = cursor.getString(1);
            double price = cursor.getDouble(2);
            cursor.moveToNext();
        }
        cursor.close();
    }

    public void bad_case_5(SQLiteDatabase db, String category) {
        String query = "SELECT * FROM items WHERE category = ?";
        Cursor cursor = db.rawQuery(query, new String[]{category});
        // ruleid: java-checkcursormovetofirstresult
        cursor.moveToFirst();
        int count = cursor.getInt(0);
        cursor.close();
    }

    public void bad_case_6(SQLiteDatabase db) {
        Cursor cursor = null;
        try {
            cursor = db.query("contacts", new String[]{"phone_number"}, "name = ?", new String[]{"John"}, null, null, null);
            // ruleid: java-checkcursormovetofirstresult
            cursor.moveToFirst();
            String phoneNumber = cursor.getString(0);
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    public void bad_case_7(ContentResolver resolver, Uri contentUri) {
        Cursor cursor = resolver.query(contentUri, null, null, null, null);
        try {
            // ruleid: java-checkcursormovetofirstresult
            cursor.moveToFirst();
            for (int i = 0; i < cursor.getCount(); i++) {
                String data = cursor.getString(1);
                System.out.println("Data: " + data);
                cursor.moveToNext();
            }
        } finally {
            cursor.close();
        }
    }

    public void bad_case_8(SQLiteDatabase db) {
        String[] columns = {"id", "name", "age"};
        String selection = "age > ?";
        String[] selectionArgs = {"18"};
        Cursor cursor = db.query("users", columns, selection, selectionArgs, null, null, "name ASC");
        // ruleid: java-checkcursormovetofirstresult
        cursor.moveToFirst();
        do {
            int id = cursor.getInt(0);
            String name = cursor.getString(1);
            System.out.println("User: " + id + " - " + name);
        } while (cursor.moveToNext());
        cursor.close();
    }

    public void bad_case_9(SQLiteDatabase db, String userId) {
        Cursor cursor = null;
        try {
            cursor = db.rawQuery("SELECT email FROM users WHERE id = ?", new String[]{userId});
            // ruleid: java-checkcursormovetofirstresult
            cursor.moveToFirst();
            String email = cursor.getString(0);
            sendEmail(email, "Welcome!");
        } finally {
            if (cursor != null && !cursor.isClosed()) {
                cursor.close();
            }
        }
    }

    private void sendEmail(String email, String message) {
        // Implementation not relevant for this example
    }

    public void bad_case_10(SQLiteDatabase db) {
        Cursor cursor = db.query("settings", new String[]{"value"}, "key = ?", new String[]{"theme"}, null, null, null);
        // ruleid: java-checkcursormovetofirstresult
        cursor.moveToFirst();
        String theme = cursor.getString(0);
        applyTheme(theme);
        cursor.close();
    }

    private void applyTheme(String theme) {
        // Implementation not relevant for this example
    }

    public void bad_case_11(SQLiteDatabase db) {
        Cursor cursor = db.rawQuery("SELECT COUNT(*) FROM messages WHERE read = 0", null);
        // ruleid: java-checkcursormovetofirstresult
        cursor.moveToFirst();
        int unreadCount = cursor.getInt(0);
        cursor.close();
        updateBadge(unreadCount);
    }

    private void updateBadge(int count) {
        // Implementation not relevant for this example
    }

    public void bad_case_12(ContentResolver resolver, Uri uri) {
        String[] projection = {"title", "author", "year"};
        String selection = "year > ?";
        String[] selectionArgs = {"2000"};
        String sortOrder = "year DESC";
        
        Cursor cursor = resolver.query(uri, projection, selection, selectionArgs, sortOrder);
        // ruleid: java-checkcursormovetofirstresult
        cursor.moveToFirst();
        String title = cursor.getString(0);
        String author = cursor.getString(1);
        cursor.close();
    }

    public void bad_case_13(SQLiteDatabase db) {
        Cursor cursor = null;
        try {
            cursor = db.query("products", new String[]{"price"}, "id = ?", new String[]{"123"}, null, null, null);
            // ruleid: java-checkcursormovetofirstresult
            cursor.moveToFirst();
            double price = cursor.getDouble(0);
            applyDiscount(price);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    private void applyDiscount(double price) {
        // Implementation not relevant for this example
    }

    public void bad_case_14(SQLiteDatabase db, String username) {
        Cursor cursor = db.rawQuery("SELECT password_hash FROM users WHERE username = ?", new String[]{username});
        // ruleid: java-checkcursormovetofirstresult
        cursor.moveToFirst();
        String storedHash = cursor.getString(0);
        cursor.close();
        validatePassword(storedHash);
    }

    private void validatePassword(String hash) {
        // Implementation not relevant for this example
    }

    public void bad_case_15(ContentResolver resolver, Uri uri) {
        Cursor cursor = resolver.query(uri, null, null, null, null);
        // ruleid: java-checkcursormovetofirstresult
        cursor.moveToFirst();
        int columnCount = cursor.getColumnCount();
        for (int i = 0; i < columnCount; i++) {
            String columnName = cursor.getColumnName(i);
            String value = cursor.getString(i);
            System.out.println(columnName + ": " + value);
        }
        cursor.close();
    }

    // True Negative Examples (Safe Code)

    public void good_case_1(SQLiteDatabase db) {
        Cursor cursor = db.query("users", new String[]{"name", "email"}, null, null, null, null, null);
        // ok: java-checkcursormovetofirstresult
        if (cursor != null && cursor.moveToFirst()) {
            String name = cursor.getString(0);
        }
        if (cursor != null) {
            cursor.close();
        }
    }

    public void good_case_2(SQLiteDatabase db) {
        String[] projection = {"id", "title", "content"};
        Cursor cursor = db.query("notes", projection, "id = ?", new String[]{"1"}, null, null, null);
        // ok: java-checkcursormovetofirstresult
        if (cursor.moveToFirst()) {
            int id = cursor.getInt(0);
            String title = cursor.getString(1);
        }
        cursor.close();
    }

    public void good_case_3(ContentResolver resolver, Uri uri) {
        Cursor cursor = resolver.query(uri, null, null, null, null);
        // ok: java-checkcursormovetofirstresult
        boolean hasData = cursor != null && cursor.moveToFirst();
        if (hasData) {
            String result = cursor.getString(cursor.getColumnIndex("data"));
        }
        if (cursor != null) {
            cursor.close();
        }
    }

    public void good_case_4(SQLiteDatabase db) {
        Cursor cursor = db.rawQuery("SELECT * FROM products WHERE price < ?", new String[]{"100"});
        // ok: java-checkcursormovetofirstresult
        if (cursor != null && cursor.moveToFirst()) {
            do {
                String productName = cursor.getString(1);
                double price = cursor.getDouble(2);
            } while (cursor.moveToNext());
        }
        if (cursor != null) {
            cursor.close();
        }
    }

    public void good_case_5(SQLiteDatabase db, String category) {
        String query = "SELECT * FROM items WHERE category = ?";
        Cursor cursor = db.rawQuery(query, new String[]{category});
        int count = 0;
        // ok: java-checkcursormovetofirstresult
        if (cursor != null && cursor.moveToFirst()) {
            count = cursor.getInt(0);
        }
        if (cursor != null) {
            cursor.close();
        }
    }

    public void good_case_6(SQLiteDatabase db) {
        Cursor cursor = null;
        try {
            cursor = db.query("contacts", new String[]{"phone_number"}, "name = ?", new String[]{"John"}, null, null, null);
            // ok: java-checkcursormovetofirstresult
            if (cursor != null && cursor.moveToFirst()) {
                String phoneNumber = cursor.getString(0);
            }
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    public void good_case_7(ContentResolver resolver, Uri contentUri) {
        Cursor cursor = resolver.query(contentUri, null, null, null, null);
        try {
            // ok: java-checkcursormovetofirstresult
            if (cursor != null && cursor.moveToFirst()) {
                do {
                    String data = cursor.getString(1);
                    System.out.println("Data: " + data);
                } while (cursor.moveToNext());
            }
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    public void good_case_8(SQLiteDatabase db) {
        String[] columns = {"id", "name", "age"};
        String selection = "age > ?";
        String[] selectionArgs = {"18"};
        Cursor cursor = db.query("users", columns, selection, selectionArgs, null, null, "name ASC");
        // ok: java-checkcursormovetofirstresult
        if (cursor != null && cursor.moveToFirst()) {
            do {
                int id = cursor.getInt(0);
                String name = cursor.getString(1);
                System.out.println("User: " + id + " - " + name);
            } while (cursor.moveToNext());
        }
        if (cursor != null) {
            cursor.close();
        }
    }

    public void good_case_9(SQLiteDatabase db, String userId) {
        Cursor cursor = null;
        try {
            cursor = db.rawQuery("SELECT email FROM users WHERE id = ?", new String[]{userId});
            // ok: java-checkcursormovetofirstresult
            if (cursor != null && cursor.moveToFirst()) {
                String email = cursor.getString(0);
                sendEmail(email, "Welcome!");
            }
        } finally {
            if (cursor != null && !cursor.isClosed()) {
                cursor.close();
            }
        }
    }

    public void good_case_10(SQLiteDatabase db) {
        Cursor cursor = db.query("settings", new String[]{"value"}, "key = ?", new String[]{"theme"}, null, null, null);
        String theme = "default";
        // ok: java-checkcursormovetofirstresult
        if (cursor != null && cursor.moveToFirst()) {
            theme = cursor.getString(0);
        }
        if (cursor != null) {
            cursor.close();
        }
        applyTheme(theme);
    }

    public void good_case_11(SQLiteDatabase db) {
        Cursor cursor = db.rawQuery("SELECT COUNT(*) FROM messages WHERE read = 0", null);
        int unreadCount = 0;
        // ok: java-checkcursormovetofirstresult
        if (cursor != null && cursor.moveToFirst()) {
            unreadCount = cursor.getInt(0);
        }
        if (cursor != null) {
            cursor.close();
        }
        updateBadge(unreadCount);
    }

    public void good_case_12(ContentResolver resolver, Uri uri) {
        String[] projection = {"title", "author", "year"};
        String selection = "year > ?";
        String[] selectionArgs = {"2000"};
        String sortOrder = "year DESC";
        
        Cursor cursor = resolver.query(uri, projection, selection, selectionArgs, sortOrder);
        // ok: java-checkcursormovetofirstresult
        if (cursor != null && cursor.moveToFirst()) {
            String title = cursor.getString(0);
            String author = cursor.getString(1);
        }
        if (cursor != null) {
            cursor.close();
        }
    }

    public void good_case_13(SQLiteDatabase db) {
        Cursor cursor = null;
        try {
            cursor = db.query("products", new String[]{"price"}, "id = ?", new String[]{"123"}, null, null, null);
            // ok: java-checkcursormovetofirstresult
            if (cursor != null && cursor.moveToFirst()) {
                double price = cursor.getDouble(0);
                applyDiscount(price);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    public void good_case_14(SQLiteDatabase db, String username) {
        Cursor cursor = db.rawQuery("SELECT password_hash FROM users WHERE username = ?", new String[]{username});
        // ok: java-checkcursormovetofirstresult
        if (cursor != null && cursor.moveToFirst()) {
            String storedHash = cursor.getString(0);
            validatePassword(storedHash);
        }
        if (cursor != null) {
            cursor.close();
        }
    }

    public void good_case_15(ContentResolver resolver, Uri uri) {
        Cursor cursor = resolver.query(uri, null, null, null, null);
        // ok: java-checkcursormovetofirstresult
        if (cursor != null && cursor.moveToFirst()) {
            int columnCount = cursor.getColumnCount();
            for (int i = 0; i < columnCount; i++) {
                String columnName = cursor.getColumnName(i);
                String value = cursor.getString(i);
                System.out.println(columnName + ": " + value);
            }
        }
        if (cursor != null) {
            cursor.close();
        }
    }
}
// {/fact}