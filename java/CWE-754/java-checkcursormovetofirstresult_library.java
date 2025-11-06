import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.net.Uri;
import android.provider.ContactsContract;
import android.provider.MediaStore;
import android.provider.CalendarContract;
import android.provider.UserDictionary;
import android.provider.Browser;
import android.provider.CallLog;
import android.provider.Settings;
import android.provider.Telephony;
import android.provider.DocumentsContract;
import android.provider.Downloads;
import android.provider.BaseColumns;
import android.content.Context;
import androidx.room.Room;
import androidx.room.RoomDatabase;
import androidx.room.Dao;
import androidx.room.Query;
import androidx.sqlite.db.SupportSQLiteDatabase;
import androidx.sqlite.db.SupportSQLiteQuery;
import androidx.sqlite.db.SimpleSQLiteQuery;
import net.sqlcipher.database.SQLiteOpenHelper;
import org.dmfs.android.contentpal.RowDataSnapshot;
import org.dmfs.android.contentpal.querying.QuerySize;
import org.dmfs.android.contentpal.tables.Table;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;
import io.requery.Persistable;
import io.requery.sql.EntityDataStore;
import io.realm.Realm;
import io.realm.RealmQuery;
import io.realm.RealmResults;
import org.greenrobot.greendao.database.Database;
import org.greenrobot.greendao.query.QueryBuilder;
import com.raizlabs.android.dbflow.config.FlowManager;
import com.raizlabs.android.dbflow.sql.language.SQLite;
import com.raizlabs.android.dbflow.sql.language.Select;
import com.raizlabs.android.dbflow.structure.database.DatabaseWrapper;
import com.couchbase.lite.CouchbaseLiteException;
import com.couchbase.lite.Database;
import com.couchbase.lite.Query;
import com.couchbase.lite.QueryBuilder;
import com.couchbase.lite.ResultSet;
import org.json.JSONObject;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

// Security Issue: Missing emptiness check on Cursor objects can lead to NoSuchElementException or incorrect data retrieval

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(Context context, HttpServletRequest request) {
    // Android SQLiteDatabase - Missing cursor check after query based on user input
    String userInput = request.getParameter("name");
    SQLiteDatabase db = context.openOrCreateDatabase("myDB", Context.MODE_PRIVATE, null);
    String[] projection = {"id", "name", "email"};
    String selection = "name = ?";
    String[] selectionArgs = {userInput};
    
    Cursor cursor = db.query("users", projection, selection, selectionArgs, null, null, null);
    // ruleid: java-checkcursormovetofirstresult
    cursor.moveToFirst();
    String email = cursor.getString(cursor.getColumnIndex("email"));
    cursor.close();
    db.close();
}

public void bad_case_2(Context context, HttpServletRequest request) {
    // Android ContentResolver - Missing cursor check when querying contacts
    String phoneNumber = request.getParameter("phone");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = Uri.withAppendedPath(ContactsContract.PhoneLookup.CONTENT_FILTER_URI, Uri.encode(phoneNumber));
    String[] projection = {ContactsContract.PhoneLookup.DISPLAY_NAME};
    
    Cursor cursor = contentResolver.query(uri, projection, null, null, null);
    // ruleid: java-checkcursormovetofirstresult
    cursor.moveToFirst();
    String contactName = cursor.getString(cursor.getColumnIndex(ContactsContract.PhoneLookup.DISPLAY_NAME));
    cursor.close();
}

public void bad_case_3(Context context, HttpServletRequest request) {
    // Android MediaStore - Missing cursor check when querying media files
    String mediaTitle = request.getParameter("title");
    ContentResolver contentResolver = context.getContentResolver();
    Uri mediaUri = MediaStore.Audio.Media.EXTERNAL_CONTENT_URI;
    String selection = MediaStore.Audio.Media.TITLE + " = ?";
    String[] selectionArgs = {mediaTitle};
    
    Cursor cursor = contentResolver.query(mediaUri, null, selection, selectionArgs, null);
    // ruleid: java-checkcursormovetofirstresult
    cursor.moveToFirst();
    String path = cursor.getString(cursor.getColumnIndex(MediaStore.Audio.Media.DATA));
    cursor.close();
}

public void bad_case_4(Context context, HttpServletRequest request) {
    // Android CalendarContract - Missing cursor check when querying calendar events
    String eventTitle = request.getParameter("event");
    ContentResolver contentResolver = context.getContentResolver();
    Uri eventsUri = CalendarContract.Events.CONTENT_URI;
    String selection = CalendarContract.Events.TITLE + " = ?";
    String[] selectionArgs = {eventTitle};
    
    Cursor cursor = contentResolver.query(eventsUri, null, selection, selectionArgs, null);
    // ruleid: java-checkcursormovetofirstresult
    cursor.moveToFirst();
    String location = cursor.getString(cursor.getColumnIndex(CalendarContract.Events.EVENT_LOCATION));
    cursor.close();
}

public void bad_case_5(Context context, HttpServletRequest request) {
    // Android UserDictionary - Missing cursor check when querying user dictionary
    String word = request.getParameter("word");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = UserDictionary.Words.CONTENT_URI;
    String selection = UserDictionary.Words.WORD + " = ?";
    String[] selectionArgs = {word};
    
    Cursor cursor = contentResolver.query(uri, null, selection, selectionArgs, null);
    // ruleid: java-checkcursormovetofirstresult
    cursor.moveToFirst();
    int frequency = cursor.getInt(cursor.getColumnIndex(UserDictionary.Words.FREQUENCY));
    cursor.close();
}

public void bad_case_6(Context context, HttpServletRequest request) {
    // Android Browser - Missing cursor check when querying browser bookmarks
    String url = request.getParameter("url");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = Browser.BOOKMARKS_URI;
    String selection = Browser.BookmarkColumns.URL + " = ?";
    String[] selectionArgs = {url};
    
    Cursor cursor = contentResolver.query(uri, null, selection, selectionArgs, null);
    // ruleid: java-checkcursormovetofirstresult
    cursor.moveToFirst();
    String title = cursor.getString(cursor.getColumnIndex(Browser.BookmarkColumns.TITLE));
    cursor.close();
}

public void bad_case_7(Context context, HttpServletRequest request) {
    // Android CallLog - Missing cursor check when querying call logs
    String phoneNumber = request.getParameter("phone");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = CallLog.Calls.CONTENT_URI;
    String selection = CallLog.Calls.NUMBER + " = ?";
    String[] selectionArgs = {phoneNumber};
    
    Cursor cursor = contentResolver.query(uri, null, selection, selectionArgs, null);
    // ruleid: java-checkcursormovetofirstresult
    cursor.moveToFirst();
    long duration = cursor.getLong(cursor.getColumnIndex(CallLog.Calls.DURATION));
    cursor.close();
}

public void bad_case_8(Context context, HttpServletRequest request) {
    // Android Settings - Missing cursor check when querying system settings
    String settingName = request.getParameter("setting");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = Settings.System.CONTENT_URI;
    String selection = Settings.NameValueTable.NAME + " = ?";
    String[] selectionArgs = {settingName};
    
    Cursor cursor = contentResolver.query(uri, null, selection, selectionArgs, null);
    // ruleid: java-checkcursormovetofirstresult
    cursor.moveToFirst();
    String value = cursor.getString(cursor.getColumnIndex(Settings.NameValueTable.VALUE));
    cursor.close();
}

public void bad_case_9(Context context, HttpServletRequest request) {
    // Android Telephony - Missing cursor check when querying SMS messages
    String sender = request.getParameter("sender");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = Telephony.Sms.CONTENT_URI;
    String selection = Telephony.Sms.ADDRESS + " = ?";
    String[] selectionArgs = {sender};
    
    Cursor cursor = contentResolver.query(uri, null, selection, selectionArgs, null);
    // ruleid: java-checkcursormovetofirstresult
    cursor.moveToFirst();
    String body = cursor.getString(cursor.getColumnIndex(Telephony.Sms.BODY));
    cursor.close();
}

public void bad_case_10(Context context, HttpServletRequest request) {
    // Android DocumentsContract - Missing cursor check when querying documents
    String documentId = request.getParameter("docId");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = DocumentsContract.buildChildDocumentsUri("com.example.provider", documentId);
    
    Cursor cursor = contentResolver.query(uri, null, null, null, null);
    // ruleid: java-checkcursormovetofirstresult
    cursor.moveToFirst();
    String displayName = cursor.getString(cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME));
    cursor.close();
}

public void bad_case_11(Context context, HttpServletRequest request) {
    // Android Downloads - Missing cursor check when querying downloads
    String title = request.getParameter("title");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = Downloads.Impl.CONTENT_URI;
    String selection = Downloads.Impl.COLUMN_TITLE + " = ?";
    String[] selectionArgs = {title};
    
    Cursor cursor = contentResolver.query(uri, null, selection, selectionArgs, null);
    // ruleid: java-checkcursormovetofirstresult
    cursor.moveToFirst();
    String status = cursor.getString(cursor.getColumnIndex(Downloads.Impl.COLUMN_STATUS));
    cursor.close();
}

public void bad_case_12(Context context, HttpServletRequest request) {
    // Room Database - Missing cursor check when executing raw query
    String searchTerm = request.getParameter("search");
    SupportSQLiteDatabase db = Room.databaseBuilder(context, MyDatabase.class, "database-name")
            .allowMainThreadQueries()
            .build()
            .getOpenHelper()
            .getWritableDatabase();
    
    SupportSQLiteQuery query = new SimpleSQLiteQuery("SELECT * FROM users WHERE name LIKE ?", new Object[]{"%" + searchTerm + "%"});
    Cursor cursor = db.query(query);
    // ruleid: java-checkcursormovetofirstresult
    cursor.moveToFirst();
    String email = cursor.getString(cursor.getColumnIndex("email"));
    cursor.close();
}

public void bad_case_13(Context context, HttpServletRequest request) {
    // SQLCipher - Missing cursor check when querying encrypted database
    String username = request.getParameter("username");
    net.sqlcipher.database.SQLiteDatabase db = new net.sqlcipher.database.SQLiteOpenHelper(context, "encrypted.db", null, 1) {
        @Override
        public void onCreate(net.sqlcipher.database.SQLiteDatabase db) {}
        @Override
        public void onUpgrade(net.sqlcipher.database.SQLiteDatabase db, int oldVersion, int newVersion) {}
    }.getWritableDatabase("password");
    
    String[] projection = {"id", "username", "password"};
    String selection = "username = ?";
    String[] selectionArgs = {username};
    
    Cursor cursor = db.query("users", projection, selection, selectionArgs, null, null, null);
    // ruleid: java-checkcursormovetofirstresult
    cursor.moveToFirst();
    String password = cursor.getString(cursor.getColumnIndex("password"));
    cursor.close();
    db.close();
}

public void bad_case_14(Context context, HttpServletRequest request) {
    // ContentPal - Missing cursor check when querying content provider
    String searchTerm = request.getParameter("search");
    ContentResolver contentResolver = context.getContentResolver();
    
    // Simplified example of ContentPal usage
    Cursor cursor = contentResolver.query(
            Uri.parse("content://com.example.provider/items"),
            null,
            "name LIKE ?",
            new String[]{"%" + searchTerm + "%"},
            null);
    
    // ruleid: java-checkcursormovetofirstresult
    cursor.moveToFirst();
    String result = cursor.getString(cursor.getColumnIndex("data"));
    cursor.close();
}

public void bad_case_15(Context context, HttpServletRequest request) {
    // ORMLite - Missing cursor check when querying database
    String userId = request.getParameter("userId");
    try {
        ConnectionSource connectionSource = new JdbcConnectionSource("jdbc:sqlite:database.db");
        Dao<User, String> userDao = DaoManager.createDao(connectionSource, User.class);
        
        // Simplified example using Android cursor
        Cursor cursor = (Cursor) userDao.queryRaw("SELECT * FROM users WHERE id = ?", userId).getResults();
        // ruleid: java-checkcursormovetofirstresult
        cursor.moveToFirst();
        String username = cursor.getString(cursor.getColumnIndex("username"));
        cursor.close();
        connectionSource.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(Context context, HttpServletRequest request) {
    // Android SQLiteDatabase - Proper cursor check after query based on user input
    String userInput = request.getParameter("name");
    SQLiteDatabase db = context.openOrCreateDatabase("myDB", Context.MODE_PRIVATE, null);
    String[] projection = {"id", "name", "email"};
    String selection = "name = ?";
    String[] selectionArgs = {userInput};
    
    Cursor cursor = db.query("users", projection, selection, selectionArgs, null, null, null);
    // ok: java-checkcursormovetofirstresult
    if (cursor != null && cursor.moveToFirst()) {
        String email = cursor.getString(cursor.getColumnIndex("email"));
    }
    if (cursor != null) {
        cursor.close();
    }
    db.close();
}

public void good_case_2(Context context, HttpServletRequest request) {
    // Android ContentResolver - Proper cursor check when querying contacts
    String phoneNumber = request.getParameter("phone");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = Uri.withAppendedPath(ContactsContract.PhoneLookup.CONTENT_FILTER_URI, Uri.encode(phoneNumber));
    String[] projection = {ContactsContract.PhoneLookup.DISPLAY_NAME};
    
    Cursor cursor = contentResolver.query(uri, projection, null, null, null);
    // ok: java-checkcursormovetofirstresult
    if (cursor != null && cursor.moveToFirst()) {
        String contactName = cursor.getString(cursor.getColumnIndex(ContactsContract.PhoneLookup.DISPLAY_NAME));
    }
    if (cursor != null) {
        cursor.close();
    }
}

public void good_case_3(Context context, HttpServletRequest request) {
    // Android MediaStore - Proper cursor check when querying media files
    String mediaTitle = request.getParameter("title");
    ContentResolver contentResolver = context.getContentResolver();
    Uri mediaUri = MediaStore.Audio.Media.EXTERNAL_CONTENT_URI;
    String selection = MediaStore.Audio.Media.TITLE + " = ?";
    String[] selectionArgs = {mediaTitle};
    
    Cursor cursor = contentResolver.query(mediaUri, null, selection, selectionArgs, null);
    String path = null;
    // ok: java-checkcursormovetofirstresult
    if (cursor != null && cursor.moveToFirst()) {
        path = cursor.getString(cursor.getColumnIndex(MediaStore.Audio.Media.DATA));
    }
    if (cursor != null) {
        cursor.close();
    }
}

public void good_case_4(Context context, HttpServletRequest request) {
    // Android CalendarContract - Proper cursor check when querying calendar events
    String eventTitle = request.getParameter("event");
    ContentResolver contentResolver = context.getContentResolver();
    Uri eventsUri = CalendarContract.Events.CONTENT_URI;
    String selection = CalendarContract.Events.TITLE + " = ?";
    String[] selectionArgs = {eventTitle};
    
    Cursor cursor = contentResolver.query(eventsUri, null, selection, selectionArgs, null);
    // ok: java-checkcursormovetofirstresult
    boolean hasData = cursor != null && cursor.moveToFirst();
    if (hasData) {
        String location = cursor.getString(cursor.getColumnIndex(CalendarContract.Events.EVENT_LOCATION));
    }
    if (cursor != null) {
        cursor.close();
    }
}

public void good_case_5(Context context, HttpServletRequest request) {
    // Android UserDictionary - Proper cursor check when querying user dictionary
    String word = request.getParameter("word");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = UserDictionary.Words.CONTENT_URI;
    String selection = UserDictionary.Words.WORD + " = ?";
    String[] selectionArgs = {word};
    
    Cursor cursor = contentResolver.query(uri, null, selection, selectionArgs, null);
    int frequency = -1;
    // ok: java-checkcursormovetofirstresult
    if (cursor != null && cursor.getCount() > 0 && cursor.moveToFirst()) {
        frequency = cursor.getInt(cursor.getColumnIndex(UserDictionary.Words.FREQUENCY));
    }
    if (cursor != null) {
        cursor.close();
    }
}

public void good_case_6(Context context, HttpServletRequest request) {
    // Android Browser - Proper cursor check when querying browser bookmarks
    String url = request.getParameter("url");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = Browser.BOOKMARKS_URI;
    String selection = Browser.BookmarkColumns.URL + " = ?";
    String[] selectionArgs = {url};
    
    Cursor cursor = contentResolver.query(uri, null, selection, selectionArgs, null);
    // ok: java-checkcursormovetofirstresult
    if (cursor != null && cursor.moveToFirst()) {
        String title = cursor.getString(cursor.getColumnIndex(Browser.BookmarkColumns.TITLE));
    } else {
        // Handle case where no data is found
    }
    if (cursor != null) {
        cursor.close();
    }
}

public void good_case_7(Context context, HttpServletRequest request) {
    // Android CallLog - Proper cursor check when querying call logs
    String phoneNumber = request.getParameter("phone");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = CallLog.Calls.CONTENT_URI;
    String selection = CallLog.Calls.NUMBER + " = ?";
    String[] selectionArgs = {phoneNumber};
    
    Cursor cursor = contentResolver.query(uri, null, selection, selectionArgs, null);
    long duration = 0;
    // ok: java-checkcursormovetofirstresult
    boolean found = cursor != null && cursor.moveToFirst();
    if (found) {
        duration = cursor.getLong(cursor.getColumnIndex(CallLog.Calls.DURATION));
    }
    if (cursor != null) {
        cursor.close();
    }
}

public void good_case_8(Context context, HttpServletRequest request) {
    // Android Settings - Proper cursor check when querying system settings
    String settingName = request.getParameter("setting");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = Settings.System.CONTENT_URI;
    String selection = Settings.NameValueTable.NAME + " = ?";
    String[] selectionArgs = {settingName};
    
    Cursor cursor = contentResolver.query(uri, null, selection, selectionArgs, null);
    String value = null;
    try {
        // ok: java-checkcursormovetofirstresult
        if (cursor != null && cursor.moveToFirst()) {
            value = cursor.getString(cursor.getColumnIndex(Settings.NameValueTable.VALUE));
        }
    } finally {
        if (cursor != null) {
            cursor.close();
        }
    }
}

public void good_case_9(Context context, HttpServletRequest request) {
    // Android Telephony - Proper cursor check when querying SMS messages
    String sender = request.getParameter("sender");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = Telephony.Sms.CONTENT_URI;
    String selection = Telephony.Sms.ADDRESS + " = ?";
    String[] selectionArgs = {sender};
    
    Cursor cursor = contentResolver.query(uri, null, selection, selectionArgs, null);
    // ok: java-checkcursormovetofirstresult
    boolean hasMessages = (cursor != null) && (cursor.getCount() > 0) && cursor.moveToFirst();
    if (hasMessages) {
        String body = cursor.getString(cursor.getColumnIndex(Telephony.Sms.BODY));
    }
    if (cursor != null) {
        cursor.close();
    }
}

public void good_case_10(Context context, HttpServletRequest request) {
    // Android DocumentsContract - Proper cursor check when querying documents
    String documentId = request.getParameter("docId");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = DocumentsContract.buildChildDocumentsUri("com.example.provider", documentId);
    
    Cursor cursor = contentResolver.query(uri, null, null, null, null);
    // ok: java-checkcursormovetofirstresult
    if (cursor != null && cursor.moveToFirst()) {
        do {
            String displayName = cursor.getString(cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME));
            // Process each document
        } while (cursor.moveToNext());
    }
    if (cursor != null) {
        cursor.close();
    }
}

public void good_case_11(Context context, HttpServletRequest request) {
    // Android Downloads - Proper cursor check when querying downloads
    String title = request.getParameter("title");
    ContentResolver contentResolver = context.getContentResolver();
    Uri uri = Downloads.Impl.CONTENT_URI;
    String selection = Downloads.Impl.COLUMN_TITLE + " = ?";
    String[] selectionArgs = {title};
    
    Cursor cursor = contentResolver.query(uri, null, selection, selectionArgs, null);
    // ok: java-checkcursormovetofirstresult
    if (cursor == null || !cursor.moveToFirst()) {
        // Handle the case where no download with the given title exists
    } else {
        String status = cursor.getString(cursor.getColumnIndex(Downloads.Impl.COLUMN_STATUS));
    }
    if (cursor != null) {
        cursor.close();
    }
}

public void good_case_12(Context context, HttpServletRequest request) {
    // Room Database - Proper cursor check when executing raw query
    String searchTerm = request.getParameter("search");
    SupportSQLiteDatabase db = Room.databaseBuilder(context, MyDatabase.class, "database-name")
            .allowMainThreadQueries()
            .build()
            .getOpenHelper()
            .getWritableDatabase();
    
    SupportSQLiteQuery query = new SimpleSQLiteQuery("SELECT * FROM users WHERE name LIKE ?", new Object[]{"%" + searchTerm + "%"});
    Cursor cursor = db.query(query);
    // ok: java-checkcursormovetofirstresult
    if (cursor != null && cursor.moveToFirst()) {
        do {
            String email = cursor.getString(cursor.getColumnIndex("email"));
            // Process each user
        } while (cursor.moveToNext());
    }
    if (cursor != null) {
        cursor.close();
    }
}

public void good_case_13(Context context, HttpServletRequest request) {
    // SQLCipher - Proper cursor check when querying encrypted database
    String username = request.getParameter("username");
    net.sqlcipher.database.SQLiteDatabase db = new net.sqlcipher.database.SQLiteOpenHelper(context, "encrypted.db", null, 1) {
        @Override
        public void onCreate(net.sqlcipher.database.SQLiteDatabase db) {}
        @Override
        public void onUpgrade(net.sqlcipher.database.SQLiteDatabase db, int oldVersion, int newVersion) {}
    }.getWritableDatabase("password");
    
    String[] projection = {"id", "username", "password"};
    String selection = "username = ?";
    String[] selectionArgs = {username};
    
    Cursor cursor = db.query("users", projection, selection, selectionArgs, null, null, null);
    String password = null;
    // ok: java-checkcursormovetofirstresult
    if (cursor != null && cursor.moveToFirst()) {
        password = cursor.getString(cursor.getColumnIndex("password"));
    }
    if (cursor != null) {
        cursor.close();
    }
    db.close();
}

public void good_case_14(Context context, HttpServletRequest request) {
    // ContentPal - Proper cursor check when querying content provider
    String searchTerm = request.getParameter("search");
    ContentResolver contentResolver = context.getContentResolver();
    
    // Simplified example of ContentPal usage
    Cursor cursor = contentResolver.query(
            Uri.parse("content://com.example.provider/items"),
            null,
            "name LIKE ?",
            new String[]{"%" + searchTerm + "%"},
            null);
    
    // ok: java-checkcursormovetofirstresult
    if (cursor != null && cursor.getCount() > 0 && cursor.moveToFirst()) {
        String result = cursor.getString(cursor.getColumnIndex("data"));
    } else {
        // Handle empty result set
    }
    if (cursor != null) {
        cursor.close();
    }
}

public void good_case_15(Context context, HttpServletRequest request) {
    // ORMLite - Proper cursor check when querying database
    String userId = request.getParameter("userId");
    try {
        ConnectionSource connectionSource = new JdbcConnectionSource("jdbc:sqlite:database.db");
        Dao<User, String> userDao = DaoManager.createDao(connectionSource, User.class);
        
        // Simplified example using Android cursor
        Cursor cursor = (Cursor) userDao.queryRaw("SELECT * FROM users WHERE id = ?", userId).getResults();
        String username = null;
        // ok: java-checkcursormovetofirstresult
        if (cursor != null && cursor.moveToFirst()) {
            username = cursor.getString(cursor.getColumnIndex("username"));
        }
        if (cursor != null) {
            cursor.close();
        }
        connectionSource.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// Helper class for Room example
abstract class MyDatabase extends RoomDatabase {
    // Database implementation
}

// Helper class for ORMLite example
class User {
    private String id;
    private String username;
    private String password;
    
    // Getters and setters
}