import java.util.*;
import java.io.*;
import javax.servlet.http.*;
import java.sql.*;
import javax.naming.*;
import java.security.*;

public class ObjectExistenceCheckingExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=object-presence@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        Map<String, UserProfile> userProfiles = getUserProfiles();
        
        // ruleid: java-checking-object-presence
        if (userProfiles.get(userId) != null) {
            UserProfile profile = userProfiles.get(userId);
            profile.updateLastAccess();
        }
    }

    public void bad_case_2(HttpServletRequest request) {
        String productId = request.getParameter("productId");
        Map<String, Product> inventory = getInventory();
        
        // ruleid: java-checking-object-presence
        Product product = inventory.get(productId);
        if (product != null) {
            product.decrementStock();
        }
    }

    public void bad_case_3(HttpServletRequest request) {
        String configName = request.getParameter("config");
        Properties appConfig = loadConfiguration();
        
        // ruleid: java-checking-object-presence
        if (appConfig.getProperty(configName) != null) {
            String configValue = appConfig.getProperty(configName);
            updateSetting(configName, configValue);
        }
    }

    public void bad_case_4(HttpServletRequest request) {
        String username = request.getParameter("username");
        HashMap<String, UserSession> activeSessions = getActiveSessions();
        
        // ruleid: java-checking-object-presence
        UserSession session = activeSessions.get(username);
        if (session != null) {
            session.extendTimeout();
        }
    }

    public void bad_case_5(HttpServletRequest request) {
        String key = request.getParameter("cacheKey");
        ConcurrentHashMap<String, CachedData> dataCache = getDataCache();
        
        // ruleid: java-checking-object-presence
        if (dataCache.get(key) != null) {
            CachedData data = dataCache.get(key);
            data.refreshTimestamp();
        }
    }

    public void bad_case_6(HttpServletRequest request) {
        String documentId = request.getParameter("docId");
        TreeMap<String, Document> documents = getDocumentRepository();
        
        // ruleid: java-checking-object-presence
        Document doc = documents.get(documentId);
        if (doc != null && doc.isEditable()) {
            doc.updateContent(request.getParameter("content"));
        }
    }

    public void bad_case_7(HttpServletRequest request) {
        String roleId = request.getParameter("role");
        Map<String, Set<String>> rolePermissions = getRolePermissions();
        
        // ruleid: java-checking-object-presence
        if (rolePermissions.get(roleId) != null) {
            Set<String> permissions = rolePermissions.get(roleId);
            permissions.add("NEW_PERMISSION");
        }
    }

    public void bad_case_8(HttpServletRequest request) {
        String sessionToken = request.getParameter("token");
        LinkedHashMap<String, AuthToken> tokenStore = getAuthTokenStore();
        
        // ruleid: java-checking-object-presence
        AuthToken token = tokenStore.get(sessionToken);
        if (token != null && !token.isExpired()) {
            token.refresh();
        }
    }

    public void bad_case_9(HttpServletRequest request) {
        String departmentId = request.getParameter("deptId");
        Map<String, Department> departments = getDepartments();
        
        // ruleid: java-checking-object-presence
        if (departments.get(departmentId) != null) {
            Department dept = departments.get(departmentId);
            dept.addEmployee(request.getParameter("employeeId"));
        }
    }

    public void bad_case_10(HttpServletRequest request) {
        String apiKey = request.getParameter("apiKey");
        Hashtable<String, ApiClient> clients = getApiClients();
        
        // ruleid: java-checking-object-presence
        ApiClient client = clients.get(apiKey);
        if (client != null) {
            client.incrementUsageCount();
        }
    }

    public void bad_case_11(HttpServletRequest request) {
        String featureFlag = request.getParameter("feature");
        EnumMap<FeatureType, Boolean> featureFlags = getFeatureFlags();
        FeatureType feature = FeatureType.valueOf(featureFlag);
        
        // ruleid: java-checking-object-presence
        if (featureFlags.get(feature) != null) {
            Boolean isEnabled = featureFlags.get(feature);
            logFeatureUsage(feature, isEnabled);
        }
    }

    public void bad_case_12(HttpServletRequest request) {
        String regionCode = request.getParameter("region");
        NavigableMap<String, Region> regions = getRegionMap();
        
        // ruleid: java-checking-object-presence
        Region region = regions.get(regionCode);
        if (region != null) {
            region.updateStatistics();
        }
    }

    public void bad_case_13(HttpServletRequest request) {
        String templateId = request.getParameter("template");
        WeakHashMap<String, EmailTemplate> templates = getEmailTemplates();
        
        // ruleid: java-checking-object-presence
        if (templates.get(templateId) != null) {
            EmailTemplate template = templates.get(templateId);
            template.incrementUsageCount();
        }
    }

    public void bad_case_14(HttpServletRequest request) {
        String serverId = request.getParameter("server");
        IdentityHashMap<ServerInstance, ServerStatus> serverStatuses = getServerStatuses();
        ServerInstance server = getServerById(serverId);
        
        // ruleid: java-checking-object-presence
        ServerStatus status = serverStatuses.get(server);
        if (status != null) {
            status.markAsActive();
        }
    }

    public void bad_case_15(HttpServletRequest request) {
        String preferenceKey = request.getParameter("prefKey");
        Map<String, UserPreference> preferences = getUserPreferences();
        
        // ruleid: java-checking-object-presence
        if (preferences.get(preferenceKey) != null) {
            UserPreference pref = preferences.get(preferenceKey);
            pref.setValue(request.getParameter("value"));
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        Map<String, UserProfile> userProfiles = getUserProfiles();
        
        // ok: java-checking-object-presence
        UserProfile profile = userProfiles.get(userId);
        if (profile != null) {
            profile.updateLastAccess();
        }
    }

    public void good_case_2(HttpServletRequest request) {
        String productId = request.getParameter("productId");
        Map<String, Product> inventory = getInventory();
        
        // ok: java-checking-object-presence
        if (inventory.containsKey(productId)) {
            Product product = inventory.get(productId);
            product.decrementStock();
        }
    }

    public void good_case_3(HttpServletRequest request) {
        String configName = request.getParameter("config");
        Properties appConfig = loadConfiguration();
        
        // ok: java-checking-object-presence
        String configValue = appConfig.getProperty(configName);
        if (configValue != null) {
            updateSetting(configName, configValue);
        }
    }

    public void good_case_4(HttpServletRequest request) {
        String username = request.getParameter("username");
        Map<String, UserSession> activeSessions = getActiveSessions();
        
        // ok: java-checking-object-presence
        activeSessions.computeIfPresent(username, (key, session) -> {
            session.extendTimeout();
            return session;
        });
    }

    public void good_case_5(HttpServletRequest request) {
        String key = request.getParameter("cacheKey");
        ConcurrentHashMap<String, CachedData> dataCache = getDataCache();
        
        // ok: java-checking-object-presence
        dataCache.computeIfPresent(key, (k, data) -> {
            data.refreshTimestamp();
            return data;
        });
    }

    public void good_case_6(HttpServletRequest request) {
        String documentId = request.getParameter("docId");
        Map<String, Document> documents = getDocumentRepository();
        
        // ok: java-checking-object-presence
        documents.computeIfPresent(documentId, (id, doc) -> {
            if (doc.isEditable()) {
                doc.updateContent(request.getParameter("content"));
            }
            return doc;
        });
    }

    public void good_case_7(HttpServletRequest request) {
        String roleId = request.getParameter("role");
        Map<String, Set<String>> rolePermissions = getRolePermissions();
        
        // ok: java-checking-object-presence
        rolePermissions.computeIfPresent(roleId, (id, permissions) -> {
            permissions.add("NEW_PERMISSION");
            return permissions;
        });
    }

    public void good_case_8(HttpServletRequest request) {
        String sessionToken = request.getParameter("token");
        Map<String, AuthToken> tokenStore = getAuthTokenStore();
        
        // ok: java-checking-object-presence
        tokenStore.computeIfPresent(sessionToken, (token, authToken) -> {
            if (!authToken.isExpired()) {
                authToken.refresh();
            }
            return authToken;
        });
    }

    public void good_case_9(HttpServletRequest request) {
        String departmentId = request.getParameter("deptId");
        Map<String, Department> departments = getDepartments();
        
        // ok: java-checking-object-presence
        Optional.ofNullable(departments.get(departmentId))
               .ifPresent(dept -> dept.addEmployee(request.getParameter("employeeId")));
    }

    public void good_case_10(HttpServletRequest request) {
        String apiKey = request.getParameter("apiKey");
        Map<String, ApiClient> clients = getApiClients();
        
        // ok: java-checking-object-presence
        Optional<ApiClient> client = Optional.ofNullable(clients.get(apiKey));
        client.ifPresent(ApiClient::incrementUsageCount);
    }

    public void good_case_11(HttpServletRequest request) {
        String featureFlag = request.getParameter("feature");
        EnumMap<FeatureType, Boolean> featureFlags = getFeatureFlags();
        FeatureType feature = FeatureType.valueOf(featureFlag);
        
        // ok: java-checking-object-presence
        featureFlags.entrySet().stream()
                   .filter(entry -> entry.getKey().equals(feature))
                   .findFirst()
                   .ifPresent(entry -> logFeatureUsage(entry.getKey(), entry.getValue()));
    }

    public void good_case_12(HttpServletRequest request) {
        String regionCode = request.getParameter("region");
        NavigableMap<String, Region> regions = getRegionMap();
        
        // ok: java-checking-object-presence
        regions.computeIfPresent(regionCode, (code, region) -> {
            region.updateStatistics();
            return region;
        });
    }

    public void good_case_13(HttpServletRequest request) {
        String templateId = request.getParameter("template");
        Map<String, EmailTemplate> templates = getEmailTemplates();
        
        // ok: java-checking-object-presence
        if (templates.containsKey(templateId)) {
            templates.get(templateId).incrementUsageCount();
        }
    }

    public void good_case_14(HttpServletRequest request) {
        String serverId = request.getParameter("server");
        Map<ServerInstance, ServerStatus> serverStatuses = getServerStatuses();
        ServerInstance server = getServerById(serverId);
        
        // ok: java-checking-object-presence
        Optional.ofNullable(serverStatuses.get(server))
               .ifPresent(ServerStatus::markAsActive);
    }

    public void good_case_15(HttpServletRequest request) {
        String preferenceKey = request.getParameter("prefKey");
        Map<String, UserPreference> preferences = getUserPreferences();
        String newValue = request.getParameter("value");
        
        // ok: java-checking-object-presence
        preferences.computeIfPresent(preferenceKey, (key, pref) -> {
            pref.setValue(newValue);
            return pref;
        });
    }

    // Helper methods to avoid compilation errors
    private Map<String, UserProfile> getUserProfiles() { return new HashMap<>(); }
    private Map<String, Product> getInventory() { return new HashMap<>(); }
    private Properties loadConfiguration() { return new Properties(); }
    private HashMap<String, UserSession> getActiveSessions() { return new HashMap<>(); }
    private ConcurrentHashMap<String, CachedData> getDataCache() { return new ConcurrentHashMap<>(); }
    private TreeMap<String, Document> getDocumentRepository() { return new TreeMap<>(); }
    private Map<String, Set<String>> getRolePermissions() { return new HashMap<>(); }
    private LinkedHashMap<String, AuthToken> getAuthTokenStore() { return new LinkedHashMap<>(); }
    private Map<String, Department> getDepartments() { return new HashMap<>(); }
    private Hashtable<String, ApiClient> getApiClients() { return new Hashtable<>(); }
    private EnumMap<FeatureType, Boolean> getFeatureFlags() { return new EnumMap<>(FeatureType.class); }
    private NavigableMap<String, Region> getRegionMap() { return new TreeMap<>(); }
    private WeakHashMap<String, EmailTemplate> getEmailTemplates() { return new WeakHashMap<>(); }
    private IdentityHashMap<ServerInstance, ServerStatus> getServerStatuses() { return new IdentityHashMap<>(); }
    private Map<String, UserPreference> getUserPreferences() { return new HashMap<>(); }
    private void updateSetting(String name, String value) {}
    private void logFeatureUsage(FeatureType feature, Boolean enabled) {}
    private ServerInstance getServerById(String id) { return new ServerInstance(); }

    // Simple classes for examples
    private class UserProfile { void updateLastAccess() {} }
    private class Product { void decrementStock() {} }
    private class CachedData { void refreshTimestamp() {} }
    private class Document { boolean isEditable() { return true; } void updateContent(String content) {} }
    private class UserSession { void extendTimeout() {} }
    private class AuthToken { boolean isExpired() { return false; } void refresh() {} }
    private class Department { void addEmployee(String employeeId) {} }
    private class ApiClient { void incrementUsageCount() {} }
    private enum FeatureType { FEATURE_A, FEATURE_B }
    private class Region { void updateStatistics() {} }
    private class EmailTemplate { void incrementUsageCount() {} }
    private class ServerInstance {}
    private class ServerStatus { void markAsActive() {} }
    private class UserPreference { void setValue(String value) {} }
}
// {/fact}