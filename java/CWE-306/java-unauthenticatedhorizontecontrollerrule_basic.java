package com.example.accesscontrol;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.accesscontrol.model.User;
import com.example.accesscontrol.model.Document;
import com.example.accesscontrol.service.UserService;
import com.example.accesscontrol.service.DocumentService;
import com.example.accesscontrol.service.AuthorizationService;

@RestController
@RequestMapping("/api")
public class AccessControlExamples {

    @Autowired
    private UserService userService;
    
    @Autowired
    private DocumentService documentService;
    
    @Autowired
    private AuthorizationService authService;
    
    @Autowired
    private Connection dbConnection;

    // True Positive Examples (Vulnerable Code)
    
    // Example 1: Direct access to user data without authorization check
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
    @GetMapping("/users/{userId}/profile")
    public ResponseEntity<User> bad_case_1(@PathVariable Long userId) {
        // ruleid: java-unauthenticatedhorizontecontrollerrule
        User user = userService.getUserById(userId);
        return ResponseEntity.ok(user);
    }
    
    // Example 2: Access to documents without checking ownership
    @GetMapping("/documents/{docId}")
    public ResponseEntity<Document> bad_case_2(@PathVariable Long docId) {
        // ruleid: java-unauthenticatedhorizontecontrollerrule
        Document document = documentService.getDocumentById(docId);
        return ResponseEntity.ok(document);
    }
    
    // Example 3: Update user information without authorization check
    @PostMapping("/users/{userId}/update")
    public ResponseEntity<String> bad_case_3(@PathVariable Long userId, @RequestParam String newEmail) {
        // ruleid: java-unauthenticatedhorizontecontrollerrule
        userService.updateUserEmail(userId, newEmail);
        return ResponseEntity.ok("User updated successfully");
    }
    
    // Example 4: Access to payment information without verification
    @GetMapping("/users/{userId}/payment-info")
    public ResponseEntity<String> bad_case_4(@PathVariable Long userId) {
        // ruleid: java-unauthenticatedhorizontecontrollerrule
        String paymentInfo = userService.getUserPaymentInfo(userId);
        return ResponseEntity.ok(paymentInfo);
    }
    
    // Example 5: Delete user data without proper authorization
    @PostMapping("/users/{userId}/delete")
    public ResponseEntity<String> bad_case_5(@PathVariable Long userId) {
        // ruleid: java-unauthenticatedhorizontecontrollerrule
        userService.deleteUser(userId);
        return ResponseEntity.ok("User deleted successfully");
    }
    
    // Example 6: Direct SQL query using user ID without authorization
    @GetMapping("/users/{userId}/orders")
    public ResponseEntity<String> bad_case_6(@PathVariable String userId) throws SQLException {
        // ruleid: java-unauthenticatedhorizontecontrollerrule
        PreparedStatement stmt = dbConnection.prepareStatement(
                "SELECT * FROM orders WHERE user_id = ?");
        stmt.setString(1, userId);
        ResultSet rs = stmt.executeQuery();
        // Process results...
        return ResponseEntity.ok("Orders retrieved");
    }
    
    // Example 7: Access to messages without checking if user is a participant
    @GetMapping("/messages/{messageId}")
    public ResponseEntity<String> bad_case_7(@PathVariable Long messageId) {
        // ruleid: java-unauthenticatedhorizontecontrollerrule
        String messageContent = userService.getMessageContent(messageId);
        return ResponseEntity.ok(messageContent);
    }
    
    // Example 8: Changing password without verifying current user
    @PostMapping("/users/{userId}/change-password")
    public ResponseEntity<String> bad_case_8(@PathVariable Long userId, 
                                           @RequestParam String newPassword) {
        // ruleid: java-unauthenticatedhorizontecontrollerrule
        userService.updatePassword(userId, newPassword);
        return ResponseEntity.ok("Password updated");
    }
    
    // Example 9: Access to health records without authorization
    @GetMapping("/patients/{patientId}/health-records")
    public ResponseEntity<String> bad_case_9(@PathVariable Long patientId) {
        // ruleid: java-unauthenticatedhorizontecontrollerrule
        String healthRecords = userService.getPatientHealthRecords(patientId);
        return ResponseEntity.ok(healthRecords);
    }
    
    // Example 10: Download file without checking permissions
    @GetMapping("/files/{fileId}/download")
    public ResponseEntity<byte[]> bad_case_10(@PathVariable Long fileId) {
        // ruleid: java-unauthenticatedhorizontecontrollerrule
        byte[] fileContent = documentService.getFileContent(fileId);
        return ResponseEntity.ok(fileContent);
    }
    
    // Example 11: Access to transaction history without verification
    @GetMapping("/accounts/{accountId}/transactions")
    public ResponseEntity<String> bad_case_11(@PathVariable Long accountId) {
        // ruleid: java-unauthenticatedhorizontecontrollerrule
        String transactions = userService.getAccountTransactions(accountId);
        return ResponseEntity.ok(transactions);
    }
    
    // Example 12: Update document without checking ownership
    @PostMapping("/documents/{docId}/update")
    public ResponseEntity<String> bad_case_12(@PathVariable Long docId, 
                                            @RequestParam String content) {
        // ruleid: java-unauthenticatedhorizontecontrollerrule
        documentService.updateDocument(docId, content);
        return ResponseEntity.ok("Document updated");
    }
    
    // Example 13: Share document without verifying owner
    @PostMapping("/documents/{docId}/share")
    public ResponseEntity<String> bad_case_13(@PathVariable Long docId, 
                                            @RequestParam Long targetUserId) {
        // ruleid: java-unauthenticatedhorizontecontrollerrule
        documentService.shareDocument(docId, targetUserId);
        return ResponseEntity.ok("Document shared");
    }
    
    // Example 14: Access to user settings without authorization
    @GetMapping("/users/{userId}/settings")
    public ResponseEntity<String> bad_case_14(@PathVariable Long userId) {
        // ruleid: java-unauthenticatedhorizontecontrollerrule
        String settings = userService.getUserSettings(userId);
        return ResponseEntity.ok(settings);
    }
    
    // Example 15: Delete document without checking ownership
    @PostMapping("/documents/{docId}/delete")
    public ResponseEntity<String> bad_case_15(@PathVariable Long docId) {
        // ruleid: java-unauthenticatedhorizontecontrollerrule
        documentService.deleteDocument(docId);
        return ResponseEntity.ok("Document deleted");
    }
    
    // True Negative Examples (Secure Code)
    
    // Example 1: Proper authorization check before accessing user profile
    @GetMapping("/users/{userId}/profile-secure")
    public ResponseEntity<User> good_case_1(@PathVariable Long userId, HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = ((User) auth.getPrincipal()).getId();
        
        // ok: java-unauthenticatedhorizontecontrollerrule
        if (currentUserId.equals(userId) || userService.isAdmin(currentUserId)) {
            User user = userService.getUserById(userId);
            return ResponseEntity.ok(user);
        }
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    
    // Example 2: Check document ownership before access
    @GetMapping("/documents/{docId}/secure")
    public ResponseEntity<Document> good_case_2(@PathVariable Long docId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = ((User) auth.getPrincipal()).getId();
        
        // ok: java-unauthenticatedhorizontecontrollerrule
        if (documentService.isDocumentOwnedByUser(docId, currentUserId) || 
            documentService.isDocumentSharedWithUser(docId, currentUserId)) {
            Document document = documentService.getDocumentById(docId);
            return ResponseEntity.ok(document);
        }
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    
    // Example 3: Using Spring Security's PreAuthorize annotation
    @PreAuthorize("@authorizationService.canAccessUser(authentication, #userId)")
    @PostMapping("/users/{userId}/update-secure")
    public ResponseEntity<String> good_case_3(@PathVariable Long userId, @RequestParam String newEmail) {
        // ok: java-unauthenticatedhorizontecontrollerrule
        userService.updateUserEmail(userId, newEmail);
        return ResponseEntity.ok("User updated successfully");
    }
    
    // Example 4: Using a service layer for authorization
    @GetMapping("/users/{userId}/payment-info-secure")
    public ResponseEntity<String> good_case_4(@PathVariable Long userId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        // ok: java-unauthenticatedhorizontecontrollerrule
        if (authService.canAccessPaymentInfo(auth, userId)) {
            String paymentInfo = userService.getUserPaymentInfo(userId);
            return ResponseEntity.ok(paymentInfo);
        }
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    
    // Example 5: Admin-only operation with proper check
    @PostMapping("/users/{userId}/delete-secure")
    public ResponseEntity<String> good_case_5(@PathVariable Long userId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        // ok: java-unauthenticatedhorizontecontrollerrule
        if (userService.isAdmin(((User) auth.getPrincipal()).getId())) {
            userService.deleteUser(userId);
            return ResponseEntity.ok("User deleted successfully");
        }
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    
    // Example 6: SQL query with proper authorization
    @GetMapping("/users/{userId}/orders-secure")
    public ResponseEntity<String> good_case_6(@PathVariable String userId) throws SQLException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUserId = ((User) auth.getPrincipal()).getId().toString();
        
        // ok: java-unauthenticatedhorizontecontrollerrule
        if (currentUserId.equals(userId) || userService.isAdmin(Long.parseLong(currentUserId))) {
            PreparedStatement stmt = dbConnection.prepareStatement(
                    "SELECT * FROM orders WHERE user_id = ?");
            stmt.setString(1, userId);
            ResultSet rs = stmt.executeQuery();
            // Process results...
            return ResponseEntity.ok("Orders retrieved");
        }
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    
    // Example 7: Checking if user is a participant in the message
    @GetMapping("/messages/{messageId}/secure")
    public ResponseEntity<String> good_case_7(@PathVariable Long messageId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = ((User) auth.getPrincipal()).getId();
        
        // ok: java-unauthenticatedhorizontecontrollerrule
        if (userService.isMessageParticipant(messageId, currentUserId)) {
            String messageContent = userService.getMessageContent(messageId);
            return ResponseEntity.ok(messageContent);
        }
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    
    // Example 8: Proper authentication for password change
    @PostMapping("/users/{userId}/change-password-secure")
    public ResponseEntity<String> good_case_8(@PathVariable Long userId, 
                                            @RequestParam String currentPassword,
                                            @RequestParam String newPassword) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = ((User) auth.getPrincipal()).getId();
        
        // ok: java-unauthenticatedhorizontecontrollerrule
        if (currentUserId.equals(userId) && 
            userService.verifyPassword(userId, currentPassword)) {
            userService.updatePassword(userId, newPassword);
            return ResponseEntity.ok("Password updated");
        }
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    
    // Example 9: Role-based access control for health records
    @GetMapping("/patients/{patientId}/health-records-secure")
    public ResponseEntity<String> good_case_9(@PathVariable Long patientId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        User currentUser = (User) auth.getPrincipal();
        
        // ok: java-unauthenticatedhorizontecontrollerrule
        if (currentUser.getId().equals(patientId) || 
            (currentUser.hasRole("DOCTOR") && userService.isDoctorAssignedToPatient(currentUser.getId(), patientId))) {
            String healthRecords = userService.getPatientHealthRecords(patientId);
            return ResponseEntity.ok(healthRecords);
        }
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    
    // Example 10: File access with permission check
    @GetMapping("/files/{fileId}/download-secure")
    public ResponseEntity<byte[]> good_case_10(@PathVariable Long fileId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = ((User) auth.getPrincipal()).getId();
        
        // ok: java-unauthenticatedhorizontecontrollerrule
        if (documentService.hasFileAccess(fileId, currentUserId)) {
            byte[] fileContent = documentService.getFileContent(fileId);
            return ResponseEntity.ok(fileContent);
        }
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    
    // Example 11: Account access verification
    @GetMapping("/accounts/{accountId}/transactions-secure")
    public ResponseEntity<String> good_case_11(@PathVariable Long accountId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = ((User) auth.getPrincipal()).getId();
        
        // ok: java-unauthenticatedhorizontecontrollerrule
        if (userService.isAccountOwner(accountId, currentUserId) || 
            userService.isAuthorizedAccountViewer(accountId, currentUserId)) {
            String transactions = userService.getAccountTransactions(accountId);
            return ResponseEntity.ok(transactions);
        }
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    
    // Example 12: Document update with ownership verification
    @PostMapping("/documents/{docId}/update-secure")
    public ResponseEntity<String> good_case_12(@PathVariable Long docId, 
                                             @RequestParam String content) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = ((User) auth.getPrincipal()).getId();
        
        // ok: java-unauthenticatedhorizontecontrollerrule
        if (documentService.isDocumentOwnedByUser(docId, currentUserId) || 
            documentService.canUserEditDocument(docId, currentUserId)) {
            documentService.updateDocument(docId, content);
            return ResponseEntity.ok("Document updated");
        }
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    
    // Example 13: Document sharing with owner verification
    @PostMapping("/documents/{docId}/share-secure")
    public ResponseEntity<String> good_case_13(@PathVariable Long docId, 
                                             @RequestParam Long targetUserId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = ((User) auth.getPrincipal()).getId();
        
        // ok: java-unauthenticatedhorizontecontrollerrule
        if (documentService.isDocumentOwnedByUser(docId, currentUserId)) {
            documentService.shareDocument(docId, targetUserId);
            return ResponseEntity.ok("Document shared");
        }
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    
    // Example 14: Settings access with proper authorization
    @GetMapping("/users/{userId}/settings-secure")
    public ResponseEntity<String> good_case_14(@PathVariable Long userId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = ((User) auth.getPrincipal()).getId();
        
        // ok: java-unauthenticatedhorizontecontrollerrule
        if (currentUserId.equals(userId)) {
            String settings = userService.getUserSettings(userId);
            return ResponseEntity.ok(settings);
        }
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    
    // Example 15: Document deletion with ownership check
    @PostMapping("/documents/{docId}/delete-secure")
    public ResponseEntity<String> good_case_15(@PathVariable Long docId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long currentUserId = ((User) auth.getPrincipal()).getId();
        
        // ok: java-unauthenticatedhorizontecontrollerrule
        if (documentService.isDocumentOwnedByUser(docId, currentUserId) || 
            userService.isAdmin(currentUserId)) {
            documentService.deleteDocument(docId);
            return ResponseEntity.ok("Document deleted");
        }
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
}
// {/fact}