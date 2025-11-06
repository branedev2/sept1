import java.io.*;
import java.util.*;
import java.nio.file.*;
import javax.servlet.http.*;
import org.springframework.web.multipart.*;
import org.springframework.web.bind.annotation.*;
import org.apache.commons.fileupload.*;
import org.apache.commons.fileupload.servlet.*;
import org.apache.commons.fileupload.disk.*;
import org.apache.commons.io.FilenameUtils;
import org.apache.struts2.dispatcher.multipart.MultiPartRequestWrapper;
import org.glassfish.jersey.media.multipart.*;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import org.jboss.resteasy.plugins.providers.multipart.*;
import com.google.cloud.storage.*;
import io.vertx.ext.web.*;
import io.vertx.ext.web.handler.BodyHandler;
import io.micronaut.http.*;
import io.micronaut.http.multipart.CompletedFileUpload;
import io.quarkus.rest.client.multipart.*;
import io.undertow.servlet.spec.MultiPartInputImpl;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.MultiPartFormInputStream;
import org.apache.wicket.request.resource.AbstractResource;
import org.apache.wicket.request.resource.IResource;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.apache.wicket.util.upload.FileItem;
import org.apache.wicket.util.upload.FileUploadException;
import org.apache.wicket.util.upload.DiskFileItemFactory;
import org.apache.wicket.util.upload.ServletFileUpload;
import org.apache.tomcat.util.http.fileupload.servlet.ServletRequestContext;
import play.mvc.*;
import play.mvc.Http.MultipartFormData;
import play.mvc.Http.MultipartFormData.FilePart;
import ratpack.handling.Handler;
import ratpack.handling.Context;
import ratpack.form.UploadedFile;
import spark.Request;
import spark.Response;
import java.util.regex.Pattern;

// Security Issue: Lack of file extension validation in file upload operations

// True Positive Examples (Vulnerable/Insecure Code)
class FileUploadExamples {

// {fact rule=unrestricted-file-upload@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) throws Exception {
        // Using Jakarta Servlet API without extension validation
        String uploadDir = "/var/uploads/";
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        
        // ruleid: java-lackoffileextensionvalidation
        File file = new File(uploadDir + fileName);
        try (InputStream fileContent = filePart.getInputStream();
             FileOutputStream outputStream = new FileOutputStream(file)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fileContent.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
    }

    @PostMapping("/upload")
    public void bad_case_2(@RequestParam("file") MultipartFile file) throws IOException {
        // Using Spring MultipartFile without extension validation
        String uploadDir = "/var/uploads/";
        String fileName = file.getOriginalFilename();
        
        // ruleid: java-lackoffileextensionvalidation
        Path path = Paths.get(uploadDir + fileName);
        Files.copy(file.getInputStream(), path, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
    }

    public void bad_case_3(HttpServletRequest request) throws Exception {
        // Using Apache Commons FileUpload without extension validation
        String uploadDir = "/var/uploads/";
        DiskFileItemFactory factory = new DiskFileItemFactory();
        ServletFileUpload upload = new ServletFileUpload(factory);
        
        List<FileItem> items = upload.parseRequest(request);
        for (FileItem item : items) {
            if (!item.isFormField()) {
                String fileName = item.getName();
                
                // ruleid: java-lackoffileextensionvalidation
                File file = new File(uploadDir + fileName);
                item.write(file);
            }
        }
    }

    public void bad_case_4(MultiPartRequestWrapper request) throws Exception {
        // Using Apache Struts 2 MultiPartRequestWrapper without extension validation
        String uploadDir = "/var/uploads/";
        File uploadDirectory = new File(uploadDir);
        
        String[] fileNames = request.getFileNames("uploadFile");
        if (fileNames != null && fileNames.length > 0) {
            String fileName = fileNames[0];
            File[] files = request.getFiles("uploadFile");
            
            if (files != null && files.length > 0) {
                // ruleid: java-lackoffileextensionvalidation
                File destFile = new File(uploadDirectory, fileName);
                Files.copy(files[0].toPath(), destFile.toPath(), StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
            }
        }
    }

    @POST
    @Path("/upload")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public void bad_case_5(@FormDataParam("file") InputStream fileInputStream,
                          @FormDataParam("file") FormDataContentDisposition fileMetaData) throws Exception {
        // Using Jersey (JAX-RS) Multipart without extension validation
        String uploadDir = "/var/uploads/";
        String fileName = fileMetaData.getFileName();
        
        // ruleid: java-lackoffileextensionvalidation
        String uploadedFileLocation = uploadDir + fileName;
        saveToFile(fileInputStream, uploadedFileLocation);
    }
    
    private void saveToFile(InputStream uploadedInputStream, String uploadedFileLocation) throws IOException {
        try (FileOutputStream outputStream = new FileOutputStream(new File(uploadedFileLocation))) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = uploadedInputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
    }

    public void bad_case_6(HttpServletRequest request) throws Exception {
        // Using Amazon S3 client without extension validation
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "my-bucket";
        
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        
        // ruleid: java-lackoffileextensionvalidation
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(filePart.getSize());
        s3Client.putObject(bucketName, fileName, filePart.getInputStream(), metadata);
    }

    @POST
    @Path("/upload")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public void bad_case_7(MultipartFormDataInput input) throws Exception {
        // Using RESTEasy Multipart without extension validation
        String uploadDir = "/var/uploads/";
        Map<String, List<InputPart>> uploadForm = input.getFormDataMap();
        List<InputPart> inputParts = uploadForm.get("file");
        
        for (InputPart inputPart : inputParts) {
            MultivaluedMap<String, String> headers = inputPart.getHeaders();
            String fileName = getFileName(headers);
            
            // ruleid: java-lackoffileextensionvalidation
            File file = new File(uploadDir + fileName);
            try (InputStream inputStream = inputPart.getBody(InputStream.class, null);
                 FileOutputStream outputStream = new FileOutputStream(file)) {
                byte[] bytes = inputStream.readAllBytes();
                outputStream.write(bytes);
            }
        }
    }
    
    private String getFileName(MultivaluedMap<String, String> headers) {
        String[] contentDisposition = headers.getFirst("Content-Disposition").split(";");
        for (String filename : contentDisposition) {
            if ((filename.trim().startsWith("filename"))) {
                String name = filename.split("=")[1].trim().replaceAll("\"", "");
                return name;
            }
        }
        return "unknown";
    }

    public void bad_case_8(HttpServletRequest request) throws Exception {
        // Using Google Cloud Storage without extension validation
        Storage storage = StorageOptions.getDefaultInstance().getService();
        String bucketName = "my-bucket";
        
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        
        // ruleid: java-lackoffileextensionvalidation
        BlobId blobId = BlobId.of(bucketName, fileName);
        BlobInfo blobInfo = BlobInfo.newBuilder(blobId).build();
        storage.create(blobInfo, filePart.getInputStream());
    }

    public void bad_case_9(RoutingContext routingContext) {
        // Using Vert.x without extension validation
        String uploadDir = "/var/uploads/";
        
        Set<FileUpload> uploads = routingContext.fileUploads();
        for (FileUpload upload : uploads) {
            String fileName = upload.fileName();
            
            // ruleid: java-lackoffileextensionvalidation
            File file = new File(uploadDir + fileName);
            try {
                Files.copy(Paths.get(upload.uploadedFileName()), file.toPath(), StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
            } catch (IOException e) {
                routingContext.fail(e);
            }
        }
        routingContext.response().end("File uploaded successfully");
    }

    @Post("/upload")
    public HttpResponse<String> bad_case_10(CompletedFileUpload file) throws IOException {
        // Using Micronaut without extension validation
        String uploadDir = "/var/uploads/";
        String fileName = file.getFilename();
        
        // ruleid: java-lackoffileextensionvalidation
        File destinationFile = new File(uploadDir + fileName);
        try (FileOutputStream outputStream = new FileOutputStream(destinationFile)) {
            byte[] bytes = file.getBytes();
            outputStream.write(bytes);
        }
        
        return HttpResponse.ok("File uploaded successfully");
    }

    public void bad_case_11(MultiPartInputImpl multiPartInput) throws IOException {
        // Using Undertow without extension validation
        String uploadDir = "/var/uploads/";
        
        Iterator<io.undertow.server.handlers.form.FormData.FormValue> iter = multiPartInput.getFormData().iterator();
        while (iter.hasNext()) {
            io.undertow.server.handlers.form.FormData.FormValue formValue = iter.next();
            if (formValue.isFileItem()) {
                String fileName = formValue.getFileName();
                
                // ruleid: java-lackoffileextensionvalidation
                File file = new File(uploadDir + fileName);
                try (FileOutputStream out = new FileOutputStream(file);
                     FileInputStream in = new FileInputStream(formValue.getPath().toFile())) {
                    byte[] buffer = new byte[1024];
                    int length;
                    while ((length = in.read(buffer)) > 0) {
                        out.write(buffer, 0, length);
                    }
                }
            }
        }
    }

    public IResource bad_case_12(PageParameters parameters) {
        // Using Apache Wicket without extension validation
        return new AbstractResource() {
            @Override
            protected ResourceResponse newResourceResponse(Attributes attributes) {
                ResourceResponse resourceResponse = new ResourceResponse();
                
                try {
                    org.apache.wicket.request.Request request = attributes.getRequest();
                    ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory());
                    List<FileItem> items = upload.parseRequest(new ServletRequestContext(
                            (HttpServletRequest) ((HttpServletRequest) request.getContainerRequest())));
                    
                    for (FileItem item : items) {
                        if (!item.isFormField()) {
                            String fileName = item.getName();
                            String uploadDir = "/var/uploads/";
                            
                            // ruleid: java-lackoffileextensionvalidation
                            File file = new File(uploadDir + fileName);
                            item.write(file);
                        }
                    }
                    
                    resourceResponse.setWriteCallback(new WriteCallback() {
                        @Override
                        public void writeData(Attributes attributes) {
                            attributes.getResponse().write("File uploaded successfully");
                        }
                    });
                } catch (Exception e) {
                    resourceResponse.setError(500, "Upload failed");
                }
                
                return resourceResponse;
            }
        };
    }

    public Result bad_case_13(Http.Request request) {
        // Using Play Framework without extension validation
        String uploadDir = "/var/uploads/";
        MultipartFormData<File> body = request.body().asMultipartFormData();
        FilePart<File> filePart = body.getFile("file");
        
        if (filePart != null) {
            String fileName = filePart.getFilename();
            
            // ruleid: java-lackoffileextensionvalidation
            File file = new File(uploadDir + fileName);
            try {
                Files.copy(filePart.getRef().toPath(), file.toPath(), StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
                return Results.ok("File uploaded successfully");
            } catch (IOException e) {
                return Results.internalServerError("Upload failed");
            }
        } else {
            return Results.badRequest("Missing file");
        }
    }

    public Handler bad_case_14() {
        // Using Ratpack without extension validation
        return ctx -> {
            ctx.parse(Form.class).then(form -> {
                String uploadDir = "/var/uploads/";
                UploadedFile file = form.file("file");
                
                if (file != null) {
                    String fileName = file.getFileName();
                    
                    // ruleid: java-lackoffileextensionvalidation
                    Path destPath = Paths.get(uploadDir + fileName);
                    Files.copy(file.getBytes(), destPath, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
                    ctx.render("File uploaded successfully");
                } else {
                    ctx.render("No file uploaded");
                }
            });
        };
    }

    public String bad_case_15(spark.Request request) {
        // Using Spark Framework without extension validation
        String uploadDir = "/var/uploads/";
        
        try {
            request.attribute("org.eclipse.jetty.multipartConfig", new javax.servlet.MultipartConfigElement("/temp"));
            Part filePart = request.raw().getPart("file");
            String fileName = filePart.getSubmittedFileName();
            
            // ruleid: java-lackoffileextensionvalidation
            File file = new File(uploadDir + fileName);
            try (InputStream inputStream = filePart.getInputStream();
                 FileOutputStream outputStream = new FileOutputStream(file)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
            }
            
            return "File uploaded successfully";
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1(HttpServletRequest request) throws Exception {
        // Using Jakarta Servlet API with extension validation
        String uploadDir = "/var/uploads/";
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        
        // Validate file extension
        List<String> allowedExtensions = Arrays.asList("jpg", "jpeg", "png", "gif", "pdf");
        String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
        
        if (allowedExtensions.contains(extension)) {
            // ok: java-lackoffileextensionvalidation
            File file = new File(uploadDir + fileName);
            try (InputStream fileContent = filePart.getInputStream();
                 FileOutputStream outputStream = new FileOutputStream(file)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fileContent.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
            }
        } else {
            throw new SecurityException("File type not allowed");
        }
    }

    @PostMapping("/upload")
    public void good_case_2(@RequestParam("file") MultipartFile file) throws IOException {
        // Using Spring MultipartFile with extension validation
        String uploadDir = "/var/uploads/";
        String fileName = file.getOriginalFilename();
        
        // Validate file extension
        String extension = FilenameUtils.getExtension(fileName);
        Set<String> allowedExtensions = new HashSet<>(Arrays.asList("jpg", "jpeg", "png", "pdf", "docx"));
        
        if (allowedExtensions.contains(extension.toLowerCase())) {
            // ok: java-lackoffileextensionvalidation
            Path path = Paths.get(uploadDir + fileName);
            Files.copy(file.getInputStream(), path, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
        } else {
            throw new SecurityException("File type not allowed: " + extension);
        }
    }

    public void good_case_3(HttpServletRequest request) throws Exception {
        // Using Apache Commons FileUpload with extension validation
        String uploadDir = "/var/uploads/";
        DiskFileItemFactory factory = new DiskFileItemFactory();
        ServletFileUpload upload = new ServletFileUpload(factory);
        
        List<FileItem> items = upload.parseRequest(request);
        for (FileItem item : items) {
            if (!item.isFormField()) {
                String fileName = item.getName();
                String extension = FilenameUtils.getExtension(fileName);
                
                // Validate extension
                Pattern pattern = Pattern.compile("^(jpg|jpeg|png|gif|pdf|txt|doc|docx)$", Pattern.CASE_INSENSITIVE);
                if (pattern.matcher(extension).matches()) {
                    // ok: java-lackoffileextensionvalidation
                    File file = new File(uploadDir + fileName);
                    item.write(file);
                } else {
                    throw new SecurityException("Invalid file extension: " + extension);
                }
            }
        }
    }

    public void good_case_4(MultiPartRequestWrapper request) throws Exception {
        // Using Apache Struts 2 MultiPartRequestWrapper with extension validation
        String uploadDir = "/var/uploads/";
        File uploadDirectory = new File(uploadDir);
        
        String[] fileNames = request.getFileNames("uploadFile");
        if (fileNames != null && fileNames.length > 0) {
            String fileName = fileNames[0];
            String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
            
            // Validate extension
            List<String> allowedExtensions = Arrays.asList("jpg", "jpeg", "png", "pdf", "docx");
            if (allowedExtensions.contains(extension)) {
                File[] files = request.getFiles("uploadFile");
                if (files != null && files.length > 0) {
                    // ok: java-lackoffileextensionvalidation
                    File destFile = new File(uploadDirectory, fileName);
                    Files.copy(files[0].toPath(), destFile.toPath(), StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
                }
            } else {
                throw new SecurityException("File extension not allowed: " + extension);
            }
        }
    }

    @POST
    @Path("/upload")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public void good_case_5(@FormDataParam("file") InputStream fileInputStream,
                           @FormDataParam("file") FormDataContentDisposition fileMetaData) throws Exception {
        // Using Jersey (JAX-RS) Multipart with extension validation
        String uploadDir = "/var/uploads/";
        String fileName = fileMetaData.getFileName();
        String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
        
        // Validate extension
        Set<String> allowedExtensions = new HashSet<>(Arrays.asList("jpg", "jpeg", "png", "pdf", "txt"));
        if (allowedExtensions.contains(extension)) {
            // ok: java-lackoffileextensionvalidation
            String uploadedFileLocation = uploadDir + fileName;
            saveToFile(fileInputStream, uploadedFileLocation);
        } else {
            throw new SecurityException("File extension not allowed: " + extension);
        }
    }

    public void good_case_6(HttpServletRequest request) throws Exception {
        // Using Amazon S3 client with extension validation
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "my-bucket";
        
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
        
        // Validate extension
        List<String> allowedExtensions = Arrays.asList("jpg", "jpeg", "png", "pdf", "docx");
        if (allowedExtensions.contains(extension)) {
            // ok: java-lackoffileextensionvalidation
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(filePart.getSize());
            s3Client.putObject(bucketName, fileName, filePart.getInputStream(), metadata);
        } else {
            throw new SecurityException("File extension not allowed: " + extension);
        }
    }

    @POST
    @Path("/upload")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public void good_case_7(MultipartFormDataInput input) throws Exception {
        // Using RESTEasy Multipart with extension validation
        String uploadDir = "/var/uploads/";
        Map<String, List<InputPart>> uploadForm = input.getFormDataMap();
        List<InputPart> inputParts = uploadForm.get("file");
        
        for (InputPart inputPart : inputParts) {
            MultivaluedMap<String, String> headers = inputPart.getHeaders();
            String fileName = getFileName(headers);
            String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
            
            // Validate extension
            Set<String> allowedExtensions = new HashSet<>(Arrays.asList("jpg", "jpeg", "png", "pdf", "txt"));
            if (allowedExtensions.contains(extension)) {
                // ok: java-lackoffileextensionvalidation
                File file = new File(uploadDir + fileName);
                try (InputStream inputStream = inputPart.getBody(InputStream.class, null);
                     FileOutputStream outputStream = new FileOutputStream(file)) {
                    byte[] bytes = inputStream.readAllBytes();
                    outputStream.write(bytes);
                }
            } else {
                throw new SecurityException("File extension not allowed: " + extension);
            }
        }
    }

    public void good_case_8(HttpServletRequest request) throws Exception {
        // Using Google Cloud Storage with extension validation
        Storage storage = StorageOptions.getDefaultInstance().getService();
        String bucketName = "my-bucket";
        
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
        
        // Validate extension
        List<String> allowedExtensions = Arrays.asList("jpg", "jpeg", "png", "pdf", "docx");
        if (allowedExtensions.contains(extension)) {
            // ok: java-lackoffileextensionvalidation
            BlobId blobId = BlobId.of(bucketName, fileName);
            BlobInfo blobInfo = BlobInfo.newBuilder(blobId).build();
            storage.create(blobInfo, filePart.getInputStream());
        } else {
            throw new SecurityException("File extension not allowed: " + extension);
        }
    }

    public void good_case_9(RoutingContext routingContext) {
        // Using Vert.x with extension validation
        String uploadDir = "/var/uploads/";
        
        Set<FileUpload> uploads = routingContext.fileUploads();
        for (FileUpload upload : uploads) {
            String fileName = upload.fileName();
            String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
            
            // Validate extension
            List<String> allowedExtensions = Arrays.asList("jpg", "jpeg", "png", "pdf", "docx");
            if (allowedExtensions.contains(extension)) {
                // ok: java-lackoffileextensionvalidation
                File file = new File(uploadDir + fileName);
                try {
                    Files.copy(Paths.get(upload.uploadedFileName()), file.toPath(), StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
                } catch (IOException e) {
                    routingContext.fail(e);
                    return;
                }
                routingContext.response().end("File uploaded successfully");
            } else {
                routingContext.response().setStatusCode(400).end("File type not allowed");
            }
        }
    }

    @Post("/upload")
    public HttpResponse<String> good_case_10(CompletedFileUpload file) throws IOException {
        // Using Micronaut with extension validation
        String uploadDir = "/var/uploads/";
        String fileName = file.getFilename();
        String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
        
        // Validate extension
        Set<String> allowedExtensions = new HashSet<>(Arrays.asList("jpg", "jpeg", "png", "pdf", "docx"));
        if (allowedExtensions.contains(extension)) {
            // ok: java-lackoffileextensionvalidation
            File destinationFile = new File(uploadDir + fileName);
            try (FileOutputStream outputStream = new FileOutputStream(destinationFile)) {
                byte[] bytes = file.getBytes();
                outputStream.write(bytes);
            }
            return HttpResponse.ok("File uploaded successfully");
        } else {
            return HttpResponse.badRequest("File type not allowed");
        }
    }

    public void good_case_11(MultiPartInputImpl multiPartInput) throws IOException {
        // Using Undertow with extension validation
        String uploadDir = "/var/uploads/";
        
        Iterator<io.undertow.server.handlers.form.FormData.FormValue> iter = multiPartInput.getFormData().iterator();
        while (iter.hasNext()) {
            io.undertow.server.handlers.form.FormData.FormValue formValue = iter.next();
            if (formValue.isFileItem()) {
                String fileName = formValue.getFileName();
                String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
                
                // Validate extension
                List<String> allowedExtensions = Arrays.asList("jpg", "jpeg", "png", "pdf", "docx");
                if (allowedExtensions.contains(extension)) {
                    // ok: java-lackoffileextensionvalidation
                    File file = new File(uploadDir + fileName);
                    try (FileOutputStream out = new FileOutputStream(file);
                         FileInputStream in = new FileInputStream(formValue.getPath().toFile())) {
                        byte[] buffer = new byte[1024];
                        int length;
                        while ((length = in.read(buffer)) > 0) {
                            out.write(buffer, 0, length);
                        }
                    }
                } else {
                    throw new SecurityException("File extension not allowed: " + extension);
                }
            }
        }
    }

    public IResource good_case_12(PageParameters parameters) {
        // Using Apache Wicket with extension validation
        return new AbstractResource() {
            @Override
            protected ResourceResponse newResourceResponse(Attributes attributes) {
                ResourceResponse resourceResponse = new ResourceResponse();
                
                try {
                    org.apache.wicket.request.Request request = attributes.getRequest();
                    ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory());
                    List<FileItem> items = upload.parseRequest(new ServletRequestContext(
                            (HttpServletRequest) ((HttpServletRequest) request.getContainerRequest())));
                    
                    for (FileItem item : items) {
                        if (!item.isFormField()) {
                            String fileName = item.getName();
                            String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
                            
                            // Validate extension
                            List<String> allowedExtensions = Arrays.asList("jpg", "jpeg", "png", "pdf", "docx");
                            if (allowedExtensions.contains(extension)) {
                                String uploadDir = "/var/uploads/";
                                // ok: java-lackoffileextensionvalidation
                                File file = new File(uploadDir + fileName);
                                item.write(file);
                            } else {
                                throw new SecurityException("File extension not allowed: " + extension);
                            }
                        }
                    }
                    
                    resourceResponse.setWriteCallback(new WriteCallback() {
                        @Override
                        public void writeData(Attributes attributes) {
                            attributes.getResponse().write("File uploaded successfully");
                        }
                    });
                } catch (Exception e) {
                    resourceResponse.setError(500, "Upload failed: " + e.getMessage());
                }
                
                return resourceResponse;
            }
        };
    }

    public Result good_case_13(Http.Request request) {
        // Using Play Framework with extension validation
        String uploadDir = "/var/uploads/";
        MultipartFormData<File> body = request.body().asMultipartFormData();
        FilePart<File> filePart = body.getFile("file");
        
        if (filePart != null) {
            String fileName = filePart.getFilename();
            String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
            
            // Validate extension
            List<String> allowedExtensions = Arrays.asList("jpg", "jpeg", "png", "pdf", "docx");
            if (allowedExtensions.contains(extension)) {
                // ok: java-lackoffileextensionvalidation
                File file = new File(uploadDir + fileName);
                try {
                    Files.copy(filePart.getRef().toPath(), file.toPath(), StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
                    return Results.ok("File uploaded successfully");
                } catch (IOException e) {
                    return Results.internalServerError("Upload failed");
                }
            } else {
                return Results.badRequest("File type not allowed: " + extension);
            }
        } else {
            return Results.badRequest("Missing file");
        }
    }

    public Handler good_case_14() {
        // Using Ratpack with extension validation
        return ctx -> {
            ctx.parse(Form.class).then(form -> {
                String uploadDir = "/var/uploads/";
                UploadedFile file = form.file("file");
                
                if (file != null) {
                    String fileName = file.getFileName();
                    String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
                    
                    // Validate extension
                    List<String> allowedExtensions = Arrays.asList("jpg", "jpeg", "png", "pdf", "docx");
                    if (allowedExtensions.contains(extension)) {
                        // ok: java-lackoffileextensionvalidation
                        Path destPath = Paths.get(uploadDir + fileName);
                        try {
                            Files.copy(file.getBytes(), destPath, StandardCopyOption.REPLAC_REDACTED_TWILIO_ID_EXISTING);
                            ctx.render("File uploaded successfully");
                        } catch (IOException e) {
                            ctx.render("Upload failed: " + e.getMessage());
                        }
                    } else {
                        ctx.render("File type not allowed: " + extension);
                    }
                } else {
                    ctx.render("No file uploaded");
                }
            });
        };
    }

    public String good_case_15(spark.Request request) {
        // Using Spark Framework with extension validation
        String uploadDir = "/var/uploads/";
        
        try {
            request.attribute("org.eclipse.jetty.multipartConfig", new javax.servlet.MultipartConfigElement("/temp"));
            Part filePart = request.raw().getPart("file");
            String fileName = filePart.getSubmittedFileName();
            String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
            
            // Validate extension
            List<String> allowedExtensions = Arrays.asList("jpg", "jpeg", "png", "pdf", "docx");
            if (allowedExtensions.contains(extension)) {
                // ok: java-lackoffileextensionvalidation
                File file = new File(uploadDir + fileName);
                try (InputStream inputStream = filePart.getInputStream();
                     FileOutputStream outputStream = new FileOutputStream(file)) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }
                }
                return "File uploaded successfully";
            } else {
                return "File type not allowed: " + extension;
            }
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }
}
// {/fact}