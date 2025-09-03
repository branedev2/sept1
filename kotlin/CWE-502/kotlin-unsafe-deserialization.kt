import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor
import org.yaml.snakeyaml.constructor.Constructor
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator
import io.ktor.application.*
import io.ktor.request.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import java.io.File
import java.io.InputStream
import java.io.StringReader
import java.net.URL
import java.util.Scanner

// True Positive Examples (Vulnerable Code)

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
fun bad_case_1(call: ApplicationCall) {
    val yamlData = call.receiveText()
    // ruleid: kotlin-unsafe-deserialization
    val yaml = Yaml()
    val result = yaml.load<Map<String, Any>>(yamlData)
    call.respondText("Processed YAML: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
fun bad_case_2(call: ApplicationCall) {
    val yamlData = call.receiveText()
    // ruleid: kotlin-unsafe-deserialization
    val yaml = Yaml(Constructor())
    val result = yaml.load<Any>(yamlData)
    call.respondText("Processed YAML: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
fun bad_case_3() {
    val yamlFile = File("config.yaml")
    // ruleid: kotlin-unsafe-deserialization
    val yaml = Yaml()
    val config = yaml.load<Map<String, Any>>(yamlFile.inputStream())
    println("Loaded configuration: $config")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
fun bad_case_4(call: ApplicationCall) {
    val jsonData = call.receiveText()
    // ruleid: kotlin-unsafe-deserialization
    val mapper = ObjectMapper().enableDefaultTyping()
    val result = mapper.readValue(jsonData, Any::class.java)
    call.respondText("Processed JSON: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
fun bad_case_5(call: ApplicationCall) {
    val jsonData = call.receiveText()
    // ruleid: kotlin-unsafe-deserialization
    val mapper = ObjectMapper()
    mapper.enableDefaultTyping()
    val result = mapper.readValue(jsonData, Map::class.java)
    call.respondText("Processed JSON: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
fun bad_case_6() {
    val url = URL("https://example.com/config.yaml")
    val yamlContent = url.readText()
    // ruleid: kotlin-unsafe-deserialization
    val yaml = Yaml()
    val config = yaml.load<Any>(yamlContent)
    println("Remote config loaded: $config")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
fun bad_case_7(call: ApplicationCall) {
    val yamlParam = call.parameters["yamlData"] ?: ""
    // ruleid: kotlin-unsafe-deserialization
    val yaml = Yaml(Constructor(Any::class.java))
    val result = yaml.load<Any>(yamlParam)
    call.respondText("Processed YAML parameter: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
fun bad_case_8(call: ApplicationCall) {
    val jsonData = call.receiveText()
    // ruleid: kotlin-unsafe-deserialization
    val mapper = jacksonObjectMapper().enableDefaultTyping()
    val result = mapper.readValue(jsonData, Map::class.java)
    call.respondText("Processed with Kotlin Jackson: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
fun bad_case_9() {
    val scanner = Scanner(System.`in`)
    println("Enter YAML data:")
    val yamlInput = scanner.nextLine()
    // ruleid: kotlin-unsafe-deserialization
    val yaml = Yaml()
    val data = yaml.load<Any>(yamlInput)
    println("Processed user input: $data")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
fun bad_case_10(call: ApplicationCall) {
    val jsonHeader = call.request.headers["X-Config-Data"] ?: ""
    // ruleid: kotlin-unsafe-deserialization
    val mapper = ObjectMapper()
    mapper.activateDefaultTyping(mapper.polymorphicTypeValidator)
    val result = mapper.readValue(jsonHeader, Any::class.java)
    call.respondText("Processed header data: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
fun bad_case_11(inputStream: InputStream) {
    // ruleid: kotlin-unsafe-deserialization
    val yaml = Yaml()
    val data = yaml.loadAll(inputStream)
    data.forEach { document ->
        println("Processing document: $document")
    }
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
fun bad_case_12(call: ApplicationCall) {
    val jsonData = call.receiveText()
    // ruleid: kotlin-unsafe-deserialization
    val mapper = ObjectMapper()
    mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL)
    val result = mapper.readValue(jsonData, Any::class.java)
    call.respondText("Processed with specific typing: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
fun bad_case_13() {
    val yamlString = """
        key1: value1
        key2: value2
    """.trimIndent()
    // ruleid: kotlin-unsafe-deserialization
    val yaml = Yaml()
    val data = yaml.loadAs(yamlString, HashMap::class.java)
    println("Loaded data: $data")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
fun bad_case_14(call: ApplicationCall) {
    val yamlData = call.receiveText()
    // ruleid: kotlin-unsafe-deserialization
    val yaml = Yaml(Constructor())
    val documents = yaml.loadAll(yamlData)
    val results = documents.map { it.toString() }.toList()
    call.respondText("Processed multiple documents: $results")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
fun bad_case_15(call: ApplicationCall) {
    val jsonData = call.receiveText()
    // ruleid: kotlin-unsafe-deserialization
    val mapper = ObjectMapper()
    mapper.activateDefaultTyping(
        mapper.polymorphicTypeValidator,
        ObjectMapper.DefaultTyping.EVERYTHING
    )
    val result = mapper.readValue(jsonData, Object::class.java)
    call.respondText("Processed with full typing: $result")
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
fun good_case_1(call: ApplicationCall) {
    val yamlData = call.receiveText()
    // ok: kotlin-unsafe-deserialization
    val yaml = Yaml(SafeConstructor())
    val result = yaml.load<Map<String, Any>>(yamlData)
    call.respondText("Processed YAML safely: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
fun good_case_2(call: ApplicationCall) {
    val jsonData = call.receiveText()
    // ok: kotlin-unsafe-deserialization
    val mapper = ObjectMapper()
    mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
    // No default typing enabled
    val result = mapper.readValue(jsonData, Map::class.java)
    call.respondText("Processed JSON safely: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
fun good_case_3() {
    val yamlFile = File("config.yaml")
    // ok: kotlin-unsafe-deserialization
    val yaml = Yaml(SafeConstructor())
    val config = yaml.load<Map<String, Any>>(yamlFile.inputStream())
    println("Loaded configuration safely: $config")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
fun good_case_4(call: ApplicationCall) {
    val jsonData = call.receiveText()
    // ok: kotlin-unsafe-deserialization
    val mapper = jacksonObjectMapper()
    // No default typing enabled
    val result = mapper.readValue(jsonData, HashMap::class.java)
    call.respondText("Processed with Kotlin Jackson safely: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
fun good_case_5() {
    val url = URL("https://example.com/config.yaml")
    val yamlContent = url.readText()
    // ok: kotlin-unsafe-deserialization
    val yaml = Yaml(SafeConstructor())
    val config = yaml.load<Map<String, Any>>(yamlContent)
    println("Remote config loaded safely: $config")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
fun good_case_6(call: ApplicationCall) {
    val yamlParam = call.parameters["yamlData"] ?: ""
    // ok: kotlin-unsafe-deserialization
    val yaml = Yaml(SafeConstructor())
    val result = yaml.load<Map<String, Any>>(yamlParam)
    call.respondText("Processed YAML parameter safely: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
fun good_case_7(call: ApplicationCall) {
    val jsonData = call.receiveText()
    // ok: kotlin-unsafe-deserialization
    val mapper = ObjectMapper()
    // Using a specific class instead of default typing
    val result = mapper.readValue(jsonData, ConfigData::class.java)
    call.respondText("Processed with specific class: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
fun good_case_8() {
    val scanner = Scanner(System.`in`)
    println("Enter YAML data:")
    val yamlInput = scanner.nextLine()
    // ok: kotlin-unsafe-deserialization
    val yaml = Yaml(SafeConstructor())
    val data = yaml.load<Map<String, Any>>(yamlInput)
    println("Processed user input safely: $data")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
fun good_case_9(call: ApplicationCall) {
    val jsonHeader = call.request.headers["X-Config-Data"] ?: ""
    // ok: kotlin-unsafe-deserialization
    val mapper = ObjectMapper()
    // Using a specific class instead of default typing
    val result = mapper.readValue(jsonHeader, ConfigData::class.java)
    call.respondText("Processed header data safely: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
fun good_case_10(inputStream: InputStream) {
    // ok: kotlin-unsafe-deserialization
    val yaml = Yaml(SafeConstructor())
    val data = yaml.loadAll(inputStream)
    data.forEach { document ->
        println("Processing document safely: $document")
    }
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
fun good_case_11(call: ApplicationCall) {
    val jsonData = call.receiveText()
    // ok: kotlin-unsafe-deserialization
    val mapper = ObjectMapper()
    // Using a specific validator for polymorphic types
    val ptv = BasicPolymorphicTypeValidator.builder()
        .allowIfBaseType(ConfigData::class.java)
        .build()
    mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL)
    val result = mapper.readValue(jsonData, ConfigData::class.java)
    call.respondText("Processed with validated typing: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
fun good_case_12() {
    val yamlString = """
        key1: value1
        key2: value2
    """.trimIndent()
    // ok: kotlin-unsafe-deserialization
    val yaml = Yaml(SafeConstructor())
    val data = yaml.loadAs(yamlString, HashMap::class.java)
    println("Loaded data safely: $data")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
fun good_case_13(call: ApplicationCall) {
    val yamlData = call.receiveText()
    // ok: kotlin-unsafe-deserialization
    val yaml = Yaml(SafeConstructor())
    val documents = yaml.loadAll(yamlData)
    val results = documents.map { it.toString() }.toList()
    call.respondText("Processed multiple documents safely: $results")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
fun good_case_14(call: ApplicationCall) {
    val jsonData = call.receiveText()
    // ok: kotlin-unsafe-deserialization
    val mapper = ObjectMapper()
    // Explicitly disable default typing
    mapper.deactivateDefaultTyping()
    val result = mapper.readValue(jsonData, Map::class.java)
    call.respondText("Processed with typing disabled: $result")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
fun good_case_15() {
    val yamlFile = File("config.yaml")
    // ok: kotlin-unsafe-deserialization
    val yaml = Yaml(SafeConstructor())
    val reader = StringReader(yamlFile.readText())
    val config = yaml.load<Map<String, Any>>(reader)
    println("Loaded configuration from reader safely: $config")
}
// {/fact}

// Helper class for safe deserialization
data class ConfigData(
    val name: String = "",
    val version: String = "",
    val settings: Map<String, String> = mapOf()
)