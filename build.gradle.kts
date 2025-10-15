plugins {
    java
    id("com.gradleup.shadow") version "9.1.0"
}

group = "io.github.stefanmaric"
version = "0.1.0-SNAPSHOT"

val keycloakVersion = "26.3.4"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
    withJavadocJar()
    withSourcesJar()
}

repositories {
    mavenCentral()
}

dependencies {
    // JWT parsing & verification (shaded into the provider JAR)
    implementation("com.nimbusds:nimbus-jose-jwt:10.5")
    implementation("com.google.crypto.tink:tink:1.18.0")

    // Keycloak SPIs provided by the server at runtime
    compileOnly("org.keycloak:keycloak-server-spi:$keycloakVersion")
    compileOnly("org.keycloak:keycloak-server-spi-private:$keycloakVersion")
    compileOnly("org.keycloak:keycloak-services:$keycloakVersion")

    // Compile-time only helpers provided by the Keycloak runtime
    compileOnly("org.jboss.logging:jboss-logging:3.5.0.Final")
}

// Produce a single provider JAR with third-party libs shaded (Keycloak SPIs remain provided)
tasks.shadowJar {
    // Remove the default "-all" classifier
    archiveClassifier.set("")
    minimize()
    manifest {
        attributes(
            "Implementation-Title" to rootProject.name,
            "Implementation-Version" to project.version,
            "Implementation-Vendor" to "Stefan Maric",
            "Implementation-URL" to "https://github.com/stefanmaric/keycloak-jwt-user-authenticator",
            "Implementation-Description" to "Delegate user authentication to trusted external systems using signed JWTs in links",
            "Automatic-Module-Name" to "io.github.stefanmaric.keycloak.jwtuser"
        )
    }
}

tasks.jar {
    // Ensure the plain jar isn't built/published by accident; Shadow jar is the artifact
    enabled = false
}

tasks.assemble {
    dependsOn(tasks.shadowJar)
}
