plugins {
    kotlin("jvm") version "1.5.20"
    `java-library`
    `maven-publish`
}

group = "com.johnturkson.security"
version = "0.0.2"

repositories {
    mavenCentral()
    maven("https://packages.johnturkson.com/maven")
}

dependencies {
    implementation(kotlin("stdlib"))
}

java {
    withJavadocJar()
    withSourcesJar()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
        }
    }
    
    repositories {
        maven {
            name = "GitLabPackages"
            url = uri("https://gitlab.com/api/v4/projects/${System.getenv("GITLAB_PROJECT_ID")}/packages/maven")
            authentication {
                create<HttpHeaderAuthentication>("header")
            }
            credentials(HttpHeaderCredentials::class) {
                name = "Deploy-Token"
                value = System.getenv("GITLAB_PUBLISHING_TOKEN")
            }
        }
    }
}
