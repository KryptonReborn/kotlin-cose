pluginManagement {
    includeBuild("build-logic")
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()

        fun mavenGithubRepo(repo: String) {
            maven {
                url = uri("https://maven.pkg.github.com/$repo")
                credentials {
                    username = System.getenv("USERNAME_GITHUB")
                    password = System.getenv("TOKEN_GITHUB")
                }
            }
        }

        mavenGithubRepo("KryptonReborn/kotlin-cbor")
    }
}

rootProject.name = "cose"

include(":library")
